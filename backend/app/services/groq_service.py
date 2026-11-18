"""Groq API client (OpenAI-compatible REST endpoint) with an egress privacy guard.

Every outgoing text payload is checked BEFORE sending:
  * none of the known original sensitive values for the document may appear;
  * no high-confidence identifier pattern (Aadhaar, PAN, email, card, phone...) may appear.
If the guard trips, nothing is sent and PrivacyGuardError is raised.
Logs never contain prompts, document content or API keys.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any
from collections.abc import Iterable

import httpx

from ..config import get_settings
from . import pii_service

logger = logging.getLogger("securedoc.groq")


class GroqError(Exception):
    """Generic, content-free error for the AI provider."""


class GroqIncomplete(GroqError):
    """The response hit the output-token cap (finish_reason=length): content is partial."""


class GroqUnavailable(GroqError):
    pass


class PrivacyGuardError(Exception):
    """Raised when an outgoing payload would contain original sensitive data."""


def _tls_verify():
    """TLS verification using the OS certificate store (Windows/macOS/Linux) so corporate
    TLS-inspection roots trusted by the OS are honoured. Verification is never disabled."""
    try:
        import ssl

        import truststore

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:  # pragma: no cover - falls back to certifi bundle
        return True


def _post(url: str, headers: dict, payload: dict, timeout: float) -> httpx.Response:
    """Single HTTP call. Isolated so tests can intercept outgoing requests."""
    with httpx.Client(timeout=timeout, verify=_tls_verify()) as client:
        return client.post(url, headers=headers, json=payload)


def _get(url: str, headers: dict, timeout: float) -> httpx.Response:
    with httpx.Client(timeout=timeout, verify=_tls_verify()) as client:
        return client.get(url, headers=headers)


def _strip_reasoning(content: str) -> str:
    """Remove <think>...</think> blocks and markdown fences some reasoning models emit."""
    content = re.sub(r"(?is)<think>.*?</think>", "", content or "").strip()
    fence = re.match(r"(?s)^```(?:json)?\s*(.*?)\s*```$", content)
    return fence.group(1) if fence else content


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def assert_safe_egress(text: str, forbidden_values: Iterable[str] = ()) -> None:
    low = _norm(text)
    compact = re.sub(r"[\s-]", "", low)
    for v in forbidden_values:
        if not v:
            continue
        if isinstance(v, tuple):  # (value, case_sensitive) - used for single name words like 'Sample'
            word, case_sensitive = v
            if case_sensitive:
                if re.search(rf"(?<![A-Za-z0-9]){re.escape(word.strip())}(?![A-Za-z0-9])", text):
                    raise PrivacyGuardError("Outgoing AI payload contained an original sensitive value; request blocked.")
                continue
            v = word
        nv = _norm(v)
        if len(nv) < 3:
            continue
        digits = pii_service.digits_only(nv)
        if re.search(rf"(?<![a-z0-9]){re.escape(nv)}(?![a-z0-9])", low) or (
            len(digits) >= 6 and digits == re.sub(r"[\s-]", "", nv) and digits in compact
        ):
            raise PrivacyGuardError("Outgoing AI payload contained an original sensitive value; request blocked.")
    hits = pii_service.strong_identifier_hits(text)
    if hits:
        raise PrivacyGuardError(f"Outgoing AI payload contained unmasked identifiers ({', '.join(sorted(set(hits)))}); request blocked.")


# ---------------------------------------------------------------- rate-limit pacing
# Groq enforces tokens-per-minute (TPM) limits and counts a request's max_tokens against the
# budget up front. The response headers say how many tokens remain and when the window resets;
# we wait for the reset BEFORE sending a request that would not fit, instead of failing.
_rl_lock = threading.Lock()
_rl_state: dict[str, dict] = {}  # per model: Groq rate limits are separate for each model


def _state(model: str) -> dict:
    return _rl_state.setdefault(model, {"remaining": None, "reset_at": 0.0})
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")


def _parse_duration(value: str | None) -> float | None:
    if not value:
        return None
    total, found = 0.0, False
    for num, unit in _DURATION_RE.findall(value):
        found = True
        total += float(num) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
    if not found:
        try:
            return float(value)
        except ValueError:
            return None
    return total


def _record_limits(headers, model: str) -> None:
    try:
        remaining = headers.get("x-ratelimit-remaining-tokens")
        reset = _parse_duration(headers.get("x-ratelimit-reset-tokens"))
    except AttributeError:
        return
    if remaining is None:
        return
    with _rl_lock:
        _state(model)["remaining"] = int(float(remaining))
        _state(model)["reset_at"] = time.monotonic() + (reset or 0.0)


def _estimate_tokens(messages: list[dict[str, Any]], max_tokens: int) -> int:
    chars, images = 0, 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            chars += len(c)
        elif isinstance(c, list):
            for part in c:
                if part.get("type") == "text":
                    chars += len(part.get("text", ""))
                elif part.get("type") == "image_url":
                    images += 1
    return chars // 4 + images * 2100 + max_tokens  # ~4 characters per token


def has_capacity(model: str, messages: list[dict[str, Any]], max_tokens: int) -> bool:
    """True if a request of this size fits the model's current per-minute token window
    (or nothing is known about it yet). Used to pick between chat models without waiting."""
    with _rl_lock:
        st = _state(model)
        remaining, reset_at, daily_block = st["remaining"], st["reset_at"], st.get("daily_until", 0.0)
    now = time.monotonic()
    if daily_block > now:
        return False
    return remaining is None or reset_at <= now or _estimate_tokens(messages, max_tokens) <= remaining


def _pace(cost: int, model: str) -> None:
    with _rl_lock:
        remaining, reset_at = _state(model)["remaining"], _state(model)["reset_at"]
    wait = reset_at - time.monotonic()
    if remaining is not None and cost > remaining and wait > 0:
        logger.info("Waiting %.1fs for the AI provider's token window to reset", min(wait, 60.0))
        time.sleep(min(wait, 60.0) + 0.25)


def _retry_delay(resp, attempt: int) -> float:
    candidates = [
        _parse_duration(resp.headers.get("retry-after")),
        _parse_duration(resp.headers.get("x-ratelimit-reset-tokens")),
    ]
    m = re.search(r"try again in ([0-9.]+)s", resp.text or "")
    if m:
        candidates.append(float(m.group(1)))
    known = [c for c in candidates if c is not None and c >= 0.5]
    # output-token (OTPM) windows are not reported in headers: back off progressively
    delay = max(known) if known else 8.0 * (attempt + 1)
    return min(max(delay, 1.0) + 0.5, 65.0)


def chat_json(
    messages: list[dict[str, Any]],
    *,
    model: str | None = None,
    forbidden_values: Iterable[str] = (),
    skip_guard_for_images: bool = False,
    max_tokens: int = 4096,
    reasoning_effort: str | None = None,
) -> dict:
    """Call Groq chat completions in JSON mode and return the parsed object.

    The privacy guard runs on all text parts. Image parts are only allowed when the
    caller explicitly passes skip_guard_for_images=True after verifying consent.
    """
    s = get_settings()
    if not s.groq_enabled:
        raise GroqUnavailable("AI provider is not configured")

    forbidden = list(forbidden_values)
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            assert_safe_egress(content, forbidden)
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    assert_safe_egress(part.get("text", ""), forbidden)
                elif part.get("type") == "image_url" and not skip_guard_for_images:
                    raise PrivacyGuardError("Image payloads require explicit consent.")

    payload = {
        "model": model or s.groq_model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    if s.groq_reasoning_format:
        payload["reasoning_format"] = s.groq_reasoning_format
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort
    headers = {"Authorization": f"Bearer {s.groq_api_key}", "Content-Type": "application/json"}
    url = f"{s.groq_base_url.rstrip('/')}/chat/completions"

    max_tokens = max(64, min(max_tokens, s.groq_max_output_tokens))
    payload["max_tokens"] = max_tokens
    last_status = None
    cost = _estimate_tokens(messages, max_tokens)
    for attempt in range(s.groq_max_retries + 1):
        _pace(cost, payload["model"])
        try:
            resp = _post(url, headers, payload, s.groq_timeout_seconds)
        except httpx.TimeoutException:
            last_status = "timeout"
            logger.warning("Groq request timed out (attempt %d)", attempt + 1)
        except httpx.HTTPError:
            last_status = "network"
            logger.warning("Groq network error (attempt %d)", attempt + 1)
        else:
            _record_limits(resp.headers, payload["model"])
            if resp.status_code == 429:
                m = re.search(r"try again in ([0-9.]+)s", resp.text)
                if m:
                    with _rl_lock:  # the body states the exact wait for the OTPM window
                        _state(payload["model"])["remaining"] = 0
                        _state(payload["model"])["reset_at"] = time.monotonic() + min(float(m.group(1)), 65.0)
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if body["choices"][0].get("finish_reason") == "length":
                        # A truncated answer must never be treated as complete (e.g. a transcription
                        # missing the last lines would leave them unmasked).
                        raise GroqIncomplete("AI response was cut off by the output limit")
                    content = body["choices"][0]["message"]["content"]
                    data = json.loads(_strip_reasoning(content))
                except (ValueError, KeyError, IndexError, TypeError) as exc:
                    raise GroqError("AI provider returned malformed JSON") from exc
                if not isinstance(data, dict):
                    raise GroqError("AI provider returned malformed JSON")
                return data
            last_status = resp.status_code
            logger.warning("Groq returned HTTP %s (attempt %d)", resp.status_code, attempt + 1)
            if resp.status_code == 400 and "max completion tokens" in resp.text.lower():
                raise GroqIncomplete("AI response was cut off by the output limit")
            if resp.status_code == 429 and ("per day" in resp.text.lower() or "(tpd)" in resp.text.lower()
                                            or "(rpd)" in resp.text.lower()):
                # Daily quota: waiting minutes inside a request helps nobody. Fail fast and clearly.
                logger.warning("Groq daily quota reached")
                with _rl_lock:  # remember it, so callers can switch to another model meanwhile
                    _state(payload["model"])["daily_until"] = time.monotonic() + 600
                raise GroqError("the AI provider's daily usage limit has been reached; please try again later")
            if resp.status_code in (413, 429) and "too large" in resp.text.lower():
                # A single request bigger than a per-minute limit can never succeed: do not retry.
                logger.warning("Groq rejected the request as too large for the account's rate limits")
                raise GroqError("The request is too large for the AI provider's rate limits.")
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < s.groq_max_retries:
                time.sleep(_retry_delay(resp, attempt))
                continue
            break
        if attempt < s.groq_max_retries:
            time.sleep(1.0 * (attempt + 1))
    if last_status == 429:
        raise GroqError("AI provider rate limit reached. Please try again shortly.")
    raise GroqError("AI provider request failed")


def list_models() -> list[str]:
    s = get_settings()
    if not s.groq_enabled:
        raise GroqUnavailable("AI provider is not configured")
    resp = _get(f"{s.groq_base_url.rstrip('/')}/models", {"Authorization": f"Bearer {s.groq_api_key}"}, 15)
    if resp.status_code != 200:
        raise GroqError(f"Model listing failed (HTTP {resp.status_code})")
    return [m.get("id") for m in resp.json().get("data", [])]


def verify_configured_models() -> dict[str, bool]:
    s = get_settings()
    available = set(list_models())
    result = {s.groq_model: s.groq_model in available}
    if s.groq_chat_model:
        result[s.groq_chat_model] = s.groq_chat_model in available
    if s.groq_vision_model:
        result[s.groq_vision_model] = s.groq_vision_model in available
    return result
