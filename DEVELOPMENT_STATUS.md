# Development Status — SecureDoc AI MVP

_Last updated: 2026-11-12_

## Completed modules
| Stage | Module | Status |
|---|---|---|
| 1 | Folder structure, venv (Python 3.14), FastAPI app, SQLite + SQLAlchemy models (7 tables), env config, React/Vite/Tailwind | ✅ verified (backend starts, tables created, frontend serves) |
| 2 | Register / login / logout / me, Argon2id, hashed session tokens, expiry, CSRF, Origin check, rate limit, privacy onboarding, versioned consent records | ✅ tests pass |
| 3 | Upload validation (size, signature, structure, encryption, page limit), PyMuPDF extraction (text, words, form fields, page classification), local PII service, Groq service with egress guard, Pydantic-validated structured extraction, consent-gated vision path | ✅ tests pass |
| 4 | Masker (consistent placeholders), masked JSON, AES-256-GCM owner fields, permanent PDF redaction, raster redaction for scanned pages, metadata scrub, post-redaction validation (withhold + needs_review), JSON-only mode | ✅ tests pass |
| 5 | Chatbot: restricted refusal, owner-field local disclosure with permission check, disabled-permission masking, content-category gating, one Groq call for document questions (scope + answer), local fallback, answer sanitization, sanitized persistence, per-document history | ✅ tests pass |
| 6 | Frontend: login, register, onboarding, dashboard (upload, history, recent status), document workspace (info, warnings, entity summary, masked JSON viewer, downloads, chat), settings (permissions, consents, policy version, delete all) | ✅ builds; component tests pass |
| 7 | Full test runs, live two-user E2E through the Vite proxy, log scan for PII | ✅ |
| 8 | Images: content-sniffed PNG/JPEG/WebP uploads (EXIF dropped, bomb guard); embedded images in PDFs. Vision transcription with square-padded 0-1000 boxes, ink-snapped pixel redaction, independent AI re-check and safe fallback. ICAO MRZ detection with check digits. Multi-file upload queue (2 concurrent, retry, per-file status) and ZIP download. Groq output-cap and pacing for the account's 1,000 OTPM limit. Chat grounding check, "is X present?" answers and misspelling-tolerant refusals | ✅ tests pass; live batch E2E with real Groq |

## Test results (actually executed in this environment)
- **Backend (pytest):** 115 passed on 2026-11-12, including `tests/test_images.py` (14). It covers MRZ, pixel redaction verified on the output pixels, re-check failure fallback, embedded images with and without consent, invisible text, content sniffing, EXIF removal, the decompression-bomb guard, the Groq output cap and truncation, the ZIP endpoint and presence answers.
- **Frontend (vitest):** 6 passed — ChatPanel (history/send, error state, document switch clears context), PermissionsForm, client validation.
- **Production build:** `vite build` succeeded.
- **Live E2E** (`backend/scripts/e2e_demo.py` against running uvicorn and Vite):
  - register → onboard → upload → 6 chat scenarios → PDF and JSON download, with no originals found in either output;
  - user B gets 404 on all of user A's endpoints, and an unauthenticated request gets 401;
  - delete → 404, logout → 401.
- **Server log scan after E2E:** 0 occurrences of the synthetic name, Aadhaar, PAN, account, email or phone.
- **Live batch E2E, 2026-11-12, real Groq, Edge via Playwright.** One batch of `synthetic_personal_information_test.pdf`, `HOL Sample Passport.pdf` and `HOL Sample Passport.jpeg` (a WebP file):
  - All three completed.
  - Both passport outputs keep the photo with the passport number and both MRZ lines burned out (checked visually).
  - The ZIP contained 3 PDFs and 3 JSON files.
  - Chat: presence question answered, number refused, name and DOB correct with the page, cricket question out of scope.
  - The raw SQLite file contained none of the original IDs.
  - `documents.masked_data`, `person_details.value` and `chat_messages.content` are stored as `enc:v1:` ciphertext.
  - The temp directory was empty afterwards.

### Bugs found by the tests and fixed
1. `logger.exception` wrote tracebacks whose exception text could include document content. Errors are now logged by exception type only, and a test asserts this.
2. On Windows, PyMuPDF held a file handle on malformed PDFs, so the temp original could not be deleted. PDFs are now opened from memory, and a test covers the failure path.
3. A question containing a restricted placeholder (`What is [AADHAAR_001]?`) bypassed the keyword refusal. It is now refused explicitly.
4. The cleanup scrub deleted the invisible text layer of the passport PDF, and the image became a grey box. Now the hidden text is removed without visible X marks, and the image is masked and put back.
5. Vision boxes drift on non-square images and are too short for large print, which left half of the passport number visible. Fixed with square padding plus ink snapping; a test now checks the output pixels.
6. The Groq key's 1,000 output-tokens-per-minute limit rejected every request with `max_tokens` above 1,000. Requests are now capped, outputs compacted and calls paced. Truncated responses are rejected, so a cut-off transcription can never leave the MRZ unmasked.
7. Misspelled questions ("adhaar") slipped past the refusal, and the model could answer from general knowledge. Fixed with tolerant patterns, an output-side placeholder guard and a grounding check.

### Final sample testing (2026-11-12): bugs found and fixed
Samples: `synthetic_text_sample_forms.pdf` (3-page table forms), `synthetic_scanned_test_id.pdf` (an ID card on an A4 scan), and `Synthetic Document Processing Dataset Sheet.png` (4 documents in one image). Fixed:
1. **Short values spread across the document.** CVV `000` and expiry `00/00` garbled the postal code, the tax reference and phone numbers. Short values are no longer propagated, PDF search hits must spell the exact whole words, and the validator skips short numbers.
2. **"-like/-shaped" labels missed** (`Aadhaar-like number`, `Passport-like reference`). Identity numbers, tax references and generic `… ID` labels are now detected.
3. **Two-column table forms.** Rows are rebuilt as `Label⇥Value` from text coordinates, for both detection and local extraction (53 clean person fields locally).
4. **AI extraction exceeded the 1,000 output-token cap** on a 3-page form. Extraction now runs page by page in a compact format, and a page whose answer is cut off is split in half.
5. **International phone lost its `+`.** A propagated digits-only copy no longer replaces a direct detection.
6. **X-masks printed at about 5pt.** They are now drawn after redaction at the original font size.
7. **Scanned ID card on an A4 page.** One box landed on empty background and a shifted box covered the DOB. Fixed by cropping to the content before vision and rejecting boxes that contain no printed text.
8. **Groq daily quota (200k tokens/day).** The app now fails fast with a clear message instead of retrying for minutes. The misleading "enable image processing" error shown when consent *was* given is fixed. Retry is only offered for temporary errors, and consent errors link to Settings.

9. **4-in-1 dataset image (2026-11-13).** The AI read only one of the four documents, Hindi text used up the output budget, and the Aadhaar number `1234 5678 9012` was not detected. Fixed in four ways:
   - Sheets are split into their separate documents along the blank gutters, and each document is read separately.
   - Non-Latin lines are returned as `[non-English text]`.
   - Wide images are split left/right.
   - A spaced 12-digit number next to "Aadhaar" is detected as an Aadhaar number.

Tests: 128 backend + 6 frontend passing.

**Live result for the dataset image (2026-11-13):** completed in 341 s using 16 Groq calls and about 15k tokens.
- **Read:** all 4 documents (Aadhaar card, passport form, bank form, job form) and 24 person fields.
- **Masked:** the Aadhaar number, the phone (`+XX XXXXX XXXXX`) and the email.
- **Readable:** names, DOB, addresses, education and employer.
- **Validation:** 8 values checked, 0 residual matches.
**Live result for a US passport image (2026-11-14):** 221 s, about 11.6k tokens.
- **Image:** correctly masked. The passport number and both machine-readable lines are burned in, while the name, DOB and photo stay readable.
- **JSON bug found:** the full-image reading failed (Groq `json_validate_failed`), so the image was read in left/right halves, and that cut text lines in two. Effects:
  - The second machine-readable line came back as two short pieces, which were labelled `OTHER_ID` and `CREDIT_CARD` (a 16-digit run passed the card checksum by chance). `USA8810171F2712` and `<585990` stayed readable in the JSON.
  - A partial passport number, `22016774`, stayed unmasked in the stored masked text.
  - The burned-in image was correct.
- **Fixes:**
  1. Images are always split top/bottom, so lines stay whole in at least one half. Multi-document sheets are already separated along their blank gaps.
  2. On a page with a machine-readable line, leftover pieces of it are masked as passport data.
  3. Near-complete partial copies of a found identifier (at most 3 digits missing) are masked.
  4. Machine-readable lines with spaces inside are recognised.
- **Tests:** 131 pass. Checked locally against the actual transcription; not yet re-run live.

- **Known cosmetic issue:** overlapping mask boxes are merged into one, which over-masks two spots. The bank form's empty Date-of-Birth row is covered, and the lower half of "Rahul Sharma" on the job form is covered. This is privacy-safe, since no sensitive data shows.

## Pending / not implemented
- Live verification against the real Groq API: there was no API key in the build environment. All Groq paths are covered with HTTP-level interception. Run `backend/check_groq.py` once a key is set.
- No local vision model, so images require explicit external-image consent (by design).
- Processing is slow on the current Groq tier (about 1–2 minutes per image document) because of the 1,000 output-tokens-per-minute limit.
- No statistical NER model: names and addresses use label and heuristic detection.

## Known issues
- Heuristic detection can miss unlabeled names and addresses, and can over-mask long numbers (classified `OTHER_ID`, flagged for review).
- The masked PDF (`documents.masked_pdf`) is stored **unencrypted**. It contains no identifiers, phone numbers or emails, but it does show names, addresses and DOB. Encrypted at rest: the masked JSON, person details, chat messages and the owner's original phone and email (AES-256-GCM). Encrypting the PDF too is planned.
- The in-memory rate limiter is per process.
- React Router v7 future-flag warnings appear in tests (cosmetic).
- Starlette deprecation warning about `httpx` in TestClient (cosmetic).

## Next implementation step
1. Add a Groq key, run `check_groq.py`, and do a manual chat-quality pass with real documents.
2. Optionally add a local NER model (e.g. spaCy `xx_ent_wiki_sm`) as an extra detector in `pii_service.detect`.
3. For production: Postgres, Redis-backed rate limiting, HTTPS with `COOKIE_SECURE=true` and `APP_ENV=production`, disk encryption, and an external security review.
