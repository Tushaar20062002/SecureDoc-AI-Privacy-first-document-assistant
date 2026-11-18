# SecureDoc AI — Privacy-Preserving Document Intelligence Chatbot

A privacy-first MVP. Users upload PDFs (job applications, government forms, bank forms). Personal data is
**detected and masked locally on the server before any external AI call**. The app then produces a masked
JSON file and, optionally, a permanently redacted PDF. Users can chat with each document under rules that the
backend enforces.

- **Backend:** Python 3.14, FastAPI, SQLAlchemy, Pydantic, SQLite, PyMuPDF, Argon2id, AES-256-GCM
- **Frontend:** React 18, Vite, Tailwind CSS v4, Axios, React Router
- **AI:** Groq (optional). Without a key or without the user's consent, the app falls back to local extraction and answering.

---

## 1. Local setup

### Prerequisites
- Python 3.12–3.14 (3.14 was used here; 3.15 lacks wheels for some dependencies)
- Node.js 20+ (24 was used)

### Backend
```powershell
cd backend
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env          # then edit: GROQ_API_KEY, ENCRYPTION_KEY, SECRET_KEY
.venv\Scripts\python check_groq.py   # optional: verifies the configured Groq models exist for your key
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Generate keys with:
`python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`.
In development, empty keys are generated automatically into `backend/.keys/`, outside the database.

### Frontend
```powershell
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173 (proxies /api to :8000)
```
Open http://127.0.0.1:5173, register, complete the privacy setup, then upload a PDF.

### Tests
```powershell
cd backend;  .venv\Scripts\python -m pytest tests -q          # 88 backend tests
cd frontend; npm test                                          # 6 component tests
# full-stack demo while both servers are running:
cd backend;  $env:PYTHONIOENCODING="utf-8"; .venv\Scripts\python scripts\e2e_demo.py
```

---

## 2. Privacy architecture

> **Masking scope (policy v1.1, default):** only *sensitive identifiers* are masked. These are government IDs (Aadhaar, PAN, passport, voter ID, driving licence), bank and card details (account, IFSC, card number, CVV, expiry), passwords/PINs/OTPs, IP addresses, **mobile numbers and email addresses**. Names, addresses, dates of birth, reference numbers, education and employment stay readable and are sent to Groq when the user consents.
>
> This follows India's IT (SPDI) Rules 2011 (Rule 3: passwords and financial information such as bank account and card details are *sensitive personal data*) and UIDAI's requirement that Aadhaar numbers be masked before storage.
>
> The scope is configurable with `MASK_CATEGORIES` in `backend/.env`. Add `PERSON,ADDRESS,DOB,APP_REF` to also mask names, addresses, birth dates and references; the table below then applies in full. Changing the scope should come with a `POLICY_VERSION` bump so that users re-consent.

| Category | Examples | Storage | Sent to Groq | Chatbot |
|---|---|---|---|---|
| **A. Owner-visible** (configurable) | name, address, email, phone, DOB, application refs | Original kept **only if permitted**, encrypted with AES-256-GCM (bound to user and document) | Never (placeholder only) | Shown only if currently permitted; otherwise the placeholder |
| A. Content (configurable) | education, employment | Readable in masked JSON | Yes (not personal identifiers) | Hidden if the user disables it |
| **B. Restricted** (fixed) | Aadhaar, PAN, passport, bank account, IFSC, cards, CVV, passwords, PIN, OTP, IP, other IDs | **Never retained** | Never | Always refused |
| **C. Masked** | `[PERSON_001]`, `[AADHAAR_001]`… | Masked JSON in the database | Default LLM context | — |

**Processing pipeline** ([extraction_service.py](backend/app/services/extraction_service.py)):
1. The upload is validated (size, signature, structure, encryption, page limit) and written under a random name to a private temp directory. **PDF, PNG, JPEG and WebP** are accepted. The type is decided by the file's content (magic bytes), never by its name; for example, a WebP named `.jpeg` is handled correctly. Images are decoded with a pixel limit (decompression-bomb guard), auto-rotated, re-encoded **without EXIF/GPS metadata** and wrapped into a one-page PDF in memory. Images need the external-image consent, because no local OCR exists.
2. PyMuPDF extracts text, word positions and form-field values per page. Each page is classified as text, scanned or blank.
3. **Local PII detection** ([pii_service.py](backend/app/services/pii_service.py)) combines label-aware extraction, format regexes, Verhoeff (Aadhaar) and Luhn (card) checksums, and heuristic NER (honorifics, declarations, relations, pincode address lines). Detected values are then propagated to every other occurrence in the document.
4. Consistent placeholders are assigned per (category, value) across the whole document.
5. If the user consented, **masked text only** goes to Groq in one structured JSON call per text batch. An **egress guard** ([groq_service.py](backend/app/services/groq_service.py)) blocks any payload that contains a known original value or a high-confidence identifier pattern.
6. The model output is validated with Pydantic, then **policy is enforced**: invented placeholders are removed, identifiers are re-masked, and restricted categories are forced to `[REDACTED]`. Sensitivity flags are computed by the backend, not by the model.
7. Masked PDF ([masking_service.py](backend/app/services/masking_service.py)):
   - Redaction annotations are applied with `apply_redactions` (text removed, not overlaid).
   - Every embedded image is removed. With image consent, a **pixel-redacted and re-checked copy** is put back in its place (see below); otherwise a labelled placeholder is shown.
   - Invisible text layers (OCR layers, render mode 3) are deleted without drawing visible X marks.
   - Form widgets and annotations are deleted.
   - Metadata, XML metadata, JavaScript, attachments and links are scrubbed.
8. **Validation:** the generated PDF is reopened and its text, widgets, annotations and metadata are re-extracted and searched for every original value. If anything is found, the PDF is **withheld** and the document is marked `needs_review`.
9. The temp original is overwritten and deleted (`finally`), on success and on failure alike.

**Scanned pages:** no OCR engine and no local vision model are used. Scanned pages are processed only when the user turns on the separate consent "send ORIGINAL scanned page images to external vision AI", which states clearly that unmasked PII will be visible to the provider. Without that consent, scanned pages are reported as unsupported, **never sent anywhere**, and replaced in the masked PDF by a notice page.

With consent, scanned pages, image uploads and embedded images (e.g. a passport photo page inside a PDF) go through this process ([vision_service.py](backend/app/services/vision_service.py), [image_service.py](backend/app/services/image_service.py)):

1. **Transcribe with line boxes.** The vision model (`qwen/qwen3.8-27b`) returns every text line with an approximate box on a 0-1000 grid.
   - Images are **padded to a square** and downscaled to at most 1000 px first. On non-square images, the model's y-coordinates drifted by about 30% in testing.
   - Machine-readable zones (passport MRZ) are included.
2. **Detect locally.** The transcription is masked like any other text. **ICAO 9303 MRZ lines** are detected and their check digits validated. The passport number they encode is masked wherever else it is printed.
3. **Burn into the pixels.** Sensitive regions are filled and overwritten with X marks; nothing is overlaid on top of the original.
   - Model boxes are approximate: they sit too high and are too short for large print. Each box is therefore **snapped to the real band of dark text pixels** with simple local image processing (a row-darkness profile, not OCR), then padded.
4. **Re-check independently.** A second vision call reads the redacted image. If any sensitive value is still readable, padding is doubled and the check repeats.
5. **Fall back safely.** If the re-check still fails, or a sensitive line had no box:
   - A scanned page is rebuilt from **masked text only**.
   - An embedded image is replaced by a placeholder.
   - The document is marked `needs_review`.
   - **Original pixels are never kept.**

Truncated AI responses (`finish_reason=length`) are treated as failures, never as complete transcriptions. Pages too dense for one response are read as overlapping halves.

---

## 3. Security controls
- **Passwords:** Argon2id (m=19 MiB, t=2, p=1), a strength policy, and dummy-hash timing equalisation for unknown emails.
- **Sessions:** 256-bit random tokens. Only their SHA-256 hash is stored. They expire and are deleted at logout.
- **Cookies:** `HttpOnly` and `SameSite=Strict` session cookie. `Secure` is enforced when `APP_ENV=production`.
- **CSRF:** a session-bound HMAC token is required in `X-CSRF-Token` on every state-changing request. Origin checking and strict CORS are added as defence in depth.
- **Rate limiting:** per IP, for auth, upload and chat.
- **Upload size:** a streaming body-size limit (ASGI level) plus a `Content-Length` check.
- **Storage:** private, with random filenames and path-traversal-safe resolution. Original PDFs are never persisted.
- **Ownership:** checked on every document, chat and download request. Missing and foreign documents both return 404.
- **Encryption:** AES-256-GCM with associated data `user|document`. The key comes from the environment, outside the database.
- **Responses:** security headers (nosniff, DENY framing, no-store, CSP and HSTS on HTTPS). Validation errors never echo submitted values, and unhandled errors return a generic 500.
- **Logging:** messages are sanitized, with a redaction filter for emails and digit runs. Exceptions are logged by type only.
- **Database:** SQLite `foreign_keys=ON` and `secure_delete=ON`, cascading deletes, and transactional preference changes.

---

## 4. API reference
Interactive docs: http://127.0.0.1:8000/api/docs (disabled in production).
State-changing endpoints require the `X-CSRF-Token` header.

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | `{email, password}` → creates account + session |
| POST | `/api/auth/login` | `{email, password}` |
| POST | `/api/auth/logout` | Invalidates the session; deletes session-only documents |
| GET | `/api/auth/me` | Current user, `onboarding_complete`, `csrf_token` |
| GET | `/api/privacy/policy` | Policy version, configurable fields, fixed restrictions, consent texts |
| GET/PUT | `/api/privacy/preferences` | Read or update permissions (`accept_policy` required the first time) |
| GET | `/api/privacy/consents` | Versioned consent records (granted / revoked timestamps) |
| DELETE | `/api/privacy/documents` | Delete all of the user's documents |
| POST | `/api/documents/upload` | multipart `file` (PDF, PNG, JPEG, WebP) + `output_mode` (`pdf_and_json` \| `json_only`). The UI sends batches of up to 10 files, 2 at a time |
| GET | `/api/documents/download/zip?ids=a,b,…` | Masked PDFs and person JSON of the user's own documents in one ZIP (up to 50) |
| GET | `/api/documents` | The user's documents |
| GET | `/api/documents/{id}` | Masked data, entity summary, warnings |
| GET | `/api/documents/{id}/download/pdf` | Masked PDF (if generated and validated) |
| GET | `/api/documents/{id}/download/json` | Masked JSON |
| DELETE | `/api/documents/{id}` | Deletes the outputs and the chat |
| POST | `/api/documents/{id}/chat` | `{message}` → sanitized user and assistant messages |
| GET | `/api/documents/{id}/chat/history` | Document-specific history |

Chat answer `kind` values: `owner_field`, `restricted`, `permission_disabled`, `not_retained`,
`document_answer`, `out_of_scope`, `missing`, `error`.

---

## 5. Retention
- **History on:** masked JSON, the masked PDF and chats are kept until the user deletes them.
- **History off:** new documents get `expires_at` equal to the session expiry. They are deleted at logout, at expiry (a background purge runs every 5 minutes), or on the next listing. During the session the masked JSON, masked PDF and chat have to exist so that the workspace works.
- **Revoking a field permission** permanently destroys the retained original values for that category across all of the user's documents. Re-enabling it applies only to future uploads.

---

## 6. Known limitations (honest)
- **Detection is not perfect.** Names and addresses are found from labels and heuristics, not a statistical NER model (spaCy and similar were not used, to keep the stack small). Free-text names without labels or honorifics can be missed. Low-confidence detections are flagged and the document is marked `needs_review`. Review outputs before sharing them.
- **No local vision model.** Images need explicit consent to external image processing, because the original image (unmasked) goes to Groq. AI transcription can misread characters; in testing, "CALLIE" was read as "CALIE" once. Pixel redaction is verified by a second AI reading plus local ink snapping, but an AI re-check is not proof. Review masked images before sharing them.
- **Two Groq models, two quotas.** Groq rate limits are per model. Extraction and images use `GROQ_MODEL` / `GROQ_VISION_MODEL` (`qwen/qwen3.8-27b`). The chatbot uses `GROQ_CHAT_MODEL` (`openai/gpt-oss-120b`, `reasoning_effort=low`), which has its own 8k TPM and daily quota. Chat sends the masked document as compact plain lines (about 2,150 prompt tokens for a 3-page form; the JSON form was about 3,175). Leave `GROQ_CHAT_MODEL` empty to use one model for everything.
- **Groq rate limits on the current key:** `qwen/qwen3.8-27b` allows **1,000 output tokens per minute** and 8,000 tokens per minute. Any request whose `max_tokens` exceeds the output limit is rejected outright. The app caps requests (`GROQ_MAX_OUTPUT_TOKENS=1000`), uses compact output formats, and waits for the provider's reset time instead of failing. As a result, an image document takes about 1–2 minutes, and a 3-file batch took about 6.5 minutes in testing. A higher Groq tier removes this wait; raise `GROQ_MAX_OUTPUT_TOKENS` accordingly.
- **Groq configuration:** `qwen/qwen3.8-27b` is used for both text and images. It was verified live with `check_groq.py`. The other models on the account (gpt-oss, allam) reject image input. On networks that inspect HTTPS traffic, the client uses the OS certificate store (`truststore`); certificate verification is never disabled.
- **Education and employment text is sent to Groq in masked form** because it is not a personal identifier. Disabling those categories hides them from display and from chat context.
- **The rate limiter is in-memory** (per process). Use Redis or a gateway in production.
- **SQLite** is suitable only for the MVP. Disk-level encryption of the database and storage is recommended.
- Secure overwrite of temp files is best effort (SSDs and journaling filesystems may keep copies).
- Recording consent does **not** establish legal compliance (e.g. with the DPDP Act or GDPR). Get a legal review before production use.
- This is an MVP that has been tested as described. It has **not** had an external security audit and should not be described as production-grade.
