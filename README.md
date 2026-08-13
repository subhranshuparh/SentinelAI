# SentinelAI

**Your AI Cybersecurity Copilot for Privacy, Identity, and Safe Browsing.**

SentinelAI catches sensitive information **before you send it** — whether you typed it, pasted it, or it
was printed on a screenshot you were about to attach — tells you when a website, a QR code or a chat
message is trying to take something from you, and correlates all of it into one evolving risk score that
always shows its arithmetic.

Built solo, in a hackathon time-box. **Ten modules end to end, 597 offline tests**, nothing mocked.

---

## The 60-second version

Security tools today are a bag of separate tools. A password manager here, a browser warning there, a
breach email six months late. None of them talk to each other, so nobody ever tells you the sentence
that actually matters:

> *"You've shared four high-risk details this month and visited two impersonation sites. You are more
> exposed than you were last week."*

SentinelAI joins the signals — **what you type**, **what you paste**, **what is printed on the
screenshot you were about to attach**, **where you browse**, **what a QR code actually does**, **who is
messaging you**, and **how exposed your identity already is** — into one score.

A card number typed on a nine-year-old bank domain is routine. The same card on a four-day-old domain
containing the word "amazon" is an incident. An AWS key pasted into your own console is a Tuesday; the
same key pasted into Discord is a breach. A QR code that pays a tea stall ₹45 is lunch; the same format
of code that *debits* you ₹50,000 while promising to pay you is the most-reported scam in the country.
Only a system that sees both halves of each pair can tell the difference — and none of these facts is
visible to a tool that looks at one signal in isolation.

---

## What's built

| Module | Status | What it does |
|---|---|---|
| **M1 — AI Privacy Assistant** | ✅ | 14 detectors + Luhn/Verhoeff checksums + a gated Gemini semantic tier, catching PII as you type. One-click masking that survives rich-text fields. |
| **M2 — Browser Security Copilot** | ✅ | Safe Browsing v4 + RDAP domain age + brand-impersonation detection, itemised in plain words. |
| **M3 — Phishing Email Detector** | ✅ | Paste an email, get itemised evidence. Deterministic link/sender/content heuristics, plus a fenced Gemini intent read that **may raise the risk score and may never lower it**. Stores nothing. |
| **M4 — Identity Guardian** *(partial)* | ✅ | Password-reuse check against 900M+ breached credentials via k-anonymity. Your browser does the hashing and the matching; **five hex characters** leave the machine. |
| **M6 — Security Dashboard** | ✅ | One screen: unified score, breakdown, 21-day trend, threat timeline, ranked next actions, email checker, screenshot checker. |
| **M8 — Explainability narrative** | ✅ | Turns "46" into sentences, each carrying the points it actually cost — and a **counterfactual lever**: the engine is pure, so it is re-run with the top driver removed to say "fix this and you go 46 → 61". Arithmetic, not advice. |
| **M9 — QR scam detection** | ✅ | Right-click any QR image. Decoded locally, then parsed: a `upi://pay` code that **debits** you is not a code that pays you, and the panel says which. Destination shown *above* the verdict. |
| **M10 — Clipboard Guardian** | ✅ | An AWS key pasted into your own console is routine; the same key in Discord is an incident. A synchronous local pre-filter **holds the paste instantly**, then a curated destination table names where it was going. |
| **M11 — Chat scam detection** | ✅ | OTP fraud, advance-fee, digital-arrest and task scams, on any site via right-click plus opt-in auto-watch on WhatsApp/Telegram Web. Quotes the line that triggered it. Stores nothing. |
| **M12 — Screenshot OCR protection** | ✅ | Tesseract runs **locally** — vendored, offline, never a cloud vision API. A misread `234S 6789 9O14` is repaired only where Verhoeff or Luhn confirms the repair, at visibly reduced confidence. |
| **Unified risk engine** | ✅ | Weighted, time-decayed aggregation whose arithmetic is published in the API response. |
| M4 — breach-by-email | Roadmap | Hard external blocker: HIBP's breach-by-email API has required a paid key since 2019 (verified `401`). The free half is what shipped. |
| M5 — Fake reviews · M7 — RAG chatbot | Cut | See [ROADMAP.md](docs/ROADMAP.md) §0 for why each. |

Aadhaar and PAN appear **only** as pattern detection in typed text (M1). They are never checked against
any government record, in M4 or anywhere else, at any budget.

---

## The two rules this codebase is built around

### 1. A signal that did not answer is never counted as a signal that said "fine"

`None` means *"not checked"*. `[]` and `0` mean *"checked, found nothing"*. They are never allowed to
render the same way. Enforced in eleven independent places:

- **Site engine** — an RDAP timeout becomes `weight: "unknown"`, rendered rather than hidden, and the
  scoring denominator becomes the weight that *actually answered*.
- **Risk engine** — a component with no data scores `null`, never 100. A user who has never run a
  password check is not rewarded with a clean bill of health for it.
- **Dashboard** — Identity renders as a dashed grey card with an em dash. There is no honest digit.
- **Extension** — an unreachable backend shows *"SentinelAI is offline — typing is not being checked"*,
  never a green tick.
- **Password check** — if the breach database is unreachable, the API returns `503` and the words
  *"Your password was not checked"*. It never returns an empty range, because an empty range renders
  as "you're safe".
- **Email analysis** — if the AI tier is down, the panel says `heuristics_only` in plain words rather
  than implying a complete check. A `dangerous` verdict from the offline signals alone still shows.
- **QR codes** — a code whose destination is a URL the site engine could not rate makes the *whole QR
  verdict* `unknown`. A payee name that cannot be verified is one grey line saying exactly that, not a
  silent pass. "No QR code found" is its own answer and never a green panel.
- **Clipboard** — the pre-filter is local, so it still holds an `AKIA…` key with the backend down; the
  destination line then reads *"could not check where this was going"* rather than vanishing. An origin
  absent from the destination table returns `unknown` — never "appropriate".
- **Screenshots** — a low-confidence transcript is reported as a poor read even when it found nothing,
  because "we read it badly and saw nothing" is not "it is clean". Every panel carries the caveat that
  handwriting and low-resolution images can be missed, so silence is never sold as a guarantee.
- **Narrative** — an unmeasured component gets its own driver sentence saying it was never checked. The
  counterfactual lever is `null` when nothing actually moves the score, rather than filler advice.
- **Tests** — `test_unknown_is_not_safe`, `test_detail_never_claims_a_check_that_did_not_happen`, and
  friends assert the property directly, so the rule survives a refactor by someone who never read this
  paragraph.

The corollary is one-sided on purpose: **thin evidence blocks a clean bill of health; it never
suppresses a warning.** Unplug the network and a brand-impersonation domain still reads `dangerous`,
and an email whose link points somewhere other than where it claims is still called out.

### 2. Explainability is a schema, not a promise

Every prediction returns confidence, reason, itemised factors, a plain-language explanation, and a
suggested action — because `reason` and `confidence` are **required fields in the Pydantic models**.
A bare verdict is not serialisable by this API.

```json
{
  "pii_type": "aadhaar",
  "confidence": 0.96,
  "reason": "Matches 12-digit Aadhaar format and the Verhoeff checksum validated",
  "explanation": "Aadhaar numbers can be used to open accounts in your name.",
  "recommendation": "Mask before sending",
  "masked_preview": "XXXX XXXX 9014"
}
```

---

## Quick start

Prerequisites: Python 3.11+, Node 22+, a Chromium browser. Nothing else — no Postgres, no Redis, no
Docker.

```bash
./run.sh            # first run: add --setup to create the venv and install everything
```

That starts the backend, the dashboard and the typing-test page, waits until `/health` actually answers
before opening anything, then **opens the pages in Chrome for you** — dashboard, typing-test page, and
on the very first run `chrome://extensions`, because loading the extension is the one step no script can
perform. `Ctrl+C` stops all three, and `./run.sh --stop` is the guaranteed cleanup if anything is ever
left holding a port. Each service logs to `.logs/` so one crash doesn't scroll away under the other two.

| | |
|---|---|
| `./run.sh` | start everything |
| `./run.sh --setup` | fresh clone — creates the venv, installs both dependency sets, seeds, then starts |
| `./run.sh --seed` | re-seed 21 days of history, then start. Worth running right before a demo |
| `./run.sh --stop` | stop everything |
| `./run.sh --no-open` | don't launch a browser |

<details>
<summary>Or start the three services by hand</summary>

```bash
# 1 — Backend
cd backend
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # bin/python on macOS/Linux
cp .env.example .env                                          # keys are optional; see below
.venv/Scripts/python.exe -m app.db.seed                       # 21 days of demo history
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000

# 2 — Dashboard (new terminal)
cd dashboard && npm install && npm run dev                    # http://localhost:5173

# 3 — Typing-test page (new terminal)
cd extension && python -m http.server 8080                    # http://localhost:8080/test/harness.html
```

Use `localhost:5173`, not `127.0.0.1:5173` — Vite binds IPv6 loopback only.
</details>

The extension is the one step no script can do for you — `chrome://extensions` → **Developer mode** →
**Load unpacked** → select [extension/](extension/). It stays loaded afterwards.

Then open `http://localhost:8080/test/harness.html` and type `2345 6789 9014`.

Things to try immediately after — the harness page has a fixture for each:

- **Password check** — click the SentinelAI toolbar icon, type `password` into the password box, press
  *Check against breaches*. It comes back as appearing in **52,372,427** breached accounts. Watch the
  network tab: five characters were sent.
- **Email check** — scroll to the bottom of the dashboard, paste a phishing email into *Check an email*
  (there's one in [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)). Every signal is itemised with the exact text
  that triggered it.
- **Clipboard** (§6) — copy the `AKIA…` chip and paste it into the box below. The paste is *held*
  before a character reaches the field, with no network call involved at all.
- **QR code** (§5) — right-click the "Scan to receive ₹50,000" code. It **pays out** ₹50,000, and the
  panel says so above the verdict. The ₹45 tea-stall code beside it stays `safe`.
- **Chat scam** (§7) — select the OTP script, right-click, *Check this message*. `dangerous`, offline,
  quoting the exact line that triggered it.
- **Screenshot** (§8) — press *Attach* under the Aadhaar card. It is drawn on a canvas by the page
  itself; there is no photograph of a real document in this repository. Press *Attach* under the
  misread one and watch the confidence drop from 0.96 to 0.75 with the corrections named.

Full instructions, troubleshooting, and reset procedures: **[RUNBOOK.md](docs/RUNBOOK.md)**.

### Running without API keys

Both keys are optional, and the degraded behaviour is designed rather than incidental:

| Missing | Effect | Still works |
|---|---|---|
| `GEMINI_API_KEY` | `tier_2_status: "disabled"` — configuration, not failure. Email analysis returns `heuristics_only: true` and says so | All 14 detectors, checksums, masking, dashboard, **all M3 Tier-1 signals** |
| `SAFE_BROWSING_API_KEY` | Signal reports `weight: "unknown"`, confidence drops | RDAP age, brand mismatch, verdicts, badge |
| *(none needed)* | Pwned Passwords and RDAP take **no key at all** | Password check works out of the box |
| **Both, network unplugged** | Offline mode | Tier 1 PII + brand mismatch + M3 link/sender/content heuristics + full dashboard |

---

## Tests

```bash
cd backend && .venv/Scripts/python.exe -m pytest tests -q
# 597 passed in ~75s
```

**No network, no server, no API keys.** Gemini and Safe Browsing are stubbed, so the suite stays green
on a dead Wi-Fi connection — which is also when you most need it. No image and no browser either: the
OCR-repair logic is pure functions over strings, so `test_ocr_normalise.py` runs in milliseconds without
Tesseract in the process at all.

---

## Architecture at a glance

```
Chrome MV3 extension          FastAPI backend                  React dashboard
  content script                Tier 1: 14 regex detectors        one endpoint
  250ms debounce   ──msg──►     + Luhn / Verhoeff       ──────►   one round trip
  clipboard.js      (only          ↓ (gated)                      one screen
   sync pre-filter,  network    Tier 2: Gemini, fenced            + email checker
   holds the paste)  path       ────────────────────              + screenshot panel
  upload.js                      destinations: where                   │
  chat.js                        was it going?                         │
  service worker                 ────────────────────                  │
   the ONLY place                Safe Browsing ‖ RDAP ‖ brand          │
   fetch() is called             ────────────────────                  ▼
  popup: SHA-1                   HIBP range (k-anonymity)      POST /phishing/analyze
  computed LOCALLY,              ────────────────────           POST /scam/analyze
  5 hex chars out  ────────►     M3 email ‖ M11 chat            (neither handler has
                                     ↓ Gemini intent             a DB session at all)
  offscreen document                 may RAISE, never lower
   jsQR + Tesseract              ────────────────────
   IMAGES NEVER LEAVE  ─text─►   QR parse → site engine
   THIS MACHINE                  OCR repair, checksum-gated
                                 ────────────────────
                                 Risk engine: weighted,
                                 decayed, self-explaining
                                      ↓
                                 Narrative: drivers +
                                 a re-run counterfactual
```

**Why two detection tiers:** an LLM call per keystroke is ~600 ms and costs money per character typed.
Pure regex can't tell an address in a shipping form from an address in a quoted news article. So:
deterministic checksums for structured data at zero latency and zero cost, and the semantic tier only on
the uncertain remainder — gated on ≥40 chars, ≥6 words, and Tier 1 having found nothing serious. The
Aadhaar demo never touches the network beyond localhost.

**Why only the service worker calls `fetch()`:** under MV3 a content script's `fetch()` obeys the *host
page's* CORS policy, not the extension's. Content scripts get a message-passing shim with an identical
surface.

**Why an offscreen document:** `jsQR` and Tesseract need a DOM and a worker, and a service worker has
neither. Putting them in the *host page* instead would mean injecting a decoder into every site you
visit and reading pixels in a context the page can tamper with. The offscreen document runs on the
extension's own origin, so the image is decoded somewhere the page cannot reach — and only the resulting
**text** is ever sent anywhere.

**Why the paste guard is synchronous and the OCR is not:** `preventDefault()` on a `paste` event must be
called in the same tick. A network round trip cannot be. So the blocking decision is made by a tiny
prefix-anchored local matcher (`AKIA`, `ghp_`, `sk_live_`, `xoxb-`, `eyJ…`) with **zero** network cost,
and everything else flows to the existing debounced scanner. A screenshot has no equivalent deadline —
nothing about a `change` event is cancellable — so it takes the seconds it needs.

Full design and trade-offs: **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## Security posture

This product reads text a user typed into their bank. The security model *is* the product.

- **No plaintext PII is ever persisted.** Classification and a masked preview only. Never logged, never
  cached.
- **Passwords are never read, and never transmitted.** `password`, `hidden`, `file` and four other
  input types are refused before capture. The one password the user *chooses* to check is SHA-1'd in
  the browser; only the first **5 hex characters** are sent, and the database column is `VARCHAR(5)`,
  so a full hash physically will not fit. ~2,000 real passwords share any given prefix (1,978 measured
  live) — the server learns a crowd, not a person.
- **Email bodies and chat messages are never stored.** `POST /phishing/analyze` and
  `POST /scam/analyze` take no database session at all, so persisting one is not something a future
  edit can do by accident. A test enumerates every table and asserts zero rows after an analysis.
- **Image bytes never leave the machine.** OCR is a vendored Tesseract build running in the extension's
  own offscreen document, or in the dashboard's browser tab. Only the extracted *text* reaches
  localhost, and only its classification plus a masked preview is stored. Gemini Vision was rejected on
  principle: uploading the Aadhaar photo is the precise act this feature exists to prevent.
- **OCR may only correct a character a checksum can vouch for.** Rewriting input is inventing data, so
  the repair is gated on Verhoeff or Luhn validating afterwards, capped at three characters, and each
  substitution is named in the reason. PAN and passport numbers have no checksum and are therefore
  deliberately *not* repairable — this module cannot hallucinate an identity document into existence.
  One candidate per span, never a search: thirty candidates against a one-in-ten checksum would find a
  "valid" Aadhaar in almost any blob of text.
- **Reading other people's messages is opt-in.** Chat auto-watch is off by default, enabled per surface,
  and shows an on-screen marker the entire time it runs. Outgoing messages are never scanned — that is
  the typing path's job, and warning twice teaches people to dismiss.
- **The clipboard is read only inside a paste handler**, which needs no permission at all; the
  `clipboardRead` permission is deliberately *not* requested. Password fields are refused before the
  clipboard is even consulted.
- **Vendored binaries are pinned and verifiable.** ~9 MB of jsQR and Tesseract ship as committed files
  because MV3 forbids a CDN and remote code in a security tool is indefensible. Every SHA-256 is in
  `extension/lib/vendor/CHECKSUMS.sha256`, `run.sh --setup` refuses to finish if one does not match, and
  an ordinary run warns loudly while leaving every other feature working.
- **Prompt-injection defence, four layers on the typing path and five on email:** instructions and
  untrusted content are never concatenated; the data block is fenced with a per-request random token;
  the output schema makes disobedience unrepresentable; every returned finding must appear as a
  literal substring of the input or it is discarded — and for email, **the model never writes the
  recommendation**, it only classifies into an enum, with the action sentence authored in Python.
  Live injection payloads are in the test suite: an email that *orders* the model to report itself
  benign is still scored `dangerous`.
- **No keys in client code.** Zero secrets in `extension/` or `dashboard/` — both are inspectable by
  anyone. All keyed calls are server-side, from a gitignored `.env`.
- **Query strings stripped** before any URL reaches Google. Reset tokens live there. Paths are kept,
  because phishing lives on paths.
- **CORS is an allowlist, never `*`.** Rate limiting is a per-device token bucket, 120/min, with
  `Retry-After`.
- **Auth** is device-header mode for the demo; the JWT path is written and flag-gated. `ENABLE_JWT_AUTH=true`
  locks every endpoint, including the dashboard's convenience path.
- **Aadhaar and PAN are pattern detection in typed text only.** No verification against any government
  record, at any budget. This does not change.
- **HTTPS is a stated deployment TODO.** The demo is loopback-only; TLS is step one the moment it isn't.

---

## Documentation — the 15 deliverables

**Start here:** [RUN_IN_VSCODE.md](docs/RUN_IN_VSCODE.md) to get it running and see it work ·
[FEATURES.md](docs/FEATURES.md) for what every feature does, who it helps, and how it was built.

| # | Deliverable | |
|---|---|---|
| 1 | [ROADMAP.md](docs/ROADMAP.md) | Scoped build plan, four spec deviations with reasoning |
| 2 | [FOLDER_STRUCTURE.md](docs/FOLDER_STRUCTURE.md) | Repo layout and why it's shaped that way |
| 3 | [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | Five tables, SQLite via SQLAlchemy 2.0 |
| 4 | [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, trade-offs |
| 5 | [API.md](docs/API.md) | Endpoint contracts and scoring rules |
| 6 | [`backend/`](backend/) | FastAPI service — detectors, site engine, risk engine |
| 7 | [`extension/`](extension/) | Chrome MV3 extension — no build step |
| 8 | [`dashboard/`](dashboard/) | Vite + React + TS + Tailwind + Recharts |
| 9 | [INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md) | Every external dependency, quota, TTL, failure mode |
| 10 | [RUNBOOK.md](docs/RUNBOOK.md) | Run it, break it, fix it |
| 11 | [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Three minutes, three beats, with fallbacks |
| 12 | [PITCH.md](docs/PITCH.md) | The story and the honest answers |
| 13 | README.md | This file |
| 14 | [RUN_IN_VSCODE.md](docs/RUN_IN_VSCODE.md) | Open the folder, press two buttons, watch it work |
| 15 | [FEATURES.md](docs/FEATURES.md) | Every feature: the problem, who it helps, how it was built |

---

## What was cut, and why

Seven modules at 40% completion demos as zero modules. Modules built end-to-end prove the thesis.

| Cut | Reason |
|---|---|
| PostgreSQL + Redis + Celery | Two daemons that can die mid-judging. `DATABASE_URL` is the whole migration; the cache already has Redis's `get`/`set(key, ttl)` interface. |
| Login / signup UI | ~3 hours producing zero judge-visible value. The auth dependency is real code behind a flag. |
| HIBP breach-by-email | External blocker — paid key since 2019, verified `401`. The free half (k-anonymity password check) is a better security story, and it shipped. |
| M5 fake reviews, M7 RAG chatbot | Weakest link to the thesis / seen fifty times, competing with demo polish. |
| M2 Tier 2/3 — SSL inspection, redirect tracing, visual brand ML | Roadmap slide. Tier 1 already carries the demo. |

Each of these is argued in full in [ROADMAP.md](docs/ROADMAP.md) §0–1.

---

## Stack

**Backend** FastAPI · Pydantic 2 · SQLAlchemy 2.0 · httpx · pytest.
**Extension** Chrome MV3, plain JS, no build step · offscreen document for the decoders.
**Dashboard** Vite 8 · React 19 · TypeScript · Tailwind 3 · Recharts.
**On-device** jsQR 1.4.0 · Tesseract.js 5.1.1 + `tessdata_fast` — vendored, pinned, checksummed, offline.
**AI** Google Gemini (`gemini-2.5-flash`) · Google Safe Browsing v4 · RDAP · HIBP Pwned Passwords.
