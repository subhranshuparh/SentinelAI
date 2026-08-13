# SentinelAI — System Architecture

**Deliverable 4 of 15.** The simplified single-service design that is actually being built.

---

## The diagram

```
┌───────────────────────────────────── USER'S BROWSER ─────────────────────────────────────┐
│                                                                                          │
│  content scripts · plain JS, no build step        background.js       popup.js           │
│  ├ content.js    typing · 250 ms debounce        ├ navigation →      ├ site verdict      │
│  ├ clipboard.js  paste · sync pre-filter   M10   │   /site/check     ├ findings          │
│  ├ upload.js     <input type=file>         M12   ├ contextMenus:     └ password check:   │
│  ├ chat.js       WhatsApp/Telegram opt-in  M11   │   QR · selection      SHA-1 LOCAL,    │
│  └ toast.js      ONE warning UI for all of them   ├ badge colour          5 hex chars out│
│                                                  └ storage.local                         │
│         ▲                                            │                                   │
│         │ decoded TEXT only — never the image        ▼                                   │
│  ┌ offscreen document · extension origin, not the host page ────────────────────────────┐│
│  │ jsQR  40 KB, one file          → QR payload      M9                                  ││
│  │ tesseract.js + wasm + eng      → OCR text        M12                                 ││
│  │ vendored, pinned, SHA-256 in INTEGRATION_NOTES.md · nothing from a CDN               ││
│  │ IMAGE BYTES NEVER LEAVE THIS DOCUMENT                                                ││
│  └──────────────────────────────────────────────────────────────────────────────────────┘│
│                                                                                          │
│         │  X-Sentinel-Device-Id                                                          │
└─────────┼─────────────────────────────────────────────────────────────────────────────────┘
          │  CORS allowlist: chrome-extension://<id>, localhost:5173
          ▼
┌───────────────────────────────── FastAPI · ONE PROCESS ──────────────────────────────────┐
│                                                                                          │
│  routers/  (thin: validate → call one service → return. no `if`.)                        │
│  ├ pii.py  ├ site.py  ├ qr.py  ├ scam.py  ├ phishing.py  ├ identity.py  ├ dashboard.py   │
│        │         │        │        │          │            │            │                │
│        ▼         ▼        ▼        ▼          ▼            ▼            ▼                │
│  services/  ★ all logic lives here. zero fastapi imports.                                │
│             ★ nothing under pii/ imports the ORM — the engine runs with no DB.           │
│                                                                                          │
│  ┌ pii/ · M1 · M10 · M12 ─────────────────┐  ┌ site/ · M2 ──────────────────────────────┐│
│  │ TIER 1 detectors.py                    │  │ safebrowsing.py  (API key)               ││
│  │   14 regex + checksums.py              │  │ rdap.py          (free)                  ││
│  │   Luhn · Verhoeff · 0 ms · $0          │  │ brand.py         (local)  ──┐            ││
│  │ ocr_normalise.py       M12             │  │        ↓ engine.py           │           ││
│  │   ONE candidate per span,              │  └──────────────────────────────────────────┘│
│  │   checksum-authorised only             │  ┌ qr/ · M9 ────────────────────────────────┐│
│  │ destinations.py        M10             │  │ parse.py  url|upi|wifi|vcard             ││
│  │   118 origins × 9 classes              │  │ engine.py URL → site.engine ←┘           ││
│  │        ↓ if uncertain                  │  │           UPI → structural,              ││
│  │ TIER 2 llm/gemini.py                   │  │           graded by amount               ││
│  │   FAIL-OPEN → tier 1 stands            │  │ no domain → nothing written              ││
│  └────────────────────────────────────────┘  └──────────────────────────────────────────┘│
│                                                                                          │
│  ┌ phishing/ · M3 ────────────────────────┐  ┌ scam/ · M11 ─────────────────────────────┐│
│  │ heuristics.py  links·sender            │  │ heuristics.py  conversation              ││
│  │                ·content                │  │   otp_solicitation = 95,                 ││
│  │ llm/prompts.py fenced intent           │  │   conclusive on its own                  ││
│  │ MAY RAISE, NEVER LOWER                 │  │ llm/scam_prompts.py — all 5              ││
│  └────────────────────────────────────────┘  │   injection defences reused              ││
│  ┌ identity/ · M4 ────────────────────────┐  │ MAY RAISE, NEVER LOWER                   ││
│  │ pwned.py  k-anonymity,                 │  └──────────────────────────────────────────┘│
│  │           5 hex chars out              │  ┌ risk/ · M6 + M8 ─────────────────────────┐│
│  │ engine.py prevalence bands,            │  │ engine.py    privacy ·                   ││
│  │           supersede by label           │  │   browsing · identity → one              ││
│  │ NO LLM TIER AT ALL                     │  │   explainable score                      ││
│  └────────────────────────────────────────┘  │ narrative.py ★ re-runs                   ││
│                                              │   engine.py MINUS the top                ││
│                                              │   driver — the lever is a                ││
│                                              │   counterfactual, not a guess            ││
│                                              └──────────────────────────────────────────┘│
│                                                                                          │
│  core/  config · cache (Redis-shaped) · ratelimit · security                             │
└──────────┬─────────────────────────────────┬──────────────────────────────────────────────┘
           │                                 │
           ▼                                 ▼
    ┌ SQLite · 5 tables ───────────────┐      ┌ EXTERNAL · server-side only ─────────┐
    │ no raw PII      no passwords     │      │ keys never reach the browser         │
    │ no emails       no chat logs     │      │ Gemini · Safe Browsing               │
    │ no images       no QR payloads   │      │ RDAP · HIBP (no key)                 │
    └──────────────────────────────────┘      └──────────────────────────────────────┘

    ┌ Dashboard · React + Vite ──────────────────────────────────────────────────┐
    │ GET  /dashboard/summary   one round trip, every widget                     │
    │ POST /phishing/analyze    stores nothing                                   │
    │ POST /scam/analyze        stores nothing                                   │
    │ POST /qr/check            ScreenshotChecker.tsx: OCR + QR in one panel,    │
    │ POST /pii/scan            tesseract.js in a worker, IMAGE STAYS LOCAL      │
    └────────────────────────────────────────────────────────────────────────────┘
```

---

## Six decisions, and what each one costs

### 1. One process, not microservices

Your spec allows microservices. Rejected, and not only for build time.

At 2am with a judge watching, a single process means **one log stream**. A four-service split means a
failure is somewhere in four terminals plus the network between them. Microservices buy independent
scaling and independent deploys — neither of which exists in a 24-hour demo on localhost.

The module boundaries the spec wants are real, they just live in `services/` where they cost nothing.
Keep the microservices diagram for the *"how we'd scale this"* slide, where it's an architecture answer
instead of an architecture bill.

### 2. Two-tier PII detection — the actual technical claim

| | Tier 1 · regex + checksums | Tier 2 · Gemini |
|---|---|---|
| Latency | ~0 ms | ~400–900 ms |
| Cost | $0 | per call |
| Offline | ✅ | ❌ |
| Catches | structured: cards, Aadhaar, IFSC, JWT | contextual: *"meet me at 42 Oak St"* |

**LLM-per-keystroke is unusable** — it's slower than typing and you pay per character. **Regex-only
can't tell** a shipping address from an address quoted in a news article. The hybrid isn't a hackathon
compromise, it's the production answer: deterministic layer handles the deterministic 90% at zero cost,
the semantic layer runs only on the uncertain remainder.

**Tier 2 fails open.** 1.5 s timeout; on timeout, error, missing key, or dead network, Tier 1 results
return as-is. Degradation must never be indistinguishable from "nothing found" — the response carries
`tier_2_available: false` so the UI can say so.

### 3. Keys live server-side, always

The extension calls *your* backend. It never holds a Gemini or Safe Browsing key.

Extension code is plain text to anyone who opens `chrome://extensions`. A key shipped there is a
published key. This is also why `.env.example` gets scrubbed and `gen-lang-client-*.json` is
gitignored — same rule, three places.

### 4. `unknown` is a first-class verdict

RDAP 404s on some ccTLDs. Safe Browsing can be rate-limited or keyless. When a signal is missing, the
risk engine **redistributes its weight** and the verdict may be `UNKNOWN` — never `SAFE`.

Collapsing *"we couldn't tell"* into *"it's fine"* is the single most common way a security tool lies
to its user, and it's a one-line bug to introduce.

### 5. Cache shaped like Redis, backed by a dict

`get(key)` / `set(key, value, ttl)`.

This is **demo infrastructure, not an optimisation**. Rehearsing the site check 20 times on the same
domain must not burn Safe Browsing quota or get you RDAP-throttled at the exact moment you're on stage.
6-hour TTL. Swapping in real Redis is an import change, which is a claim you can back by opening the
file.

### 6. The two-tier shape is reused, not reinvented — and Tier 2's power is asymmetric

Modules 1 and 3 have the same skeleton: a deterministic tier that is free, offline, and instant, and a
semantic tier that runs only where determinism runs out. What differs is **what the LLM is allowed to
do with its answer**, and that difference is deliberate:

| | M1 · PII | M3 · Phishing |
|---|---|---|
| Tier 1 | 14 regex + Luhn/Verhoeff | links · sender · content heuristics |
| Tier 2 gate | Tier 1 found nothing and text looks contextual | always, when a key exists |
| Tier 2 power | **adds findings** | **may raise the score, never lower it** |
| Tier 2 down | Tier 1 results stand, `tier_2_status: unavailable` | Tier 1 verdict stands, `heuristics_only: true` |

`final = max(tier1, tier1 × 0.80 + intent_penalty × 0.20)` is the whole of the M3 rule. Tier 1 is
arithmetic over facts — *this link's href does not match its anchor text* is checkable. Tier 2 is a
judgement about intent. **Judgements get upside-only influence over facts**, so a model that has been
talked into saying "benign" by the email it is reading cannot clear that email.

Module 4 has no LLM tier at all. An exact hash match against a known corpus is not a judgement call,
and adding a model to it would only add a way to be wrong.

**Why `services/site/brand.py` is imported by `services/phishing/`:** `sbi-verify-account.tk` is the
same lie whether it arrives as a URL bar or as an `href`. One brand table, one `registrable_domain`,
one definition of "not an official address" — so the extension badge and the email panel can never
disagree about the same domain.

---

## Request flows

**PII scan** (the hot path — runs while typing)

```
keystroke → debounce 250ms → skip if <input type=password>
  → check chrome.storage.local allowlist   ← no network if suppressed
  → POST /api/v1/pii/scan
      → Tier 1 regex + checksum            (always)
      → Tier 2 Gemini                       (only if uncertain AND available)
      → persist PiiEvent  (masked preview only)
      → recompute privacy sub-score
  → toast: [Mask] [Ignore] [Always allow here]
```

**Site check** (on navigation)

```
navigation → cache hit? → return (0 external calls)
  → miss: Safe Browsing ‖ RDAP ‖ brand-match   (concurrent, httpx async)
  → any signal missing → weight redistributed, verdict may be UNKNOWN
  → persist SiteCheck + reasons[] → cache 6h → badge colour
```

**Password check** (popup, Module 4) — note where the boundary sits

```
user types a password into the popup
  → SHA-1 computed IN THE BROWSER (crypto.subtle), field cleared immediately
  → GET /identity/pwned-range/{first 5 hex chars}      ← 5 chars is all that leaves
      → backend proxies HIBP with Add-Padding: true
      → ~2 000 suffixes back (1 978 measured for 5BAA6); padding rows dropped
  → THE MATCH HAPPENS LOCALLY. The server is never told which suffix matched.
  → POST /identity/password-check {prefix, count, label}
      → count corroborated against the same public range   (0.95 vs 0.75 confidence)
      → persist a CLASSIFICATION — never the password, never the full hash
      → recompute Identity sub-score (supersede by label, no time decay)
```

**Email analysis** (dashboard panel, Module 3)

```
paste → POST /phishing/analyze          ← NO db session in the handler signature
  → TIER 1, offline:  links 0.35 ‖ content 0.30 ‖ sender 0.15
        within a group: max + bump×(n−1), never a sum
        content needs two sides: request verb within 80 chars of credential noun
  → TIER 2, Gemini:   fenced <<<SENTINEL-{random hex}>>>, enum-constrained schema
        quotes verified as literal substrings; recommendation authored in Python
  → final = max(tier1, tier1×0.80 + intent×0.20)     ← may raise, never lower
  → return. NOTHING IS WRITTEN. (test_nothing_is_persisted proves it per-table.)
```

**Dashboard** — one `GET /dashboard/summary`, one round trip, all six widgets. Six endpoints would be
six loading states to design and six ways to look broken.

---

## Failure modes, and what the user sees

| Fails | Result | User sees |
|---|---|---|
| Gemini down / no key | Tier 1 only | Detection continues; banner "context analysis unavailable" |
| Safe Browsing keyless | 2 of 3 site signals | Verdict with reasons; `unknown` if too thin |
| RDAP 404 | age signal dropped | Reasons list omits domain age |
| HIBP unreachable | **no range returned** | `503` + "Your password was not checked." Never an empty range, which would read as "safe" |
| Gemini down during email analysis | Tier 1 verdict stands | `heuristics_only: true`, panel says the AI reading is missing — a `dangerous` verdict from links alone is still shown |
| Backend down | extension degrades | Toast: "SentinelAI offline" — never a silent failure |
| Network dead entirely | `ENABLE_GEMINI_TIER=false` | **Full Module 1 demo still runs offline**, and M3 Tier 1 still catches lookalike links |

That last row is the one that matters: the core demo moment survives hotel Wi-Fi.

---

## What is never stored, in one place

| Data | Where it lives | Where it does **not** |
|---|---|---|
| Typed text | Request memory, for the duration of the scan | Never persisted, never logged. Only a `masked_preview` is stored |
| Passwords | The popup input, until the button is clicked | Never transmitted. The field is cleared after hashing |
| Full SHA-1 hash | The popup, for the local match | Never transmitted. `POST /password-check` rejects a 40-char hash with `422` |
| Email bodies | Request memory | **No DB session exists in the handler.** Not stored, not logged |
| URL query strings | — | Stripped before the URL reaches Google Safe Browsing; reset tokens and OTPs live there |
| API keys | Server `.env` | Never in extension or dashboard code — both are readable by anyone |
