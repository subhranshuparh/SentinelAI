# SentinelAI — Folder Structure

**Deliverable 2 of 15.** Three deployables in one repo, no build tooling shared between them.

```
SentinelAI/
│
├── README.md                      # Deliverable 13 — the front door
├── run.sh                         # One command for all three services. Waits on /health before
│                                  #   opening anything, then launches Chrome by PATH — the chrome:
│                                  #   scheme has no protocol handler, so only the binary itself can
│                                  #   reach chrome://extensions, which is where the one unscriptable
│                                  #   step lives. Stops by PORT rather than by PID: uvicorn and vite
│                                  #   both fork, so killing the wrapper orphans the real server and
│                                  #   it keeps answering the next run with stale code.
│                                  #   --setup / --seed / --stop / --no-open.
│
├── .logs/                         # gitignored. run.sh sends each service's stdout here so one
│                                  #   crash does not scroll away under the other two. Also holds
│                                  #   .extension-loaded-once, the marker that stops the
│                                  #   chrome://extensions tab reopening on every single run.
│
├── .vscode/                       # Not required to run — it just removes the setup friction
│   ├── settings.json              # Interpreter + pytest cwd. Without it Pylance red-underlines
│   │                              #   every `app.*` import while the code runs perfectly.
│   ├── tasks.json                 # "▶ Run everything" = backend + dashboard + harness, 3 terminals
│   ├── launch.json                # Debug configs. uvicorn WITHOUT --reload — the reloader forks and
│   │                              #   breakpoints attach to the parent, so they silently never fire.
│   └── extensions.json            # Python, Pylance, Ruff, ESLint, Tailwind, REST Client
│
├── docs/                          # The written deliverables live here
│   ├── ROADMAP.md                 # Deliverable 1
│   ├── FOLDER_STRUCTURE.md        # Deliverable 2  (this file)
│   ├── DATABASE_SCHEMA.md         # Deliverable 3
│   ├── ARCHITECTURE.md            # Deliverable 4
│   ├── API.md                     # Deliverable 5
│   ├── INTEGRATION_NOTES.md       # Deliverable 9  (rate limits, quotas, caching)
│   ├── RUNBOOK.md                 # Deliverable 10 (local run instructions)
│   ├── DEMO_SCRIPT.md             # Deliverable 11
│   ├── PITCH.md                   # Deliverable 12
│   ├── RUN_IN_VSCODE.md           # Deliverable 14 — open it, run it, see it work
│   └── FEATURES.md                # Deliverable 15 — every feature: problem, benefit, build
│
├── backend/                       # FastAPI — single service, modular routers
│   ├── app/
│   │   ├── main.py                # App factory, CORS, rate limiter, router mounting
│   │   │
│   │   ├── core/                  # Cross-cutting concerns. No business logic.
│   │   │   ├── config.py          # Pydantic Settings — every env var declared & typed
│   │   │   ├── security.py        # Device-id dependency + JWT path (flag-gated)
│   │   │   ├── cache.py           # TTLCache — same get/set interface as Redis
│   │   │   └── ratelimit.py       # Per-device token bucket
│   │   │
│   │   ├── db/
│   │   │   ├── session.py         # SQLAlchemy engine + get_db dependency
│   │   │   ├── models.py          # ORM tables (Deliverable 3)
│   │   │   └── seed.py            # Populates demo history — Phase 7 insurance
│   │   │
│   │   ├── schemas/               # Pydantic request/response contracts
│   │   │   ├── pii.py             # `reason` + `confidence` REQUIRED, not Optional
│   │   │   ├── site.py
│   │   │   ├── identity.py        # M4 — hash_prefix is max_length=5, by design
│   │   │   ├── phishing.py        # M3 — risk_score direction stated in the field doc
│   │   │   └── dashboard.py
│   │   │
│   │   ├── services/              # ★ All business logic. Zero FastAPI imports here.
│   │   │   ├── pii/
│   │   │   │   ├── detectors.py   # 14 regex detectors — pure functions
│   │   │   │   ├── checksums.py   # Luhn (cards) + Verhoeff (Aadhaar)
│   │   │   │   ├── masking.py     # Format-preserving redaction
│   │   │   │   └── engine.py      # Tier-1 regex → Tier-2 Gemini orchestration
│   │   │   ├── site/
│   │   │   │   ├── safebrowsing.py
│   │   │   │   ├── rdap.py        # Domain age. Unknown ≠ safe.
│   │   │   │   ├── brand.py       # Brand-token vs. domain mismatch  ← reused by phishing/
│   │   │   │   └── engine.py
│   │   │   ├── identity/          # M4 — no LLM here; a hash match is not a judgement
│   │   │   │   ├── pwned.py       # HIBP range + count corroboration. 5 chars out.
│   │   │   │   └── engine.py      # Prevalence bands, supersede-by-label, no decay
│   │   │   ├── phishing/          # M3
│   │   │   │   ├── heuristics.py  # Tier 1: links · sender · content. Offline, $0.
│   │   │   │   └── engine.py      # Weighted groups + "Tier 2 may raise, never lower"
│   │   │   ├── llm/
│   │   │   │   ├── gemini.py      # Client + timeout + fail-open + shared breaker
│   │   │   │   ├── prompts.py     # Delimited-block templates (injection defence)
│   │   │   │   └── phishing_prompts.py  # Random per-request fence + enum'd schema
│   │   │   └── risk/
│   │   │       └── engine.py      # Weighted aggregation → unified score
│   │   │
│   │   └── routers/               # ★ Thin. Validate → call service → return.
│   │       ├── pii.py
│   │       ├── site.py
│   │       ├── identity.py
│   │       ├── phishing.py        # ★ Takes NO db session. Storing an email is impossible.
│   │       └── dashboard.py
│   │
│   ├── scripts/
│   │   └── smoke_test_keys.py     # Phase 0 gate — run this FIRST
│   ├── tests/                     # 315 tests, no network, ~40s
│   │   ├── conftest.py            # Isolated DB per test run
│   │   ├── test_checksums.py      # Luhn + Verhoeff. Offline, <1s
│   │   ├── test_detectors.py      # Weighted toward false positives
│   │   ├── test_api_pii.py        # Endpoint contract via TestClient
│   │   ├── test_tier2.py          # Injection defence + fail-open, Gemini stubbed
│   │   ├── test_site.py           # False positives + missing-signal honesty
│   │   ├── test_identity.py       # k-anonymity, padding, supersession, 503-not-[]
│   │   ├── test_phishing.py       # Tier-2 can't lower; 5-layer injection defence;
│   │   │                          #   test_nothing_is_persisted enumerates every table
│   │   └── test_risk_engine.py    # Decay, rounding, redistribution + endpoint
│   ├── requirements.txt
│   ├── .env.example               # Committed
│   └── .env                       # NEVER committed
│
├── extension/                     # Chrome MV3 — plain JS, no build step
│   ├── manifest.json
│   ├── background.js              # Service worker: navigation → site check → badge,
│   │                              #   plus the only place fetch() is ever called
│   ├── content/
│   │   ├── content.js             # Field capture, debounce, mask write-back
│   │   ├── toast.js               # Non-blocking notification UI
│   │   └── toast.css              # Shadow-DOM scoped
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.js
│   │   └── popup.css
│   ├── lib/
│   │   ├── api.js                 # Backend client — service worker + popup only
│   │   ├── bridge.js              # Content-script shim: same API, routed via messages
│   │   └── allowlist.js           # Per-site false-positive overrides
│   ├── test/
│   │   └── harness.html           # Local field playground + demo fallback
│   └── icons/
│       └── generate_icons.py      # Regenerates the PNGs; no Pillow dependency
│
└── dashboard/                     # Vite + React + TS + Tailwind 3 + Recharts
    ├── index.html                 # Paints #0b0f16 before React boots — no white flash
    ├── tailwind.config.js
    ├── postcss.config.js
    └── src/
        ├── main.tsx
        ├── index.css              # Tailwind layers + one scrollbar override
        ├── App.tsx                # Fetch, 10s poll, loading/empty/error orchestration
        ├── theme.ts               # Risk band → colour. One file owns "what red means".
        ├── types.ts               # Mirrors backend Pydantic schemas, by hand
        ├── api/client.ts          # Single fetch wrapper + typed ApiError
        └── components/
            ├── ScoreHero.tsx      # Unified score
            ├── ScoreBreakdown.tsx # Privacy / Identity / Browsing + redistribution note
            ├── RiskTrendChart.tsx # Recharts
            ├── ThreatTimeline.tsx
            ├── FlaggedSites.tsx
            ├── Recommendations.tsx
            ├── EmailChecker.tsx   # M3 paste-and-analyze — the only interactive panel
            └── states/index.tsx   # Loading / Empty / Error — reused everywhere
```

---

## Why this shape

### `services/` holds every decision; `routers/` holds none

A router is: validate input → call one service function → return the model. If a router contains an
`if`, the logic is in the wrong file.

**Concrete payoff at hour 20, half-asleep:** "why did this score come out 34?" is answered by reading
one pure function in `services/risk/engine.py` with no FastAPI, no DB session, no HTTP in scope. When
the demo misbehaves, you debug a function, not a request lifecycle.

**Second payoff:** `tests/` imports `services/` directly. `test_checksums.py` runs in under a second
with no server and no network — so you can keep running it during Phase 2 when the extension is the
thing that's broken.

### Detectors are pure functions, not a class hierarchy

`detect_aadhaar(text) -> list[Finding]`. No state, no config, no inheritance. Adding a 15th PII type is
one function plus one registry entry, and it cannot break the other 14. At hour 18 you want additive
changes only.

### The extension has no build step

No webpack, no bundler, no npm install in `extension/`. `chrome://extensions → Load unpacked` and it
runs; edit a file, hit reload, see the change. A build pipeline here costs 45 minutes of setup and buys
you nothing that matters in 24 hours — and a broken bundler config at hour 19 is unrecoverable.

### Only the service worker touches the network

`lib/api.js` is loaded by the service worker and the popup. Content scripts get `lib/bridge.js`
instead, which presents the identical surface but forwards each call over `chrome.runtime.sendMessage`.

This is not stylistic. Under MV3 a content script's `fetch()` is governed by the **host page's** CORS
policy, not the extension's — so a scan fired from `mail.google.com` to `127.0.0.1:8000` is blocked,
and the failure arrives as a bare `TypeError` with nothing useful in it. Host permissions do not lift
that for content scripts; they only apply to extension-origin contexts.

Two things fall out of it for free: the backend URL exists in exactly one file, and the service worker
can reject messages that did not come from a real tab — so another extension that guesses this one's
id cannot use it as an open proxy to the local backend.

Cost of this choice, stated honestly: no TypeScript in the extension, no npm packages. Both acceptable
— the content script is ~250 lines of DOM work.

### `theme.ts` owns what red means

Risk-band colours are defined once and imported by the hero, the breakdown, the chart, and the
timeline. The alternative — a Tailwind class inline in each component — is how a score of 62 ends up
amber in one widget and red in another on the same screen. The roadmap's rule that *red is reserved for
genuinely high risk only* has to live somewhere enforceable, and this is that place.

`components/states/` ships as a single `index.tsx` rather than three files. Loading, empty, and error
are ~30 lines each and are always considered together — an empty state that doesn't visually rhyme with
its error state is the actual failure mode here.

### `dashboard/src/types.ts` mirrors the backend by hand

No codegen, no OpenAPI client generator. One file, ~40 lines, copied from the Pydantic schemas. Codegen
is correct at 3 months and a time sink at 24 hours.

### `core/cache.py` deliberately imitates Redis

`get(key)` / `set(key, value, ttl)`. When someone asks "why not Redis?", the answer is a file you can
open: *the interface is Redis's, the backend is a dict, swapping is an import change.* Same argument as
`config.py` holding `DATABASE_URL` — the Postgres migration is a string.

### `db/seed.py` exists from day one

An empty dashboard is a broken-looking dashboard. This script is what makes the Phase 5 screen
presentable at Phase 7, and having it early means you develop against realistic data instead of
building charts that only ever render one point.

---

## Convention rules

| Rule | Reason |
|---|---|
| `services/` never imports from `routers/` or `fastapi` | Keeps logic testable and framework-free |
| Every AI/detection response carries `confidence` + `reason` | Explainability enforced by schema, per spec |
| No raw PII in DB or logs — classification + masked preview only | Spec security requirement, non-negotiable |
| Secrets only in `backend/.env` | Extension code is public to anyone who opens DevTools |
| `chrome.storage.local` for allowlist, never the backend | Per-site overrides are private and offline |
| Passwords are hashed in the browser; only 5 hex chars leave it | k-anonymity is the feature, not an optimisation. The DB column is `VARCHAR(5)` so a full hash physically will not fit |
| A handler that must not persist takes no `db` session | `routers/phishing.py`. A guarantee enforced by the signature beats one enforced by review |
| A signal that did not answer is never counted as one that said "fine" | `None` = *not checked*; `[]`/`0` = *checked, nothing found*. The single rule behind `verdict: unknown`, `identity_score: null`, `domain_age_days: null`, and `heuristics_only` |
