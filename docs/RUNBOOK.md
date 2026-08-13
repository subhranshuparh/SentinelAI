# SentinelAI — Runbook

**Deliverable 10 of 15.** How to run this on a clean machine, and what to do when it misbehaves.

Everything runs on `localhost`. There is no deploy step, no container, no daemon to supervise.

---

## 0. Prerequisites

| Need | Version used | Check |
|---|---|---|
| Python | 3.11.6 | `python --version` |
| Node.js | 22.17.1 | `node --version` |
| npm | 10.9.2 | `npm --version` |
| Chrome / Edge | any MV3-capable build | `chrome://version` |

Nothing else. No Postgres, no Redis, no Docker.

Commands below are **Git Bash on Windows**. On macOS/Linux the only difference is
`backend/.venv/bin/python` instead of `backend/.venv/Scripts/python.exe`.

---

## 1. First run, from a fresh clone

### 1.1 Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
cp .env.example .env
```

Now open `backend/.env` and fill in the two keys. **Both are optional** — see §3 for exactly what you
lose without each.

```bash
# From backend/, with the venv python:
.venv/Scripts/python.exe scripts/smoke_test_keys.py
```

This is the Phase-0 gate and it should be the first thing you run, not the last. A Safe Browsing key
that needs the API enabled in the Cloud console is a 30-minute fix now and a project-killer at hour 14.

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

Verify:

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","version":"0.1.0","tiers":{"regex":true,"gemini":true,"safe_browsing":true}}
```

`tiers` reports *capability*, never key values. Mid-demo this is the fastest way to discover that Tier 2
quietly stopped working.

### 1.2 Seed the demo history

```bash
# From backend/, server can stay running:
.venv/Scripts/python.exe -m app.db.seed
```

21 days of deterministic history (`RANDOM_SEED = 20260601`) for device `demo-device-sentinel-01`.
Re-running is a no-op; `--reset` rebuilds it.

**`--reset` deletes rows for that one seeded device and nothing else.** A seed script that truncates
tables is one fat finger away from destroying real captured events.

### 1.3 Dashboard

```bash
cd dashboard
npm install
npm run dev          # http://localhost:5173
```

### 1.4 Extension

1. `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select the `extension/` folder
4. Pin it to the toolbar so the badge is visible during a demo

No `npm install`, no build step. Edit a file, hit the reload icon on the card, see the change.

---

## 2. Daily start (everything already installed)

Three terminals, or three tabs:

```bash
# 1 — backend
cd backend && .venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000

# 2 — dashboard
cd dashboard && npm run dev

# 3 — test page (optional, for the typing demo)
cd extension && python -m http.server 8080
#   → http://localhost:8080/test/harness.html
```

Then reload the extension at `chrome://extensions` if the backend was restarted.

---

## 3. Running without keys

Both keys are optional, and the failure modes are *designed*, not incidental.

| Missing | What happens | What still works |
|---|---|---|
| `GEMINI_API_KEY` blank | `tier_2_status: "disabled"` — configuration, not failure. Email analysis returns `heuristics_only: true` and the panel says the AI reading is missing | All 14 regex detectors, checksums, masking, toast, dashboard, **every M3 Tier-1 signal** |
| `SAFE_BROWSING_API_KEY` blank | That signal reports `weight: "unknown"`; confidence drops | RDAP domain age, brand mismatch, verdicts, badge |
| *(no key exists)* | Pwned Passwords and RDAP are unauthenticated | Password check needs no configuration at all |
| **Both blank, network unplugged** | Offline mode | Tier 1 PII + brand-mismatch site checks + M3 link/sender/content signals + full dashboard |

To force offline mode deliberately (useful for rehearsing the "kill the Wi-Fi" moment):

```bash
ENABLE_GEMINI_TIER=false     # in backend/.env
```

Nothing renders green on missing information in any of these states. A signal that did not answer is
never counted as a signal that said "fine".

---

## 4. Tests

```bash
cd backend
.venv/Scripts/python.exe -m pytest tests -q
# 315 passed in ~40s
```

**No network, no server, no API keys required.** Gemini and Safe Browsing are stubbed. This matters
mid-build: you can keep the suite green while the extension is the thing that's broken.

Dashboard typecheck + production build:

```bash
cd dashboard
npm run build       # tsc -b && vite build
```

---

## 5. Troubleshooting

### The dashboard is blank / shows an error banner

Check the backend is up: `curl -s http://127.0.0.1:8000/health`.

If it is up, this is almost always CORS. `CORS_ALLOW_ORIGINS` must contain the **exact** origin in your
address bar. `http://localhost:5173` and `http://127.0.0.1:5173` are *different origins to a browser* —
both ship in the default config, but if you changed it, whichever one you typed is the one that must be
listed. (On Windows there's a second trap underneath: `localhost` resolves to `::1` before
`127.0.0.1`.)

### The dashboard says "No activity recorded yet"

That's the first-run state, not an error — a `404` from the summary endpoint, rendered with onboarding
copy and a neutral tone rather than a red alarm. It means the device has no events in the last 30 days.
Run the seed script (§1.2), or use the extension for a minute.

### Toast never appears while typing

In order of likelihood:

1. **Extension not reloaded** after a backend restart. `chrome://extensions` → reload icon.
2. **Field is a password field.** By design — `password`, `hidden`, `file`, `submit`, `button`,
   `checkbox`, `radio` are never read. A password must not enter a variable, let alone a request.
3. **Under 6 characters.** `MIN_SCAN_LENGTH` gate.
4. **Type suppressed on this origin.** You clicked *Always allow here* earlier. Open the popup — the
   allowlist section lists every muted `{origin, type}` pair with an **Unmute** button.
5. Open the page console — a content-script error shows there, not in the service-worker console.

### Site badge stays grey

Grey is `unknown`, and `unknown` is a real answer, not a bug. It means too little of the evidence
answered to offer a verdict (`available_weight < 0.31`). Check `/health` to see whether Safe Browsing is
armed.

If the badge never changes at all, open the **service worker** console: `chrome://extensions` → the
extension card → *Inspect views: service worker*. That's where network errors surface, not the page
console.

### `TypeError: Failed to fetch` in the page console

Something is calling `fetch()` from a content script. Under MV3 that is governed by the **host page's**
CORS policy, not the extension's. All network calls must go through `lib/bridge.js` →
`chrome.runtime.sendMessage` → service worker. Host permissions do not lift this for content scripts.

### Gemini returns 429 immediately, even on the first call

You are on `gemini-2.0-flash`. It has **zero free-tier quota** on AI Studio express keys — that 429 is
not rate limiting, it's an empty allocation, and it looks identical to going too fast. Set
`GEMINI_MODEL=gemini-2.5-flash`.

### Safe Browsing returns 400

You are sending an OAuth bearer token, most likely from a service-account JSON. Safe Browsing v4 only
accepts a **plain API key** (Cloud Console → Credentials → Create API key). No IAM role fixes this. The
successor Web Risk API does take OAuth — and also requires billing enabled, which is why the MVP is on
v4.

### RDAP returns nothing for a domain

Normal. Some ccTLDs 404; some registries throttle by IP. The contract holds: `domain_age_days: null`
means *RDAP had no answer* — not "old", and not "safe". The weight redistributes and confidence drops.

### Password check says "could not be checked"

The Pwned Passwords range API was unreachable. This is deliberately *loud*: the endpoint returns `503`,
not an empty range, because an empty range would render as "your password is safe" and telling a user
that because a CDN was down is the exact lie this codebase refuses everywhere else.

Verify the upstream directly:

```bash
curl -s -H 'Add-Padding: true' https://api.pwnedpasswords.com/range/5BAA6 | wc -l
# ~1000+ lines (padded). The unpadded real count for this prefix is 1978.
```

No API key exists for this service, so a `401`/`403` here means a proxy is intercepting, not a
configuration mistake.

### "Password check rejected my input"

`hash_prefix` is `max_length=5`. If you are calling the API by hand and sent a full 40-character SHA-1,
that `422` is the design working — the server refuses to be handed the one thing the whole feature
exists to keep from it. Send only the first five characters; the browser does this automatically.

### The Identity card still shows a dash after I checked a password

The dashboard resolves "the most recently active device" when no `X-Sentinel-Device-Id` header is sent.
The popup writes under the **extension's** device id, and the seeded demo history is under
`demo-device-sentinel-01`. If the seeded device is more recently active, you are looking at its
Identity score, which is `null`.

Pin the view to the device you just used:

```
http://localhost:5173  →  the app calls /api/v1/dashboard/summary
curl -s 'http://127.0.0.1:8000/api/v1/dashboard/summary?device_id=<your-extension-device-id>'
```

The extension's id is printed in the popup's devtools console, or read it from `chrome.storage.local`.

### Email analysis returns `heuristics_only: true`

The Gemini tier did not run. Three causes, in order: no `GEMINI_API_KEY`, `ENABLE_GEMINI_TIER=false`,
or the shared circuit breaker is open after two consecutive failures (it parks the tier for 60 s).
Check `/health`.

This is not a broken result. Every deterministic signal still ran, and a lookalike link or a
credential request still produces a `dangerous` verdict on its own — the panel simply says the AI
reading is missing rather than implying a complete check.

### An email I know is phishing scored low

Read the signal list before touching the weights. Two common, correct causes:

1. **No sender was pasted.** The sender group is 0.15 of the score and it is dropped from the
   denominator when absent, not scored as clean. Paste the `From:` line too.
2. **The email is pure social engineering with no link, no attachment, and no credential request** —
   a "hi, it's your CEO, are you at your desk?" opener. There is genuinely little for Tier 1 to
   measure; the Gemini intent tier is what catches these, and it can raise the score to at most
   `tier1 × 0.80 + 95 × 0.20`. That ceiling is intentional: the alternative is letting a model's
   opinion alone produce a `dangerous` verdict.

### The trend chart has one point

Snapshots are written at most once per 5 minutes (`SNAPSHOT_MIN_INTERVAL_MINUTES`), so a dashboard
polling every 10 seconds can't flood it. For a full 21-day chart, run the seed script.

### Score changed and I want to know why

`GET /api/v1/dashboard/summary` returns `contributions[]`, and the published points sum to the headline
by construction (half-up rounding, swept by a test). Read them and the arithmetic is right there. The
underlying function is pure — `services/risk/engine.py` `compute()` has no FastAPI, no DB session, no
HTTP in scope, so you can call it directly from a REPL.

---

## 6. Reset to a clean state

```bash
# Nuke the database entirely — it is one file
rm backend/sentinel.db
cd backend && .venv/Scripts/python.exe -m app.db.seed

# Clear the site-verdict cache: it is in-process, so just restart uvicorn

# Clear extension state (device id, allowlist):
#   Individual mutes:  popup → allowlist section → Unmute
#   Everything:        chrome://extensions → Remove → Load unpacked again
#                      (this drops chrome.storage.local, so a NEW device id is
#                       generated — the dashboard will show the seeded device
#                       instead until the new one records an event)
```

---

## 7. Ports

| Port | Service | Notes |
|---|---|---|
| 8000 | FastAPI backend | Hardcoded in `extension/lib/api.js`; change both if you move it |
| 5173 | Vite dashboard | Must match `CORS_ALLOW_ORIGINS` |
| 8080 | `python -m http.server` for the test harness | Optional |

---

## 8. Deployment notes (not done, stated honestly)

The demo runs on localhost by design — the roadmap's rule is *"the demo runs on localhost, deployment
is a slide."* If this were deployed:

1. **HTTPS is mandatory before anything else.** The request bodies are exactly the sensitive strings the
   product exists to protect. Terminate TLS at the proxy, set `Strict-Transport-Security`, switch the
   extension base URL to `https://`. No application code changes.
2. `DATABASE_URL` → a `postgresql://` DSN. Add `psycopg`. That is the whole migration.
3. Rate limiting moves to Redis behind the same `check()` signature — in-memory buckets are per-process
   and wrong across workers.
4. `ENABLE_JWT_AUTH=true` and issue real tokens. The verification path is already written and
   flag-gated; `get_current_device` and `get_optional_device` both fail closed when the flag is on.
5. CORS gets the real dashboard origin. Never `*` — this backend receives text typed into a user's bank.
6. **The k-anonymity guarantee is transport-dependent.** Over plain HTTP, an observer sees the 5-char
   prefix in the URL path — still a crowd of ~2,000, so the design holds, but TLS is what keeps it from
   being correlated with everything else that session. This is one more reason item 1 is item 1.
7. Nothing in the deploy changes what is stored. There is still no password column, no email-body
   column, and no DB session in the phishing handler.
