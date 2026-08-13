# Running SentinelAI in VS Code

**Deliverable 14 of 15.** Open the folder, press two buttons, watch it work.

This is the *"I have the repo and VS Code, now what"* guide. It assumes nothing. If you want the
terminal-only version, or the troubleshooting encyclopedia, that's [RUNBOOK.md](RUNBOOK.md). If you
want to know what each feature does and why, that's [FEATURES.md](FEATURES.md).

---

## 0. What you need first

| Need | Version this was built on | How to check |
|---|---|---|
| **VS Code** | any current build | — |
| **Python** | 3.11.6 | `python --version` |
| **Node.js** | 22.17.1 | `node --version` |
| **Chrome or Edge** | any MV3-capable build | `chrome://version` |

There is **no Postgres, no Redis, no Docker, no cloud account**. The database is one file called
`sentinel.db` that gets created on first run.

> **Windows note.** Everything below uses `backend/.venv/Scripts/python.exe`. On macOS or Linux the
> only difference anywhere in this project is `backend/.venv/bin/python`. That is the entire
> cross-platform delta.

---

## 1. Open the project

```
File → Open Folder… → select the SentinelAI folder
```

Open the folder that contains `backend/`, `dashboard/`, `extension/` and `docs/` — **not** one of
those subfolders. The `.vscode/` config in this repo assumes the workspace root is the project root,
and the Python import paths break if you open `backend/` on its own.

VS Code will show a popup: *"This workspace has extension recommendations."* Click **Install All**.
It's a short list, defined in [`.vscode/extensions.json`](../.vscode/extensions.json):

| Extension | Why |
|---|---|
| Python + Pylance + debugpy | run and debug the backend, resolve `app.*` imports |
| Ruff | the linter this codebase is formatted for |
| ESLint | the dashboard's linter |
| Tailwind CSS IntelliSense | class-name autocomplete in the dashboard |
| REST Client | lets you fire API requests from a `.http` file without leaving the editor |

---

## 2. One-time setup (about three minutes)

Press `Ctrl+Shift+P` → type **Tasks: Run Task** → pick each of these **in order**:

### `Setup · install backend deps`

Creates `backend/.venv` and installs FastAPI, SQLAlchemy, httpx and pytest. Wait for it to finish
before the next step.

### Create your `.env`

In the VS Code Explorer, open `backend/`, copy `.env.example`, and rename the copy to `.env`.
(Or in a terminal: `` cp backend/.env.example backend/.env ``.)

**Both API keys are optional.** The project runs without either — see §6 for exactly what changes.
If you do have them, fill in:

```ini
GEMINI_API_KEY=...            # AI Studio. Use gemini-2.5-flash, NOT 2.0-flash — see RUNBOOK §5
SAFE_BROWSING_API_KEY=...     # Cloud Console → Credentials → API key. A plain key, not a service account
```

> `.env` is gitignored. **No key ever goes in `extension/` or `dashboard/`** — both of those are
> readable by anyone with DevTools open. Every keyed call happens server-side.

### `Setup · check API keys (Phase-0 gate)`

This runs `backend/scripts/smoke_test_keys.py`. **Run it now, not later.** A Safe Browsing key that
needs its API enabled in the Cloud console is a thirty-minute fix today and a project-killer the
night before a demo. It prints a per-key verdict and never prints the keys themselves.

### `Setup · install dashboard deps`

`npm install` in `dashboard/`. This is the slowest step.

### `Seed 21 days of demo history`

Writes deterministic history (`RANDOM_SEED = 20260601`) for device `demo-device-sentinel-01`, so the
dashboard has a trend line and a timeline on first open instead of an empty state.

> **`--reset` only deletes rows for that one seeded device.** A seed script that truncates tables is
> one fat finger away from destroying real captured events, so this one doesn't have that power.

### Select the interpreter

`Ctrl+Shift+P` → **Python: Select Interpreter** → choose the one ending in
`backend\.venv\Scripts\python.exe`.

If you skip this, Pylance red-underlines every `from app.…` import while the code runs perfectly.
That's the single most common false alarm on this repo — it's an editor setting, not a broken build.

---

## 3. Run it

`Ctrl+Shift+P` → **Tasks: Run Task** → **`▶ Run everything`**

That starts three dedicated terminals at once:

| Terminal | What | Where |
|---|---|---|
| `1 · Backend` | FastAPI + uvicorn, auto-reloads on save | http://127.0.0.1:8000 |
| `2 · Dashboard` | Vite dev server, hot-reloads on save | http://localhost:5173 |
| `3 · Test harness` | a plain HTML page with text fields, for the typing demo | http://localhost:8080/test/harness.html |

You can also run them individually — the tasks are numbered `1 ·`, `2 ·`, `3 ·` in the picker.

### Or one command in the integrated terminal

If you'd rather stay in a terminal (`Ctrl+` `` ` ``) than use the task picker:

```bash
./run.sh
```

Same three services, one process. It also does two things the tasks can't.

It **polls `/health` and refuses to open anything until the backend actually answers**, so you never
refresh a dead page and conclude the project is broken. And then it **opens the pages in Chrome for
you** — dashboard, typing-test page, and on the very first run `chrome://extensions`, since loading the
extension is the one step that cannot be scripted. That tab appears once and never again: the marker
lives at `.logs/.extension-loaded-once`, so a fresh clone gets the prompt and your machine stops being
nagged about a step you already did. `Ctrl+C` stops all three.

Chrome is launched **by path**, not through the OS "open" handler, for one specific reason: the
`chrome:` scheme has no registered protocol handler, so `start chrome://extensions` silently fails. Only
the binary itself can navigate there — and that page is exactly where the manual step lives. If no
Chrome or Edge is found, the script falls back to `open` / `xdg-open` / `start` and, failing all of
those, just prints the links.

| | |
|---|---|
| `./run.sh` | start everything |
| `./run.sh --setup` | create the venv, install backend + dashboard deps, then start. Use on a fresh clone — replaces all of §2 except the `.env` keys |
| `./run.sh --seed` | re-seed 21 days of demo history from scratch, then start. **Run this right before a demo** |
| `./run.sh --stop` | stop everything, including servers orphaned by a previous run |
| `./run.sh --no-open` | start without launching a browser — for headless or CI use |

Shutdown is defined by **port, not process ID**, and that is deliberate: `uvicorn --reload` and
`npm run dev` both fork, so the process the script launched is a wrapper whose real server is a
grandchild in another tree. Kill the wrapper abruptly — close the terminal, kill the tab — and the
grandchild keeps the port bound. It then answers the *next* run with stale code, which presents as the
genuinely baffling "I fixed it and nothing changed". `--stop` finds whoever holds 8000/5173/8080 and
terminates that tree, so it's also the fix for `[Errno 10048] address already in use`.

> **Why `--stop` exists at all, given `Ctrl+C`.** Git Bash emulates POSIX signals over Win32, and the
> emulation is not dependable for a background script. Measured on this repo: `timeout` delivering
> `TERM` ran the cleanup trap, while `kill -TERM` on the same script ran **nothing** and left all three
> ports held. Interactive `Ctrl+C` is the well-behaved case — `SIGINT` reaches every member of the
> foreground process group, so the servers exit on their own whether or not the trap fires. Rather than
> depend on which case you are in, **startup clears the ports before binding**, so a leftover server can
> never break the next run. `--stop` is the explicit version of the same function.

### Confirm the backend is alive

Open http://127.0.0.1:8000/health in a browser. You want:

```json
{"status":"ok","version":"0.1.0","tiers":{"regex":true,"gemini":true,"safe_browsing":true}}
```

`tiers` reports **capability, never key values**. Mid-demo this is the fastest way to discover that
the AI tier quietly stopped working. `false` is not an error — it means that tier is unconfigured, and
§6 says what you lose.

Interactive API docs, generated from the Pydantic models: **http://127.0.0.1:8000/docs**

### Load the extension

1. Go to `chrome://extensions`
2. Turn on **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. **Pin it to the toolbar** so you can see the badge

There is no build step for the extension — no npm, no bundler, no compile. Edit a file, click the
reload icon on the extension card, see the change. That was a deliberate choice: a build step between
you and a demo fix is a liability at 2 a.m.

---

## 4. See it work — five things, about four minutes

### ① PII caught while you type

Open **http://localhost:8080/test/harness.html** and type this into the big text box:

```
My Aadhaar is 2345 6789 9014
```

A calm toast slides in from the corner: *"Aadhaar number detected"*, with a **Mask it** button that
rewrites the field to `XXXX XXXX 9014`.

> **Use that exact number.** It's Verhoeff-valid. An arbitrary twelve digits like `2234 5678 9013`
> fails the checksum and produces **no alert at all** — which is the feature working, not a bug. A
> privacy tool that flags your order number gets uninstalled in ten minutes.

Now try these to see the shape of the thing:

| Type this | What happens | Why |
|---|---|---|
| `4242 4242 4242 4242` | flagged, `XXXX XXXX XXXX 4242` | passes the Luhn checksum |
| `1234 5678 9012 3456` | **nothing** | fails Luhn — not a real card number |
| `hi` | **nothing** | under the 6-character minimum, and zero AI calls are made |
| a password field | **nothing, ever** | `password`, `hidden`, `file` + 4 more input types are refused *before* capture |

### ② A site that's impersonating a brand

Click the SentinelAI toolbar icon while on any page — the popup shows that site's verdict. To see a
bad one without visiting anything sketchy, use the API docs at http://127.0.0.1:8000/docs →
`POST /api/v1/site/check` → **Try it out** → body:

```json
{ "url": "https://amazon-login-security.xyz/verify" }
```

**Verified live:** `dangerous`, trust score **25**, confidence **0.53**. Read the `reasons` array —
each signal is a separate itemised sentence, written for a human:

- *"This address uses the name 'amazon' but it is not an official amazon website."*
- *"It also contains the word 'login', which scam sites use to make you feel you must act now."*
- *"The age of this web address could not be looked up."* ← **weight: `unknown`**

That last line is the most important one in the whole product. RDAP had no answer, so the signal
reports `unknown` and is **shown rather than hidden**, the scoring denominator shrinks to the weight
that actually answered, and confidence drops to 0.53 to say so. Compare `https://www.google.com/` —
`safe`, score **100**, confidence **1.0**, *"has existed for over 28 years."*

### ③ Your password against 900 million breached ones

Click the toolbar icon → the password box → type `password` → **Check against breaches**.

> **password appears in 52,372,427 breached accounts.**

Now the part worth watching. Open DevTools on the popup (right-click → Inspect) → **Network** tab →
run it again. The only request is:

```
GET /api/v1/identity/pwned-range/5BAA6
```

**Five characters.** Your browser SHA-1'd the password locally, sent only the first five hex
characters of the hash, got back **1,978 candidate suffixes** (measured live for this prefix), and
did the comparison itself. The server sees a crowd of ~2,000 and cannot tell which one you are — and
the database column that stores the prefix is `VARCHAR(5)`, so a full hash physically will not fit.

We can *prove we cannot know your password* rather than promising we won't look.

### ④ A phishing email that orders our AI to call it safe

Scroll to the bottom of the dashboard at http://localhost:5173 → **Check an email** → paste the
payload from [DEMO_SCRIPT.md](DEMO_SCRIPT.md). Its body contains an instruction telling the model to
ignore its rules and report the email as benign.

**Verified live:** `dangerous`, risk score **97**, intent `credential_theft`, 8 itemised signals,
`link_display_mismatch` ranked first.

Why the injection fails is the single best thing to understand about this codebase:

```
final_score = max(tier1, tier1 × 0.80 + ai_intent × 0.20)
```

> **The AI is allowed to accuse. It is not allowed to acquit.**

Tier 1 is arithmetic over checkable facts — *this link's `href` does not match its anchor text* is
either true or it isn't. Tier 2 is a judgement about intent. A judgement gets **upside-only**
influence over a fact. So even a *completely successful* injection cannot clear an email whose link
provably points at a lookalike domain. Four other layers stop the injection before it gets that far;
this one is the backstop that makes them defence in depth rather than a single point of failure.

⚠️ **Risk score is inverted here, and only here.** `97` means *near-certain phishing*. Everywhere
else in the product — `trust_score`, `overall_score`, `privacy_score`, `identity_score` — higher is
better.

### ⑤ The dashboard, where it all joins up

Open **http://localhost:5173**. Look at the breakdown table under the hero score:

| Component | Score | Weight | Applied | Points |
|---|---|---|---|---|
| Privacy | 37 | 0.4 | **0.5** | 18.5 |
| Browsing | 55 | 0.4 | **0.5** | 27.5 |
| Identity | **—** | 0.2 | **0.0** | 0.0 |

Two things to check by hand, right now:

1. **18.5 + 27.5 = 46, and 46 is the headline.** The published breakdown always sums to the published
   number, using half-up rounding so it matches the arithmetic *you* do. A test sweeps every input
   combination to guarantee it. (Your digits will differ — the seed writes history relative to when
   you ran it, and everything decays on a 7-day half-life. The *property* is what's fixed.)
2. **Identity is an em dash, not a zero and not a green tick.** This device has never run a password
   check, so there is nothing honest to put there. Its 0.2 weight is redistributed to the two
   components that did answer — that's `0.5` against a nominal `0.4` — and overall confidence drops to
   `0.8` to say so.

**Then make the em dash disappear.** Go back to the popup, check a password, reload the dashboard.
Identity becomes a real number, `weight_applied` snaps back to `0.4 / 0.4 / 0.2`, and confidence
returns to `1.0`. The redistribution was never a placeholder for a missing feature — it's what the
engine does whenever a component has nothing to say, and it undoes itself the moment that component
speaks.

---

## 5. Run the tests

`Ctrl+Shift+P` → **Tasks: Run Task** → **`Tests · backend (315, offline)`**

```
315 passed in ~41s
```

Or use the **Testing** sidebar (the flask icon) to run and debug individual tests — `.vscode/settings.json`
already points it at `backend/` with the right interpreter.

**No network, no running server, no API keys.** Gemini and Safe Browsing are stubbed, so the suite
stays green on dead Wi-Fi — which is exactly when you most need to know whether your code is the
problem.

Dashboard typecheck + production build: **`Build · dashboard (tsc + vite)`** → `✓ built in ~1.2s`.

### Debugging

`F5` → **Debug backend (uvicorn, no reload)**. Set a breakpoint anywhere in `backend/app/`.

> `--reload` is deliberately absent from that launch config. The reloader runs your app in a *child*
> process while the debugger attaches to the parent, so breakpoints silently never fire and you spend
> twenty minutes doubting your own code.

---

## 6. Running with no API keys at all

Both keys are optional, and every degraded state is **designed**, not incidental:

| Missing | What happens | What still works |
|---|---|---|
| `GEMINI_API_KEY` | `tier_2_status: "disabled"` — *configuration*, not failure. Email analysis returns `heuristics_only: true` and the panel says the AI reading is missing | All 14 regex detectors, both checksums, masking, toasts, the whole dashboard, **every phishing Tier-1 signal** |
| `SAFE_BROWSING_API_KEY` | That one signal reports `weight: "unknown"` and confidence drops | RDAP domain age, brand-impersonation detection, verdicts, badge |
| *(neither exists)* | Pwned Passwords and RDAP are unauthenticated APIs | The password check needs **no configuration at all** |
| **Both blank, Wi-Fi unplugged** | Full offline mode | Tier-1 PII + brand-mismatch site checks + all phishing link/sender/content signals + the entire dashboard |

To rehearse the "kill the Wi-Fi" moment deliberately, set `ENABLE_GEMINI_TIER=false` in `backend/.env`.

**Nothing renders green on missing information in any of these states.** A signal that did not answer
is never counted as a signal that said "fine" — and the corollary is one-sided on purpose: thin
evidence blocks a clean bill of health, but it never suppresses a warning. Unplug everything and a
brand-impersonation domain still reads `dangerous`.

---

## 7. When something's wrong

| Symptom | Cause, in order of likelihood |
|---|---|
| Red squiggles under `from app.…` | Interpreter not selected. §2, last step. The code runs fine. |
| `[Errno 10048] address already in use` (or `EADDRINUSE`) | A server from a previous run still holds the port. `./run.sh --stop`. |
| You changed backend code and the change had no effect | Same cause as above — an orphaned server on 8000 is answering with the code it started with. `--reload` can't help you if the process you're talking to isn't the one you restarted. `./run.sh --stop`, then start again. |
| Dashboard unreachable on `127.0.0.1:5173` but fine on `localhost:5173` | Not a bug. Vite binds IPv6 loopback (`[::1]`) only. Use `localhost`. |
| Dashboard is blank or shows an error banner | Backend down (`/health`), or CORS. `CORS_ALLOW_ORIGINS` needs the **exact** origin in your address bar — `localhost:5173` and `127.0.0.1:5173` are *different origins* to a browser. |
| Dashboard says "No activity recorded yet" | Not an error — it's the first-run state. Run the seed task. |
| Toast never appears | Extension not reloaded after a backend restart · it's a password field (by design) · under 6 characters · you clicked *Always allow here* earlier (the popup lists every mute with an **Unmute** button) |
| Site badge stays grey | Grey is `unknown`, and `unknown` is a real answer. Too little evidence answered to offer a verdict. |
| `TypeError: Failed to fetch` in the page console | Something is calling `fetch()` from a content script. Under MV3 that obeys the **host page's** CORS policy, not the extension's. All network calls go through `lib/bridge.js` → the service worker. |
| Gemini 429 on the very first call | You're on `gemini-2.0-flash`, which has **zero** free-tier quota on AI Studio keys. Set `GEMINI_MODEL=gemini-2.5-flash`. |
| Safe Browsing returns 400 | You're sending an OAuth token from a service-account JSON. v4 accepts a **plain API key** only. No IAM role fixes this. |
| Password check returns 503 | Pwned Passwords was unreachable. This is deliberately loud — an empty range would render as *"your password is safe"*, and telling a user that because a CDN was down is the exact lie this codebase refuses everywhere else. |
| `422` on a password check you wrote by hand | `hash_prefix` is `max_length=5`. You sent a full 40-char SHA-1. That rejection is the design working — the server refuses to be handed the one thing the feature exists to keep from it. |
| Identity card still shows a dash after checking a password | The dashboard resolves *the most recently active device* when no device header is sent. The popup writes under the **extension's** device id; the seeded history is under `demo-device-sentinel-01`. |

The full version of this table, with the reasoning behind each answer, is
[RUNBOOK.md §5](RUNBOOK.md).

### Start completely over

```bash
rm backend/sentinel.db                  # the database is one file
# then run the "Seed 21 days of demo history" task again
```

Extension state (device id, per-site mutes) lives in `chrome.storage.local`: remove and re-load the
unpacked extension to clear it.

---

## 8. Where to look in the code

| You want to understand | Open |
|---|---|
| How PII is detected | [`backend/app/services/pii/detectors.py`](../backend/app/services/pii/detectors.py) — 14 pure functions, no I/O |
| Why `2345 6789 9014` passes and `2234 5678 9013` doesn't | [`backend/app/services/pii/checksums.py`](../backend/app/services/pii/checksums.py) — Luhn and Verhoeff, ~15 lines each |
| How a site verdict is scored | [`backend/app/services/site/engine.py`](../backend/app/services/site/engine.py) — the "weight that answered" denominator |
| The k-anonymity password check | [`backend/app/services/identity/pwned.py`](../backend/app/services/identity/pwned.py) |
| Why the phishing AI can't acquit | [`backend/app/services/phishing/engine.py`](../backend/app/services/phishing/engine.py) — search for `max(` |
| The unified score | [`backend/app/services/risk/engine.py`](../backend/app/services/risk/engine.py) — `compute()` is a **pure function**, callable from a REPL |
| What the extension does per keystroke | [`extension/content/`](../extension/content/) and [`extension/lib/bridge.js`](../extension/lib/bridge.js) |
| The dashboard | [`dashboard/src/components/`](../dashboard/src/components/) |

**Everything each feature does, why it exists, and how it was built:** [FEATURES.md](FEATURES.md).
