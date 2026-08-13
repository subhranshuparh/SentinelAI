# SentinelAI — Scoped Build Roadmap

**Deliverable 1 of 15** · Constraints: **solo developer**, **24–36 hours**, keys in hand: Gemini + Google Safe Browsing.

---

## 0. The honest scope verdict

The full spec describes 7 modules, 5 external APIs, PostgreSQL + Redis + Celery + a vector DB,
JWT auth, and a Chrome extension. That is a **4–6 week product for a team of three.**

A solo developer with 24–36 hours has roughly **20–24 productive hours** after sleep, food, debugging
rabbit holes, and submission paperwork. Attempting the full spec produces seven things that are 40%
done, which demos as zero things. So this roadmap builds **four modules end-to-end** and pitches the
rest as roadmap — which is a stronger judge story than partial breadth, because the four that exist
actually prove the "unified risk engine" thesis.

### What gets built (in priority order — stop wherever time runs out)

| # | Scope | Module | Hours | Status |
|---|---|---|---|---|
| 1 | Real-time PII detection while typing (extension + backend) | M1 | ~9.5h | **Must ship** |
| 2 | Site trust check: Safe Browsing + RDAP domain age + brand mismatch | M2 Tier 1 | ~3h | **Must ship** |
| 3 | Unified dashboard: combined score, breakdown, timeline | M6 simplified | ~4h | **Must ship** |
| 4 | Risk engine (weighted aggregation across M1 + M2) | — | ~1.5h | **Must ship** |
| 5 | Demo prep, seed data, README, deck | — | ~3h | **Must ship** |
| 6 | Password-reuse check via Pwned Passwords k-anonymity | M4 (partial) | ~1.5h | **Shipped** |
| 7 | Phishing email paste-and-analyze | M3 | ~2.5h | **Shipped** |

> **Status as built: all 7 rows are complete, including both stretch items.** Phases 0–7
> (H0 → H24) shipped and were verified at every checkpoint; the H24 → H30 stretch block was then
> built out in full. The H28–30 buffer was left unspent, as instructed. See the per-phase
> checkpoints below and `docs/RUNBOOK.md` for how to re-verify each one.
>
> **A second build followed** — five further modules (M8–M12), scoped and delivered separately.
> They are **not** back-dated into the hour-by-hour plan below, because that plan is a record of what
> actually happened in the first 30 hours and rewriting it would make this document a worse one.
> See **§5** at the end.

**Total must-ship: ~21 hours.** That is the entire 24-hour budget with ~3h of slack. The stretch items
are only reachable in a 36-hour event, and only if nothing goes wrong — they were reached.

### What is explicitly NOT built — pitch only

| Module | Why cut |
|---|---|
| M5 Fake review detector | Weakest link to the core "prevent oversharing" narrative. Your own spec marks it demo-only. Cut. |
| M7 RAG chatbot | LangChain + FAISS + corpus curation is 4–6h for a feature judges have seen 50 times. Cut entirely — not even the "single Gemini call" fallback, because it competes for polish time with the demo moment. |
| M2 Tier 2/3 | SSL inspection, redirect tracing, HTML/JS static analysis, visual brand ML. Roadmap slide. |
| All 8 bonus features | Roadmap slide. |

---

## 1. Four deviations from the spec — with reasoning

These are deliberate. Each one is stated so you can overrule it, not slipped in quietly.

### 1.1 PostgreSQL + Redis → **SQLite + in-process TTL cache**

**Concern:** two services to install, configure, and keep alive during judging. Postgres alone is ~40 min of
setup on Windows, and a dead Redis container mid-demo is a silent failure with a confusing traceback.

**Decision:** SQLite via SQLAlchemy, and a ~60-line `TTLCache` dict for the Safe Browsing / RDAP layer.
Zero install, zero daemons, the DB is a file you can delete and regenerate in one command.

**Migration path is genuinely one line** — `DATABASE_URL` swaps `sqlite:///./sentinel.db` for a
`postgresql://` DSN, and the cache module has the same `get/set(key, ttl)` interface as Redis. Say this
out loud in the pitch: *"the storage layer is Postgres-ready, we ran SQLite for demo reliability."*

**Celery is dropped entirely.** There is no background job in the MVP that takes longer than a request.

### 1.2 JWT auth + user accounts → **single-user local mode, JWT stubbed**

**Concern:** signup, login, bcrypt, token refresh, protected-route wiring, and a login screen is ~3
hours that produces exactly zero judge-visible value in a 3-minute demo. Nobody scores a login form.

**Decision:** the extension sends a static `X-Sentinel-Device-Id` header; the backend treats it as the
user identity. The auth dependency (`get_current_user`) exists as a real FastAPI dependency with the
JWT verification path written but flag-gated off. Rate limiting keys off the same header, so the
security story is still true.

**What this costs you:** nothing in the demo, and you can honestly say *"auth is a dependency swap, not
a refactor — here's the function"* while pointing at real code.

### 1.3 WHOIS API → **RDAP (verified working, free, no signup)**

You have no WHOIS key. You don't need one. RDAP is the IETF successor to WHOIS, served free and
unauthenticated by the registries themselves.

```
$ curl -sL https://rdap.org/domain/google.com
  registration -> 1997-09-15T04:00:00Z      # ← domain age, no API key, no rate-limit signup
```

`rdap.org` is a bootstrap redirector — it follows the IANA registry map to the right RDAP server per
TLD, so `.xyz`, `.top`, `.com` all work through one URL. **Follow redirects (`-L` / `follow_redirects=True`).**

Caveat to know before the demo: some ccTLDs and a few registries return 404 or rate-limit. The service
must treat "no domain age" as *unknown*, not as *safe* and not as *malicious* — the risk engine drops
that signal's weight and redistributes rather than defaulting the score.

### 1.4 Module 4 identity check → **password reuse only, no breach-by-email**

**This is a hard external blocker, not a scope choice.** Verified this session:

```
$ curl -o /dev/null -w "%{http_code}" https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com
401
```

HIBP's breach-by-email API has required a **paid key ($3.95/month)** since 2019. Your spec's Module 4
headline — "enter your email, see your breaches" — cannot be built for free.

**Two options:**
- **(a)** Pay $3.95 for one month. Genuinely the best-value spend in this entire project if Module 4 matters to you.
- **(b)** Build the *free* half instead: **Pwned Passwords range API** (verified working above, no key).
  Client hashes the password with SHA-1, sends **only the first 5 hex chars**, receives ~1,000 suffix
  hashes, and matches locally. The real password never leaves the device.

> **Measured, after building it:** the estimate above was folklore. Prefix `5BAA6` (the prefix of
> `password`) returns **1,978** real candidates from the live API, not ~800. Padding entries — HIBP
> returns them when you send `Add-Padding: true`, so response *size* leaks nothing about how many real
> hits a prefix has — carry `count == 0` and are dropped client-side. Every user-facing string says
> "around a thousand", which is the honest floor rather than the flattering estimate.

Option (b) was chosen and built, and not as a consolation prize — it's a *better security story* than
the paid endpoint. "We check your password against 900 million breached credentials and we
mathematically cannot learn what your password is" is a k-anonymity explanation you can deliver in 20
seconds, and it directly satisfies your own spec's requirement: *"password reuse (optional, local-only
comparison — never transmit actual passwords)."*

Either way: **Aadhaar/PAN stay in Module 1 as pattern detection in typed text only.** No verification
against any government record, ever. This stays true regardless of budget.

---

## 2. Hour-by-hour plan

Times are elapsed-hours from your start. Every phase ends with a **checkpoint** that answers the
question your spec demands: *"is this demoable right now, even if we stopped here?"*

### Phase 0 — Setup & key verification · H0 → H1.0 (1h)

- Scaffold `backend/`, `extension/`, `dashboard/`, `docs/`
- Python venv + FastAPI/uvicorn/httpx/pydantic/sqlalchemy; `npm create vite` for dashboard
- `.env` + `.env.example`, `.gitignore` (**verify `.env` is ignored before the first commit**)
- **Smoke-test both API keys with a real call, right now**

> **Why this is Hour 0 and not Hour 12:** a Safe Browsing key that needs the API enabled in the Cloud
> console, or a Gemini key that's region-blocked, is a 30-minute fix at hour 0 and a project-killer at
> hour 14. Never discover a dead key late.

**✅ Checkpoint 0:** both APIs return 200 from a scratch script. Nothing is demoable yet — this is the
only phase where that's acceptable.

### Phase 1 — Backend PII core (regex tier) · H1.0 → H4.5 (3.5h)

- FastAPI app, CORS locked to extension + dashboard origins, `/health`
- **Detector registry**: 13 patterns — email, phone (IN/intl), credit card (**+ Luhn**), Aadhaar
  (**+ Verhoeff checksum**), PAN, passport, IFSC, UPI ID, bank account, DOB, coordinates, API keys
  (AWS/Google/Stripe/GitHub prefixes), JWT
- `POST /api/v1/pii/scan` → per-finding `{type, confidence, reason, risk, span, masked_preview}`
- **Response schema makes `reason` and `confidence` required fields** — explainability enforced by
  Pydantic, not by discipline
- pytest over the detector registry (pure functions, no network, runs in <1s)

> **Why checksums matter more than they look:** Luhn and Verhoeff are what turn "any 12 digits" into
> "a real Aadhaar number, 96% confidence." They are ~15 lines each and they are the difference between
> a demo that flags your order ID and one that doesn't. This is the highest-value hour in the build.

**✅ Checkpoint 1:** paste `"My Aadhaar is 2345 6789 9014"` into Swagger UI → structured finding with
confidence and reason. **Demoable via `/docs` if you stopped here.** Ugly, but real.

> Use that exact number. It is Verhoeff-valid; an arbitrary 12 digits such as `2234 5678 9013` is not,
> and the endpoint correctly returns **no findings** for it. Verified live during final re-verification:
> the invalid number scores `low` with an empty `findings` array, the valid one scores `high` at 0.96.
> Checking the checksum before checking the code saves the ten minutes it cost here.

### Phase 2 — Chrome extension · H4.5 → H10.0 (5.5h) ← **the demo moment**

- MV3 `manifest.json`, content script on the 7 target sites + `<all_urls>` for generic forms
- Capture `input` / `textarea` / `contenteditable` (Gmail and WhatsApp Web are contenteditable — this
  is the part that breaks; budget for it)
- **250ms debounce**, minimum-length gate, skip password fields entirely
- Non-blocking toast: finding, risk, confidence, reason, **[Mask] [Ignore] [Always allow here]**
- One-click mask writes back to the field preserving format (`XXXX XXXX 9013`)
- Popup: current-page trust badge + session findings count

> **The false-positive escape hatch is not optional.** A tool that flags every order number gets
> uninstalled in 10 minutes. `Always allow here` writes `{origin, pattern_type}` to
> `chrome.storage.local` and suppresses that pair permanently. It is ~30 lines and it is the difference
> between a product and a nuisance. Demo it — judges recognize the maturity.

**✅ Checkpoint 2:** type an Aadhaar number into a Gmail compose box → toast appears → click Mask →
text is masked in place. **This is your demo. If everything after this fails, you still have a project.**

### Phase 3 — Gemini context tier · H10.0 → H12.5 (2.5h)

- Second-tier call **only** when regex finds nothing but text length + heuristics suggest context-
  dependent PII ("meet me at 42 Oak Street", "our Q3 revenue was ₹4.2 crore")
- Structured JSON output schema; **prompt-injection hardening** — user text goes in a delimited block,
  never concatenated into the instruction section, and the system prompt states that content inside the
  block is data, never instructions
- **Fail-open to regex results.** 1.5s timeout. Gemini being slow or down must degrade the answer, never
  break typing.

> **Why two tiers, stated for the pitch:** an LLM call per keystroke is ~600ms and costs money per
> character typed — unusable. Pure regex can't tell an address in a shipping form from an address in a
> quoted news article. The hybrid — deterministic tier for structured data at 0ms and $0, semantic tier
> only on the uncertain remainder — is the actual production architecture, and it's a real engineering
> answer to give when a judge asks "why not just call the LLM?"

**✅ Checkpoint 3:** unstructured address text is caught with reasoning. Kill the network → regex tier
still works. **Demo survives a hotel Wi-Fi failure.**

### Phase 4 — Site trust (M2 Tier 1) · H12.5 → H15.5 (3h)

- `POST /api/v1/site/check`: Safe Browsing v4 lookup ‖ RDAP domain age ‖ brand-token mismatch
  (`amazon-login-security.xyz` contains `amazon`, is not `*.amazon.com`/`.in`)
- TTL cache, 6h — **this is demo-critical, not an optimization**: reloading the same page 20 times
  during rehearsal must not burn Safe Browsing quota or get you RDAP-throttled at judging time
- Extension: on navigation, check → set badge color → popup shows itemized reasons
- Unknown-signal handling: RDAP 404 → weight redistributes, score is not silently "safe"

**✅ Checkpoint 4:** visit a fresh suspicious domain → red badge → popup lists *why*, itemized.
**Two independent detectors now working. Demo is genuinely multi-module.**

### Phase 5 — Dashboard (M6 simplified) · H15.5 → H19.5 (4h)

- Vite + React + TS + Tailwind + Recharts, dark by default
- **One screen:** big unified Security Score · three sub-scores (Privacy / Identity / Browsing) ·
  Recharts area chart of score over time · threat timeline · flagged-sites list · ranked recommendations
- `GET /api/v1/dashboard/summary` — one endpoint, one round trip
- Every list has a **real empty state** ("Nothing caught yet — that's good news") and an error state

> **This is the screen that sells the thesis.** Modules 1 and 2 are individually unremarkable — a
> regex matcher and an API wrapper. The dashboard is where a judge sees typing behavior and browsing
> context feeding *one* score, and the "unified risk engine, not a bag of tools" claim becomes visible
> instead of asserted. Build it even if it's rough.

**✅ Checkpoint 5:** actions taken in the extension appear on the dashboard within seconds.

### Phase 6 — Risk engine & polish · H19.5 → H21.0 (1.5h)

- Weighted aggregation with **stated, defensible weights** (e.g. Privacy 0.4 / Browsing 0.4 /
  Identity 0.2), time-decay so old events stop dominating
- Return the weight contributions in the API response — the score explains itself
- Consistent risk-tier color mapping; **red reserved for genuinely high risk only**

**✅ Checkpoint 6:** unified score moves for a defensible, explainable reason.

### Phase 7 — Demo prep · H21.0 → H24.0 (3h)

- **Seed script**: one command populates realistic history so the dashboard isn't empty on stage
- **Rehearse the 3-minute script end-to-end three times** — this is where you find the bugs that only
  appear under pressure
- Offline fallback: mock-mode flag so a dead network doesn't kill the demo
- README, run instructions, deck content

**✅ Checkpoint 7 — the only one that counts:** the full demo runs start-to-finish, three times,
without you touching a terminal.

### Stretch (36h only) · H24 → H30 — **built**

- **H24–25.5 · ✅ shipped:** Pwned Passwords k-anonymity check. `GET /api/v1/identity/pwned-range/{prefix}`
  proxies the range API (5 hex chars only, `Add-Padding: true`), the popup does the SHA-1 and the suffix
  match locally, and `POST /api/v1/identity/password-check` stores *only* `{hash_prefix, breach_count,
  label}` — never a password, never a full hash. Identity stops being a `None` sub-score and starts
  being earned. Supersession by label means changing a password visibly recovers the score.
- **H25.5–28 · ✅ shipped:** Module 3 phishing email paste-and-analyze. Tier 1 is deterministic and
  offline (links / sender / content, each an independent group); Tier 2 is a fenced Gemini intent call
  under a hard response schema. **Tier 2 may raise the risk score and may never lower it** — a model
  saying "benign" cannot overrule a link that provably points at a lookalike domain. Nothing is
  persisted: the endpoint takes no DB session at all, and a test enumerates every table to prove it.
- **H28–30 · unspent, as instructed.** **Do not fill this.** Unspent buffer is what a working demo is
  made of.

**✅ Checkpoint 8:** paste a phishing email into the dashboard panel → itemised signals, a risk score
labelled with its direction, and a next step written in Python rather than by the model. Paste an
email whose body *orders* the model to answer "benign" → still scored dangerous. Type a password into
the popup → breach count with a confidence that reflects whether the number could be corroborated.

---

## 3. Rules for the next 24 hours

1. **Never break a passing checkpoint to start the next phase.** Commit at every green checkpoint.
2. **Hour 21 is a hard freeze.** No new features after it, regardless of how close something feels.
   Every hackathon loses to a feature that was "10 minutes away" at hour 23.
3. **If a phase overruns by >45 min, cut its scope, not the next phase.** Phase 5 stealing from Phase 7
   means an unrehearsed demo, which is worse than a plainer dashboard.
4. **The demo runs on localhost.** No deploy. Deployment is a slide.
5. When you're tempted by M5 or M7 at hour 18 — reread section 0.

---

## 4. Target users, per module (drives UI copy tone)

| Module | Primary beneficiary | Copy implication |
|---|---|---|
| M1 PII detection | Students & senior citizens — most likely to paste an Aadhaar into a chat without thinking | Plain language, no jargon, large text, explain *why* it's risky not just *that* it is |
| M2 Site trust | Online shoppers & senior citizens — the actual phishing victim demographic | Itemized reasons in plain words: "registered 4 days ago" beats "low domain reputation score" |
| M3 Phishing email | Senior citizens & anyone who received a message they can't place — the "is this real?" forward-to-a-relative moment | The signals *are* the copy. "The link says onlinesbi.sbi but goes to sbi-verify-account.tk" teaches; "risk 82" does not. State the score's direction in words next to the number |
| M4 Password check | Everyone, but especially reusers — the single highest-leverage 30 seconds in the product | The privacy promise must be on screen *before* the input, not in a tooltip. A user is about to type a real password into an extension |
| M6 Dashboard | Professionals & solo founders — the ones who'll check a score weekly | Denser is acceptable here; this user tolerates a chart |

---

## 5. The second build — M8 → M12

Five modules added after the original scope closed, delivered **in risk order** so that a fight with
the hardest one at the end would leave four finished modules rather than five half-built ones. Each was
complete — code, tests, and docs — before the next started.

| # | Module | Status | The gap it closed |
|---|---|---|---|
| M8 | Explainability narrative | ✅ | The score published its arithmetic but never told a story. "46" does not say what to change. |
| M9 | QR scam detection | ✅ | UPI QR fraud is among India's most-reported scams and nothing in the product could see a QR code. |
| M10 | Clipboard Guardian | ✅ | Detection was typing-only, and knew nothing about *where* something was being pasted. |
| M11 | Chat scam detection | ✅ | Scam detection was email-only. The fraud economy runs on WhatsApp. |
| M12 | Screenshot OCR protection | ✅ | A photograph of an Aadhaar card is invisible to every text detector in the product. |

### Why this order

Risk, descending — the reverse of how features are usually scheduled. M8 is pure arithmetic over rows
that already exist and could not fail in an interesting way. M12 depends on a 9 MB wasm build behaving
inside an MV3 content security policy, which is the one thing in this project that could have simply
refused to work. Putting it last meant its failure mode was "four new modules instead of five", not
"five modules, none of them finished".

### The decisions worth arguing with

**OCR runs locally, or not at all.** Gemini Vision would have been a third of the code and a fraction
of the download. It was rejected on principle: uploading the Aadhaar photograph to a cloud API is
precisely the act the feature exists to prevent, and a security tool that commits the harm it warns
about has no argument left to make. So Tesseract is vendored — pinned, checksummed, ~9 MB in the repo
— and every byte of every image stays on the machine.

**Only a checksum may authorise a correction.** OCR misreads `0`/`O`, `1`/`I`, `5`/`S` and `8`/`B`, so
`234S 6789 9O14` is a fully-read Aadhaar number that no regex will match. Repairing it means rewriting
the user's data, and the only thing that makes a rewritten read trustworthy is an independent
arithmetic property: Verhoeff for Aadhaar, Luhn for cards. PAN, passport and IFSC have no checksum and
are therefore deliberately *not* repairable — otherwise this module becomes a machine for hallucinating
identity documents out of low-resolution photographs.

**One candidate per span, never a search.** The obvious implementation tries every combination of
substitutions and keeps whichever passes. It is broken: Verhoeff and Luhn each admit roughly one in ten
random strings of the right length, so testing thirty candidates finds a "valid" Aadhaar in almost any
twelve-character blob on the page. The substitution map is a *function* — one digit reading per
character — so the checksum's own error rate is the whole error rate.

**No LLM writes user-facing advice, anywhere.** Unchanged from M3 and extended to M11: the model
classifies into an enum, and Python authors every sentence a user reads.

**Chat auto-watch is opt-in, off by default, per surface, with an on-screen indicator.** The
feature-specific risk is not a false positive; it is that the tool reads other people's messages. The
right-click path — selector-free, works on every site, cannot break when WhatsApp reships its DOM — is
the one that is always available.

### What this cost

~9 MB of vendored third-party binaries, which is a real and unwelcome addition to a repository. The
mitigation is the standard a security tool shipping binaries should hold itself to: every file pinned
to a version, every SHA-256 recorded in `extension/lib/vendor/CHECKSUMS.sha256` and explained in
`INTEGRATION_NOTES.md`, `run.sh --setup` refusing to finish if one does not match, and an ordinary run
warning loudly while leaving every unaffected feature working.

### Verification

`597 passed` — the 315 from the first build, plus the M8–M12 suites, all still offline, no server, no
API keys, no image, no browser. The per-feature checks a human should run by hand are the
"What to verify" lists in `extension/test/harness.html`, which now cover all four new extension
surfaces plus the dashboard's screenshot panel.

---

## Next deliverable

**2 — Folder structure.** Confirm this roadmap (or tell me what to move) and I'll produce it.
