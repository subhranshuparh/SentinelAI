# SentinelAI — Integration Notes

**Deliverable 9 of 15.** Every external dependency, what it costs, what it does when it breaks, and
where the number lives in code.

The organising rule for this whole document: **SentinelAI has no hard external dependency.** Kill the
network entirely and the product still detects Aadhaar numbers, still masks them, and still renders a
dashboard — with every degraded signal labelled as degraded. Anything below that fails, fails to a
stated, tested behaviour rather than to a traceback.

---

## 1. The four external surfaces

| Service | Auth | Cost | Called from | Blocking? |
|---|---|---|---|---|
| Google Gemini (`generateContent`) | API key, header | Free tier, per-request quota | Backend only | No — Tier 2 fails open to Tier 1, in both M1 and M3 |
| Google Safe Browsing v4 (`threatMatches:find`) | API key, query param | Free, unmetered in practice | Backend only | No — signal drops, weight redistributes |
| RDAP (`rdap.org` → registry) | **None** | Free, no signup | Backend only | No — `domain_age_days: null` |
| Pwned Passwords range API | **None** | Free, no signup, no rate limit published | Backend only | Yes, for that one feature — `503` and "not checked", never a fabricated clean result |

The last row is the only place in this product where a failed upstream produces an error status instead
of a degraded answer, and the asymmetry is deliberate: there is no partial credit on "is this password
breached". Any answer other than the real one is a lie, and the least harmful lie is still "we could
not check".

**No API key exists anywhere in `extension/` or `dashboard/`.** Both are inspectable by anyone who
opens DevTools or `chrome://extensions`. Every keyed call originates in the FastAPI process, reading
from `backend/.env`, which is gitignored. The extension's only credential is a device UUID it generated
itself, which authorises nothing but its own row in a local SQLite file.

---

## 2. Gemini — the Tier-2 semantic detector

### What it is used for, and what it is not

It is used for one thing: text where the regex tier found nothing but the content might still be
sensitive — `"meet me at 42 Oak Street, the blue door"`, `"our Q3 revenue was ₹4.2 crore"`. It is
**never** used to decide whether an Aadhaar number is an Aadhaar number. That is Verhoeff's job, and
Verhoeff is deterministic, free, and instant.

### The gate — why cost is bounded

`should_run_tier_2()` in [engine.py](../backend/app/services/pii/engine.py) refuses the call unless
**all** of these hold:

| Gate | Value | Reason |
|---|---|---|
| Tier 1 found nothing high/critical | — | If we already know it's an Aadhaar, an LLM cannot improve on "it's an Aadhaar" |
| `len(text) >= MIN_TIER_2_CHARS` | 40 | Under 40 chars there is no context to reason about |
| `words >= MIN_TIER_2_WORDS` | 6 | Same test from the other side; catches 40 chars of one URL |
| `ENABLE_GEMINI_TIER` | `true` | Kill switch |
| `GEMINI_API_KEY` non-empty | — | Absence is *configuration*, not failure |

Consequence for quota: typing `"hi"`, `"ok"`, `"2234 5678 9013"` costs **zero** Gemini calls. The
demo's headline moment — the Aadhaar toast — never touches the network beyond localhost.

### Timeout: 4.0 s, and why it is not the roadmap's 1.5 s

Measured on this machine, `gemini-2.5-flash` with `thinkingBudget: 0` on a ~600-token prompt returns in
**1.4–1.9 s**. The roadmap's 1.5 s sat *inside* that spread — the worst possible place for a timeout,
because roughly half of all perfectly healthy responses would have been discarded as failures and
reported to the user as "couldn't fully check". 4.0 s clears the measured p99 with room for venue
Wi-Fi.

This costs the demo nothing, because of the gate above: the path that a judge watches never waits on
Gemini.

### Circuit breaker

`_FAILURE_THRESHOLD = 2`, `_COOLDOWN_SECONDS = 60.0`
([gemini.py](../backend/app/services/llm/gemini.py)).

Two consecutive failures park the tier for a minute. No further calls are attempted, so a dead key or a
region block costs 2 timeouts, not one per keystroke for the rest of the session. During the cooldown
`tier_2_status` reads `unavailable` and the UI says so.

### Model choice — a real gotcha, documented

`gemini-2.0-flash` returns **HTTP 429 with zero free-tier quota** on AI Studio express keys. It is not
rate limiting you; that model has no free allocation on that key type. The symptom looks identical to
"you're going too fast", which is how it eats an hour. Use `gemini-2.5-flash`. This is noted in
`.env.example` next to the variable, not only here.

### Prompt injection — the integration risk that matters

The text sent to Gemini is *arbitrary content from an arbitrary web page*. Four layers, in
[prompts.py](../backend/app/services/llm/prompts.py):

1. **No concatenation.** Instructions and user data are separate parts of the request. There is no
   f-string that puts page content next to a system instruction.
2. **Per-request random fence token.** The delimiter is unguessable, so page content cannot close the
   block early and start issuing instructions.
3. **Schema-constrained output.** The response schema makes disobedience unrepresentable — the model
   can only emit findings of declared types, not prose, not tool calls.
4. **Substring verification.** Every returned finding must appear *literally* in the submitted text or
   it is discarded. A model talked into inventing a finding cannot get it past this.

Tested in `test_tier2.py` with live injection payloads (`"ignore previous instructions and…"`).

### The second Gemini caller: email intent (Module 3)

`analyze_email()` in the same file, with a **12 s** budget rather than 4 s — nobody is typing while it
runs, the user pressed a button and is watching a spinner, and a longer prompt deserves a longer
ceiling. It shares the same circuit breaker deliberately: if Gemini is down, it is down for both
callers, and letting the email path keep retrying would just re-park the tier for the typing path.

It adds a **fifth** injection layer that the typing path does not need, because the threat model is
strictly worse — a phishing email is *authored by an attacker who expects to be analysed*:

5. **The model does not write the recommendation.** It classifies into an enum (`credential_theft`,
   `payment_fraud`, `malware_delivery`, `impersonation`, `extortion`, `unclear`, `benign`) and the
   action sentence is authored in Python and looked up by key. The most action-provoking sentence in
   the product is never composed by attacker-influenced text.

And one architectural rule that is not a prompt defence at all, but does the same job:

> **Tier 2 may raise the risk score and may never lower it.**
> `final = max(tier1, tier1 × 0.80 + intent_penalty × 0.20)`

Even a *fully successful* injection — one that defeats all five layers and gets `intent: "benign"` out
of the model — cannot clear an email whose link provably points at a lookalike domain. The worst an
attacker achieves is no improvement on the deterministic verdict. Verified live: an email instructing
the model to return `benign` scored `dangerous 82` with intent `credential_theft`.

---

## 3. Google Safe Browsing v4

### Key type is not optional

Must be a **plain API key** (Cloud Console → Credentials → Create API key). Safe Browsing v4 rejects
OAuth bearer tokens with HTTP 400. A service-account JSON will not work here no matter how correct the
IAM roles are — verified the hard way this build. The successor **Web Risk** API *does* take OAuth, and
also requires billing enabled (`403 BILLING_DISABLED` without it), which is why the MVP is on v4.

Enable "Safe Browsing API" on the project. Free, no billing required.

### Privacy of the request

Query strings and fragments are stripped before the URL leaves the process. Password-reset tokens,
magic-link codes, and session ids live in query params, and sending them to a third party in the name
of security would be its own breach. The **path is kept** — phishing lives on paths
(`/amazon/signin/verify`), so dropping it would blind the check.

### Quota and caching

Free tier is generous, but rehearsal is the real consumer: running the demo twenty times against one
domain is twenty lookups. `CACHE_TTL_SECONDS = 6 * 60 * 60`
([site/engine.py](../backend/app/services/site/engine.py)) keyed on the **query-stripped URL**.

This is listed under integration rather than performance on purpose — it is a *demo-reliability*
control. Cache first, rehearse freely.

### Failure behaviour

Timeout 3.0 s. On timeout or error the signal is dropped, not defaulted:

- `reasons[]` gains an entry with `weight: "unknown"` — rendered in the popup, never hidden.
- `confidence` falls, because the denominator is the weight that *actually answered*.
- The verdict cannot become `safe` on the remaining evidence alone if the total answering weight is
  below `MIN_WEIGHT_FOR_VERDICT` (0.31).

**A clean Safe Browsing result is discounted 50%** unless the domain is provably older than 30 days.
The list is built by crawling; it always lags a campaign launched this morning. "Not on Google's list"
is genuinely weaker evidence for a four-day-old domain than for a nine-year-old one, and the score says
so.

---

## 4. RDAP — domain age without a WHOIS key

We have no WHOIS API key and do not need one. RDAP is the IETF successor to WHOIS, served free and
unauthenticated by the registries themselves. `rdap.org` is a bootstrap redirector that follows the
IANA registry map to the correct server per TLD, so `.com`, `.xyz` and `.top` all work through one URL.

### The redirect loop is hand-written, and that is deliberate

`httpx.Timeout` is **per-operation, not per-request**. A 4 s timeout on a request that follows three
redirects permits roughly 4 s *per hop* — so a chain of slow registries can hang far past the budget
the code appears to set. Since RDAP is a bootstrap redirector, multi-hop is the normal case, not the
exception.

[rdap.py](../backend/app/services/site/rdap.py) therefore follows redirects manually against a single
shared wall-clock deadline:

```
_MAX_REDIRECTS      = 3
_MIN_USEFUL_SECONDS = 0.4     # don't start a hop that cannot finish
RDAP_TIMEOUT_SECONDS = 8.0    # total, all hops included
```

8 s is measured, not guessed: `sbi.co.in` 1.9 s, `wikipedia.org` 2.7 s, `uidai.gov.in` 3.5 s, a `.xyz`
404 at 4.7 s. The original 4.0 s sat inside that spread and was rejecting valid answers. It costs
nothing in practice — RDAP runs in parallel with Safe Browsing, and only on navigation, never while
typing.

### Known-unreliable, by design of the ecosystem

Some ccTLDs return 404. Some registries rate-limit by IP. Both are normal. The contract is:

> `domain_age_days: null` means **RDAP had no answer**. It does not mean "old", and it does not mean
> "safe".

This is the single most important line in this document. A missing signal that silently reads as a pass
is how a security tool tells a user a phishing page is fine.

---

## 4b. Pwned Passwords — the range API, and why it needs no key

`GET https://api.pwnedpasswords.com/range/{5 hex chars}`. No signup, no key, no published rate limit.
This is the *free half* of HIBP; the breach-by-email endpoint next door has needed a paid key since
2019 (verified `401` this build, see §11).

### The k-anonymity protocol, in the order it happens

```
1. popup.js:  SHA-1(password)              ← in the browser, via crypto.subtle
2. popup.js:  take the first 5 hex chars   ← everything else stays local
3. backend:   GET /range/{5 chars}  +  header  Add-Padding: true
4. backend:   drop rows where count == 0   ← those are the padding
5. popup.js:  look for its own 35-char suffix in the returned map
6. popup.js:  POST {prefix, count, label}  ← the count, never the suffix
```

**Step 5 is the whole design.** The match happens on the client. The server is told a number, never
told which suffix produced it, and therefore never narrows the candidate set below the crowd.

### Measured, not estimated

Everyone quotes "~800 hashes per prefix". That is folklore. Live, this build:

```bash
curl -s https://api.pwnedpasswords.com/range/5BAA6 | wc -l
# 1978    ← the prefix of "password"
```

Every user-facing string says "around a thousand", which is the honest floor rather than the
flattering estimate. The corpus is ~900 million credentials; `password` itself appears **52,372,427**
times.

### `Add-Padding: true` is not optional

Without it, response *length* leaks information: a prefix with few real hits returns a short body, and
a passive observer who can see TLS record sizes learns something about the crowd size. With it, HIBP
pads every range to a uniform size with fake entries carrying `count == 0`, which
[pwned.py](../backend/app/services/identity/pwned.py) drops on parse. This is why the `count` field in
the API response is the number of *real* candidates, not the number of lines returned.

### Corroboration without de-anonymising

`count_is_plausible(prefix, count)` re-fetches the **same public range** and checks that some suffix in
it carries the reported number. This catches a broken or lying client without the server learning which
suffix matched — it verifies "this number exists in the crowd", not "this is your password".

| Input | Result | Confidence returned |
|---|---|---|
| True `52372427` for `5BAA6` | corroborated | `0.95` |
| Fabricated `10000000` for `5BAA6` | contradicted | `0.75` |
| Range fetch failed | *could not check* | `0.95` — the finding stands |

That last row is the invariant applied in the direction people forget: **"could not corroborate" is not
"contradicted".** The user watched their own browser compute the match; a network hiccup during a
double-check is not evidence against it.

### Budgets

| Constant | Value | File | Reason |
|---|---|---|---|
| `TIMEOUT_SECONDS` | 6.0 | `identity/pwned.py` | A padded range is ~50 KB; 6 s clears it on venue Wi-Fi |
| `CACHE_TTL_SECONDS` | 12 h | `identity/pwned.py` | The corpus changes monthly. Rehearsing the same demo password 20 times is 1 request |
| `MAX_SUFFIXES` | 2 000 | `identity/pwned.py` | A memory bound on a response we do not control. Measured max is 1 978 |

### Failure behaviour

`503` with *"The breach database could not be reached. Your password was not checked."* — **never an
empty range**. An empty range is indistinguishable from "no match found", which renders as *your
password is safe*. Telling a user that because a CDN was down is the precise failure this codebase
refuses everywhere else, so it is asserted by a test rather than left to care.

---

## 5. Internal rate limiting

Token bucket, per `X-Sentinel-Device-Id`, `RATE_LIMIT_PER_MINUTE = 120`
([ratelimit.py](../backend/app/core/ratelimit.py)).

**Why a bucket and not a fixed window:** typing is bursty. A fixed window rejects a legitimate flurry of
edits that happens to land at the wrong second; a bucket absorbs the burst and only throttles sustained
abuse. New callers start with a full bucket, so a first request is never throttled.

**Why 120:** at a 250 ms debounce, sustained typing peaks around 4 requests/second in short bursts and
far less in practice. 120/min absorbs real usage while still capping a runaway content script — a
debounce that stops debouncing, or a re-render loop on a busy page — that would otherwise drain the
Gemini quota in minutes.

`429` responses carry `Retry-After`. The extension drops that one scan **silently** and lets the next
debounce tick retry ([lib/api.js](../extension/lib/api.js)). No error toast, deliberately: hitting the
limiter is self-inflicted load from the user's own typing, not something they did wrong, and nothing is
actually lost — the text is still sitting in the field, so the next tick scans a superset of it. This is
the one case where staying quiet is honest rather than evasive, and it is why `backendOnline` is still
set to `true` on a `429`: the backend answered.

**Deployment note:** in-memory and per-process. Correct for a single-worker MVP. A multi-worker deploy
moves this to Redis behind the same `check()` signature — the call site does not change.

---

## 6. Caching summary — every TTL in one table

| What | Where | TTL | Why this number |
|---|---|---|---|
| Site verdict (SB + RDAP + brand) | `site/engine.py` `CACHE_TTL_SECONDS` | 6 h | Rehearsal must not burn quota or trip RDAP throttling |
| Gemini circuit breaker | `llm/gemini.py` `_COOLDOWN_SECONDS` | 60 s | Long enough to stop hammering a dead key, short enough to self-heal mid-demo |
| Dashboard score snapshot | `routers/dashboard.py` `SNAPSHOT_MIN_INTERVAL_MINUTES` | 5 min | A dashboard polling every 10 s must not write 6 chart points a minute |
| Dashboard scoring window | `risk/engine.py` `LOOKBACK_DAYS` | 30 d | Fixed **server-side**; a client-tunable window lets the caller pick the flattering number. **Identity is exempt** — a breached password does not age out |
| Pwned Passwords range | `identity/pwned.py` `CACHE_TTL_SECONDS` | 12 h | The corpus updates monthly. Caching a *public* range leaks nothing — it is keyed on 5 chars anyone can request |
| PII scan result | — | **Never cached** | Text changes on every keystroke; a cache would be a permanent miss *and* a place where typed text lives |
| Email analysis | — | **Never cached** | Same reason, harder: caching would mean keeping email bodies (or a hash of them) in memory. The endpoint holds nothing after the response |

The cache is `dict`-backed with a `get(key)` / `set(key, value, ttl)` interface deliberately shaped like
Redis, capped at `DEFAULT_MAX_ENTRIES = 2_000`, expiring lazily on read. The answer to "why not Redis?"
is a 90-line file a reviewer can open: **the interface is Redis's, the backend is a dict, swapping is an
import change.**

---

## 7. Client-side budgets (extension)

| Constant | Value | File | Reason |
|---|---|---|---|
| `DEBOUNCE_MS` | 250 | `content/content.js` | Below this you scan mid-word and flag nothing; above it the toast feels laggy |
| `MIN_SCAN_LENGTH` | 6 | `content/content.js` | Nothing under 6 chars can be a card, an Aadhaar, or an email |
| `NEVER_SCAN_TYPES` | `password`, `hidden`, `file`, `submit`, `button`, `checkbox`, `radio` | `content/content.js` | A password must never enter a variable, let alone a request |
| `SCAN_TIMEOUT_MS` | 4 000 | `lib/api.js` | Matches the backend's own Tier-2 ceiling |
| `SITE_TIMEOUT_MS` | 12 000 | `lib/api.js` | Must exceed RDAP's 8 s server budget, or the client gives up on a call that was going to succeed |
| Text cap | 20 000 chars | backend, `413` | A paste that large is not the typing path |

### All network calls originate in the service worker

Content scripts get `lib/bridge.js` — the same surface, forwarded over `chrome.runtime.sendMessage`.
Not stylistic: under MV3 a content script's `fetch()` is governed by the **host page's** CORS policy,
not the extension's, so a scan fired from `mail.google.com` to `127.0.0.1:8000` is blocked and the
failure arrives as a bare `TypeError`. Host permissions do not lift this for content scripts.

Two things fall out for free: the backend URL exists in exactly one file, and the service worker can
reject messages that did not come from a real tab — so another extension that guesses this one's id
cannot use it as an open proxy to the local backend.

---

## 8. CORS

```
CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

Never `*`. The backend receives text the user typed into their bank's website; any origin being able to
call it is a real leak, not a theoretical one.

**Both spellings are listed because they are different origins to a browser.** Whichever one the user
types into the address bar is the one sent in the `Origin` header. Listing only one turns a working
dashboard into an unexplained CORS failure that depends on how the tab was opened. (On Windows there is
a second trap underneath: `localhost` resolves to `::1` before `127.0.0.1`.)

The extension origin (`chrome-extension://<id>`) is added at runtime once the unpacked id is known —
the id is machine-specific, so hardcoding it in a committed file would be wrong on every other machine.

---

## 9. HTTPS

**Deployment TODO, stated rather than hidden.** The demo runs on `http://127.0.0.1:8000`. Loopback
plaintext is not an interception risk in any meaningful sense — the traffic never leaves the machine —
but the moment this backend is reachable off-host, TLS is mandatory *before* anything else, because the
request bodies are exactly the sensitive strings the product exists to protect.

Concretely, on deploy: terminate TLS at the reverse proxy, set `Strict-Transport-Security`, and switch
the extension's base URL to `https://`. Nothing in application code changes.

---

## 10. Failure matrix — what a judge can unplug

| Break this | Result | Still demoable? |
|---|---|---|
| Gemini key removed | `tier_2_status: "disabled"`. Regex tier unaffected | **Yes** — the Aadhaar demo is unchanged |
| Gemini times out | `tier_2_status: "unavailable"`, breaker opens after 2 | **Yes** |
| Safe Browsing key removed | Signal drops to `weight: "unknown"`, confidence falls | **Yes** — brand mismatch alone still returns `dangerous` |
| RDAP 404 / throttled | `domain_age_days: null`, weight redistributes | **Yes** |
| Pwned Passwords unreachable | `503` + *"Your password was not checked."* Never an empty range | Partly — that one feature is honest about being unavailable |
| Gemini down during email analysis | `heuristics_only: true`, intent `null`. Every deterministic signal still fires | **Yes** — a lookalike link alone still reads `dangerous` |
| Email crafted to defeat the AI tier | Tier 2 can only raise the score, so the deterministic verdict stands | **Yes** — this is the demo, not a caveat |
| **Entire network down** | Tier 1 + brand mismatch + M3 link/sender/content signals + full dashboard | **Yes** — this is the offline demo mode |
| Backend down | Extension shows a one-per-page banner: *"SentinelAI is offline — typing is not being checked."* Dashboard shows an error banner and keeps the last good data with a staleness note | Degraded, and *honest* — never green, never silently quiet |
| Database deleted | `404` on the dashboard, rendered as first-run onboarding, not as an error | Yes — `python -m app.db.seed` restores it |

Nothing in that table renders green on missing information. That is the whole invariant, stated once:
**a signal that did not answer is never counted as a signal that said "fine".**

---

## 11. What is deliberately not integrated

| Not used | Why |
|---|---|
| HIBP breach-by-email | Requires a paid key ($3.95/mo) since 2019. Verified `401` this build. The **free** half — Pwned Passwords, §4b — is built; the paid half is roadmap. |
| WHOIS APIs | RDAP is free, keyless, and the standard's successor. No reason to pay. |
| Web Risk API | Needs billing enabled (`403 BILLING_DISABLED`). Safe Browsing v4 is free and sufficient. |
| Dark-web / paste-site sources | Out of scope by the project's own security constraints. Authorised APIs and public data only. |
| Aadhaar/PAN verification against government records | **Never.** Aadhaar and PAN are pattern detection in typed text only (Module 1). This does not change with budget. |
| Redis / Celery / Postgres | No MVP job outruns a request. Swaps are a connection string and an import. |
| A QR-decoding **web service** | The image would have to be uploaded. The pictures people check are screenshots of their own payment apps — see §12. |

---

## 12. Vendored client-side libraries

Modules 9 and 12 need a decoder in the browser. Every one of them is a **committed file**, pinned by
version and by SHA-256. Nothing is fetched at runtime, ever.

| File                           | Library                               | Version | Licence    | Size   | SHA-256                                                            |
| ------------------------------ | ------------------------------------- | ------- | ---------- | ------ | ------------------------------------------------------------------ |
| `extension/lib/vendor/jsqr.js` | [jsQR](https://github.com/cozmo/jsQR) | 1.4.0   | Apache-2.0 | 251 KB | `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` |

Verify at any time — this is not a claim you have to take on trust:

```bash
cd extension/lib/vendor && sha256sum -c CHECKSUMS.sha256
```

`run.sh` runs the same check on every start. Under `--setup` a mismatch is a hard failure, because
`--setup` promises a complete install; on an ordinary run it is a loud warning that names exactly what
is degraded (QR and OCR) and what is not (typing protection, site checks, the dashboard). Refusing to
start the other four modules because a QR decoder is truncated would be the wrong trade.

### Why vendored rather than loaded from a CDN

Three independent reasons, any one of which would be sufficient:

1. **MV3 forbids it.** The extension CSP is `script-src 'self'`. A CDN `<script>` does not execute.
2. **Remote code in a security tool is indefensible.** Code fetched at scan time can be replaced
   tomorrow by whoever controls the CDN, with no reinstall and no user consent. A product whose job is
   telling people what to trust cannot itself be a delivery channel for arbitrary code.
3. **It must work offline.** The offline demo is a stated feature, not a fallback.

### Why unminified

`jsqr.js` is shipped at 251 KB rather than the ~40 KB minified build. Extension load time is unaffected
(it is a local file, parsed once, in a document that only exists during a decode), and in exchange the
code a reviewer reads is the code that runs. Minifying a vendored dependency optimises the dimension
that does not matter here and destroys the one that does.

Audited before committing, each re-checkable with `grep`:

- **no `eval`, no `new Function`** — which is why it satisfies MV3's CSP with no `unsafe-eval`;
- **no network calls** — it is a pure pixels-in, string-out decoder;
- UMD wrapper assigns `self.jsQR`, so `offscreen/offscreen.html` loads it as a classic script and the
  extension's no-build-step rule survives.

### Where it runs, and where it does not

jsQR executes **only** inside `offscreen/offscreen.html`. That document is extension-origin, has no web
page in it, is invisible, and is unreachable from any site. It is created for a decode and closed the
moment the decode finishes — an offscreen document that outlives its work keeps the service worker
resident, turning an occasional right-click into a permanent process.

It is never injected into a website, and the image never leaves the machine: the offscreen document
fetches it, draws it to a canvas, reads the pixels, and sends **only the decoded string** to the
backend. That is the entire privacy argument for the feature. A QR-decoding web service would have
required uploading a screenshot of the user's payment app to check whether it was safe to look at.

### The one thing this cannot decode

`blob:` image URLs are scoped to the document that minted them, so the offscreen document cannot fetch
one. WhatsApp Web, Telegram Web and Gmail all render received images as `blob:` — precisely where a scam
QR code arrives — so `content/qr.js` reads those bytes in-page and hands back a `data:` URL. It is the
only reason that file exists.

### NPCI PSP handle list

`backend/app/services/qr/psp.py` carries ~100 UPI handles (`@okhdfcbank`, `@ybl`, `@paytm`, …) taken by
hand from NPCI's published list of live PSPs and their handles. **No scraping, no runtime fetch, no
API.** It is a Python frozenset in source control.

It is used in one direction only. A recognised handle is weak positive evidence; an **unrecognised**
handle is explicitly *not* treated as proof of fraud — new PSPs launch and this list will always lag —
and the docstring in `psp.py` says so, so nobody later mistakes staleness for a finding.
