# Vendored third-party code

Everything in this directory is a **pinned copy** of a published library, committed
verbatim. Nothing here is fetched at runtime.

That is a deliberate constraint rather than a packaging convenience:

- **Manifest V3 forbids it anyway.** The extension CSP is `script-src 'self'`, so a
  `<script src="https://cdn…">` would simply not execute.
- **Remote code in a security tool is indefensible.** An extension that downloads and
  runs code at scan time can be given different code tomorrow, by whoever controls the
  CDN, without the user reinstalling anything. The whole point of this product is
  telling people what is safe to trust.
- **A reviewer must be able to check.** Every file's SHA-256 is in
  `CHECKSUMS.sha256` and in `docs/INTEGRATION_NOTES.md`, and `run.sh` verifies them
  on startup. Verify by hand at any time:

  ```bash
  cd extension/lib/vendor && sha256sum -c CHECKSUMS.sha256
  ```

## Contents

| File | Library | Version | Licence | Used by |
|---|---|---|---|---|
| `jsqr.js` | [jsQR](https://github.com/cozmo/jsQR) | 1.4.0 | Apache-2.0 | Module 9 — QR scam detection |
| `tesseract/tesseract.min.js` | [tesseract.js](https://github.com/naptha/tesseract.js) | 5.1.1 | Apache-2.0 | Module 12 — screenshot OCR |
| `tesseract/worker.min.js` | tesseract.js | 5.1.1 | Apache-2.0 | Module 12 |
| `tesseract/tesseract-core-simd.wasm.js` | [tesseract.js-core](https://github.com/naptha/tesseract.js-core) | 5.1.1 | Apache-2.0 | Module 12 |
| `tesseract/eng.traineddata` | [tessdata_fast](https://github.com/tesseract-ocr/tessdata_fast) | 4.1.0 | Apache-2.0 | Module 12 |

### jsqr.js

Downloaded from `https://unpkg.com/jsqr@1.4.0/dist/jsQR.js`.

Kept **unminified** on purpose. It is 251 KB rather than ~40 KB, which costs nothing at
extension load time, and in exchange the code a reviewer audits is the code that runs.
Minifying a vendored dependency in a security tool optimises the one dimension that does
not matter here and destroys the one that does.

Audited properties, re-checkable with `grep`:

- no `eval` and no `new Function` — it satisfies MV3's CSP without `unsafe-eval`;
- no network access of any kind; it is a pure pixels-in, string-out decoder;
- UMD wrapper assigns `self.jsQR`, which is why `offscreen.html` can load it as a plain
  classic script with no build step.

It runs **only** inside `offscreen/offscreen.html` — an extension-origin document with no
page in it. It is never injected into a website.

### tesseract/

Tesseract's LSTM recogniser, compiled to WebAssembly. Downloaded from:

```
https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js
https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js
https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.1/tesseract-core-simd.wasm.js
https://github.com/tesseract-ocr/tessdata_fast/raw/4.1.0/eng.traineddata
```

Minified, unlike `jsqr.js`, and that asymmetry is deliberate rather than an
oversight. jsQR is 250 KB of readable JavaScript a reviewer can genuinely audit;
`tesseract-core-simd.wasm.js` is a 4.7 MB Emscripten bundle with the wasm binary
embedded as a base64 `data:` URI, and there is no version of it a human reads.
Shipping the unminified sources would have grown the repository without adding a
single reviewable line. What *is* reviewable is the checksum — these four files
are byte-identical to the published releases above, and `sha256sum -c` proves it.

There is no separate `.wasm` file to fetch or verify: the binary lives inside
`tesseract-core-simd.wasm.js`, so the checksum on that file covers it.

**`tessdata_fast`, not `tessdata_best`.** The fast model is 4 MB against 15 MB
and roughly three times quicker, at a small accuracy cost on unusual fonts. For
reading the printed digits on an Aadhaar card or a bank statement that trade is
clearly right — and Module 12 never trusts a bare read anyway: a corrected digit
is only accepted when a checksum confirms it (`services/pii/ocr_normalise.py`).

Two settings differ between the two places these files run, and getting either
backwards breaks that surface silently:

| | Extension (offscreen document) | Dashboard (`lib/imageScan.ts`) |
|---|---|---|
| Assets served from | `chrome.runtime.getURL(...)` | `http://127.0.0.1:8000/vendor/...` |
| `workerBlobURL` | **`false`** | **default (`true`)** |

The extension's CSP is `script-src 'self' 'wasm-unsafe-eval'`, which refuses a
`blob:` worker — so Tesseract must load `worker.min.js` directly, which it can,
because the file is same-origin there. The dashboard has the opposite problem:
the assets are cross-origin (Vite on :5173, uvicorn on :8000) and
`new Worker(crossOriginUrl)` is blocked by every browser regardless of CORS, so
the default blob wrapper — which produces a *same-origin* blob URL — is the only
thing that works. `'wasm-unsafe-eval'` is required in the manifest for the same
underlying reason: compiling a WebAssembly module counts as code generation.

Both surfaces pass `gzip: false`. Without it Tesseract appends `.gz` and asks for
`eng.traineddata.gz`, which is not the file that was vendored or checksummed.
