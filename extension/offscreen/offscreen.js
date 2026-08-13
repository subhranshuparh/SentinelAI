/**
 * Image decoding, at extension origin, off any page.
 *
 * Two jobs, one document:
 *
 *   * **Module 9** — turn a picture into the string a QR code contains.
 *   * **Module 12** — turn a picture into the words printed on it.
 *
 * Everything about what those strings *mean* happens in the backend
 * (`services/qr/`, `services/pii/`), because a verdict written in JavaScript
 * that ships inside the extension is a verdict anyone can read and route
 * around. This file is a pair of decoders and nothing else: it never scores,
 * never phrases advice, and never talks to the network except to fetch the
 * image it was asked about.
 *
 * The reason both live here is the reason the file is named for its mechanism:
 * a service worker has no `<canvas>`, and a content script runs inside a page
 * that can read anything the extension puts in its DOM. An offscreen document
 * is the only context that is both DOM-capable and page-inaccessible. Sharing
 * one between the two features also means one document to remember to close
 * — an open offscreen document keeps the service worker resident forever.
 *
 * Both decodes are deliberately conservative:
 *
 *   * bytes are capped before they become pixels — a 200 MP image would take
 *     the browser down, and no QR code needs one;
 *   * the response must actually be an image, checked by Content-Type rather
 *     than by the file extension in the URL;
 *   * failure is reported as a *named reason*, never as an empty result. The
 *     caller has to be able to tell "there is no QR code in this picture" from
 *     "the picture could not be read", because the first is an answer and the
 *     second is the absence of one. That distinction is the whole discipline of
 *     this codebase and it does not stop at the network boundary.
 */

/** 8 MB. Same ceiling Module 12 uses for screenshots, for the same reason:
 *  above this the browser stalls visibly, and a QR photo is never this big. */
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

/** Refuse absurd dimensions even if the byte count passed — a small,
 *  highly-compressed file can still decode to a gigapixel bitmap. */
const MAX_IMAGE_SIDE = 8000;

/**
 * First decode pass runs at this longest side.
 *
 * jsQR's cost is linear in pixel count, and a 12 MP phone photo is ~40x more
 * pixels than it needs: a QR code that fills a reasonable part of the frame is
 * still tens of modules wide at 1600px. When the downscale loses it — a small
 * code in a big screenshot — the second pass runs at native resolution. Two
 * attempts, cheapest first, rather than one expensive one.
 */
const FAST_PASS_MAX_SIDE = 1600;

/** Reused across decodes. Creating a canvas per call leaks in long sessions. */
let canvas = null;

function context2d(width, height) {
  if (canvas === null) canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  // willReadFrequently: every single use of this canvas is a getImageData.
  // Without it Chrome keeps the surface on the GPU and each read stalls on a
  // readback.
  return canvas.getContext('2d', { willReadFrequently: true });
}

/**
 * Fetch an image and hand back its pixels.
 *
 * @param {string} source http(s) or data: URL.
 * @returns {Promise<ImageBitmap>}
 * @throws {Error} with a machine-readable `.code`, never a raw network message.
 */
async function loadBitmap(source) {
  let response;
  try {
    // No credentials: an image that only renders when the user's cookies are
    // attached is one this document has no business pulling. Losing those cases
    // is correct — they surface as "could not read", which is honest.
    response = await fetch(source, { credentials: 'omit', cache: 'force-cache' });
  } catch (_error) {
    throw taggedError('unreachable');
  }
  if (!response.ok) throw taggedError('unreachable');

  const type = (response.headers.get('content-type') || '').toLowerCase();
  // data: URLs synthesised by the content script carry their own type, and
  // fetch reports it faithfully. A missing type on an http response is treated
  // as untrusted rather than assumed to be fine.
  if (!type.startsWith('image/')) throw taggedError('not-an-image');

  const blob = await response.blob();
  if (blob.size === 0) throw taggedError('not-an-image');
  if (blob.size > MAX_IMAGE_BYTES) throw taggedError('too-large');

  try {
    const bitmap = await createImageBitmap(blob);
    if (bitmap.width > MAX_IMAGE_SIDE || bitmap.height > MAX_IMAGE_SIDE) {
      bitmap.close();
      throw taggedError('too-large');
    }
    return bitmap;
  } catch (error) {
    // createImageBitmap rejects on anything that is not a decodable image —
    // including an HTML error page served with an image Content-Type.
    throw error.code ? error : taggedError('not-an-image');
  }
}

function taggedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

/**
 * Run jsQR over a bitmap at one scale.
 *
 * @returns {string|null} The decoded payload, or null when no code was found
 *                        at this scale. Null here means "not at this size",
 *                        not "no QR code" — only the caller, having tried every
 *                        scale, is entitled to say that.
 */
function decodeAt(bitmap, scale) {
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));

  const ctx = context2d(width, height);
  ctx.drawImage(bitmap, 0, 0, width, height);
  const pixels = ctx.getImageData(0, 0, width, height);

  // attemptBoth covers codes printed light-on-dark, which is common on posters
  // and on the dark-mode screenshots people forward in chat apps.
  const found = self.jsQR(pixels.data, width, height, { inversionAttempts: 'attemptBoth' });

  // jsQR returns an object with an empty `data` for some partial reads. An
  // empty payload is not a payload.
  return found && typeof found.data === 'string' && found.data.length > 0 ? found.data : null;
}

/**
 * Decode the first QR code in an image.
 *
 * @param {string} source
 * @returns {Promise<{ok: true, payload: string} | {ok: false, code: string}>}
 */
async function decodeQr(source) {
  let bitmap;
  try {
    bitmap = await loadBitmap(source);
  } catch (error) {
    return { ok: false, code: error.code || 'unreachable' };
  }

  try {
    const longest = Math.max(bitmap.width, bitmap.height);
    const scales = longest > FAST_PASS_MAX_SIDE ? [FAST_PASS_MAX_SIDE / longest, 1] : [1];

    for (const scale of scales) {
      let payload;
      try {
        payload = decodeAt(bitmap, scale);
      } catch (_error) {
        // A tainted or oversized canvas. Try the next scale rather than
        // reporting "no QR code found", which would be a claim we cannot make.
        return { ok: false, code: 'unreadable' };
      }
      if (payload !== null) return { ok: true, payload };
    }
    return { ok: false, code: 'no-qr-found' };
  } finally {
    bitmap.close();
    // Release the backing surface. A 8000x8000 canvas held across an idle
    // document is 256 MB of nothing.
    if (canvas) {
      canvas.width = 1;
      canvas.height = 1;
    }
  }
}

// ---------------------------------------------------------------------------
// Module 12 — optical character recognition
// ---------------------------------------------------------------------------
//
// Tesseract's LSTM engine, compiled to WebAssembly, running entirely on this
// machine. The image bytes never leave it. That is not a performance choice:
// the feature exists to stop people sending photographs of their Aadhaar card
// to strangers, and a version of it that posted the photograph to a cloud
// vision API would be doing the exact thing it warns about.
//
// Everything the engine needs is loaded from `chrome.runtime.getURL(...)`, so
// there is no CDN, no version drift, and a reviewer can check the SHA-256 of
// every byte that executes here against docs/INTEGRATION_NOTES.md.

/** Tesseract's own language code. `eng.traineddata` is the vendored model. */
const OCR_LANG = 'eng';

/** OEM 1 = LSTM only. The legacy engine is not in `tessdata_fast` at all, and
 *  asking for a combined mode would fail at load rather than fall back. */
const OCR_ENGINE_MODE = 1;

/**
 * Longest side fed to the recogniser.
 *
 * Unlike the QR path, downscaling here is a *cost* — OCR accuracy tracks the
 * pixel height of the glyphs. But a 12 MP phone photo is minutes of CPU for no
 * extra characters, because at that size the text is already far above the
 * ~20px x-height the LSTM wants. 2400 is the compromise: a full-page A4 scan
 * still lands near 300 DPI.
 */
const OCR_MAX_SIDE = 2400;

/**
 * Below this, the image is doubled before recognition.
 *
 * A 640px-wide screenshot of a card has ~10px digits, which Tesseract reads
 * badly and inconsistently. Bicubic upscaling adds no information, but it does
 * give the LSTM's convolutions something to work with, and it is the single
 * cheapest accuracy win available here. Module 12's whole point is reading
 * *small* text in *low-resolution* screenshots, so this matters more than it
 * looks.
 */
const OCR_UPSCALE_BELOW_SIDE = 1000;

/** Matches the backend's own text ceiling. A page of prose is ~3,000 chars; the
 *  cap only ever bites on a scanned document, where the first 20k is plenty. */
const OCR_MAX_CHARS = 20000;

/**
 * Ceilings, in ms, on the two things that can hang rather than fail.
 *
 * If MV3's CSP ever refuses to compile the wasm module, `createWorker` does not
 * reject — it sits there. Without these the user would watch a spinner until
 * they gave up, and "the tool hung" is indistinguishable from "the tool found
 * nothing". A named timeout turns both into `engine-unavailable`, which the UI
 * can honestly report.
 */
const OCR_INIT_TIMEOUT_MS = 25000;
const OCR_RECOGNISE_TIMEOUT_MS = 30000;

/**
 * Mean per-word confidence, 0-100, below which a read is called unreliable.
 *
 * Reported upward rather than acted on here. A poor read that found nothing must
 * not be presented as "no sensitive data in this image" — that is the one
 * sentence this feature is not entitled to say about a blurry photograph.
 *
 * The threshold only applies when text *was* recognised. An image with no glyphs
 * at all — a photograph of a face, a logo, a chart — is a clean read of a
 * picture that had nothing to read, and flagging those as unreliable would put a
 * "might have missed something" warning on most of the images anybody uploads.
 * Over-alerting is the failure mode this whole UI is written against.
 */
const OCR_LOW_CONFIDENCE = 55;

/** Its own canvas, not the QR one. The QR path shrinks its canvas to 1x1 in a
 *  `finally` to release the surface; sharing would mean one feature's cleanup
 *  could land in the middle of the other's recognise call. */
let ocrCanvas = null;

/**
 * The Tesseract worker, created once per offscreen document and reused.
 *
 * Initialisation costs ~2-4 seconds: 4.7 MB of wasm to compile and 4 MB of
 * language model to parse. Paying that per image would make checking a
 * three-file upload feel broken, so the worker outlives a single request and
 * the *document* is the lifetime boundary. The service worker holds the
 * document open for one user action and closes it after, which is the right
 * granularity — long enough to batch, short enough that an idle browser is not
 * keeping a wasm heap alive.
 */
let ocrWorker = null;
/** In-flight init, so two images arriving together create one worker. */
let ocrWorkerPromise = null;

/**
 * Reject instead of hanging.
 *
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} code Machine-readable reason for the timeout.
 * @returns {Promise<T>}
 * @template T
 */
function withTimeout(promise, ms, code) {
  let timer = null;
  const expiry = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(taggedError(code)), ms);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Create the OCR worker, or reuse the existing one.
 *
 * Every path option here is load-bearing under MV3, and each one was a failure
 * before it was a setting:
 *
 *   * `workerBlobURL: false` — Tesseract's default is to fetch its worker
 *     script, wrap it in a Blob, and spawn the worker from a `blob:` URL.
 *     The extension CSP (`script-src 'self'`) refuses that outright. This
 *     option makes it load `worker.min.js` directly from the extension origin.
 *   * `gzip: false` — otherwise it appends `.gz` to the language path and asks
 *     for `eng.traineddata.gz`, which is not the file that was vendored or
 *     checksummed.
 *   * `corePath` names a *file*, not a directory. Given a directory, Tesseract
 *     picks between the SIMD and non-SIMD cores at runtime; naming the file
 *     guarantees the binary that runs is the binary in INTEGRATION_NOTES.md.
 *   * `logger` is a no-op. The default writes a progress line per percent, and
 *     a security tool should not be narrating the contents of someone's
 *     Aadhaar card to a console log.
 *
 * @returns {Promise<object>} A Tesseract worker.
 * @throws {Error} tagged `engine-unavailable`.
 */
async function ensureOcrWorker() {
  if (ocrWorker !== null) return ocrWorker;
  if (ocrWorkerPromise !== null) return ocrWorkerPromise;

  const asset = (name) => chrome.runtime.getURL(`lib/vendor/tesseract/${name}`);

  ocrWorkerPromise = withTimeout(
    self.Tesseract.createWorker(OCR_LANG, OCR_ENGINE_MODE, {
      workerPath: asset('worker.min.js'),
      corePath: asset('tesseract-core-simd.wasm.js'),
      langPath: chrome.runtime.getURL('lib/vendor/tesseract/'),
      workerBlobURL: false,
      gzip: false,
      logger: () => {},
      errorHandler: () => {},
    }),
    OCR_INIT_TIMEOUT_MS,
    'engine-unavailable',
  )
    .then((worker) => {
      ocrWorker = worker;
      return worker;
    })
    .catch((error) => {
      // Clear the cached promise so a later attempt is allowed to retry: a
      // one-off failure here should not disable the feature for the session.
      ocrWorkerPromise = null;
      throw error.code ? error : taggedError('engine-unavailable');
    });

  return ocrWorkerPromise;
}

/**
 * Release the wasm heap and the language model.
 *
 * Called explicitly by the service worker before it closes this document, and
 * again on `pagehide` as a backstop. Terminating twice is harmless; leaking a
 * worker is a ~40 MB heap that outlives the reason it existed.
 */
async function releaseOcrWorker() {
  const worker = ocrWorker;
  ocrWorker = null;
  ocrWorkerPromise = null;
  if (ocrCanvas) {
    ocrCanvas.width = 1;
    ocrCanvas.height = 1;
  }
  if (worker === null) return;
  try {
    await worker.terminate();
  } catch (_error) {
    // The document is going away regardless. A failure to tear down cleanly is
    // not something the user can act on and not something worth surfacing.
  }
}

/**
 * Draw a bitmap onto the OCR canvas at a size the recogniser can work with.
 *
 * @param {ImageBitmap} bitmap
 * @returns {HTMLCanvasElement}
 */
function prepareForOcr(bitmap) {
  const longest = Math.max(bitmap.width, bitmap.height);
  let scale = 1;
  if (longest > OCR_MAX_SIDE) scale = OCR_MAX_SIDE / longest;
  else if (longest < OCR_UPSCALE_BELOW_SIDE) scale = 2;

  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));

  if (ocrCanvas === null) ocrCanvas = document.createElement('canvas');
  ocrCanvas.width = width;
  ocrCanvas.height = height;

  // No willReadFrequently: Tesseract reads this canvas once per image, so the
  // GPU-side surface is the faster choice here — the opposite of the QR path,
  // which does a getImageData per scale.
  const ctx = ocrCanvas.getContext('2d');
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';

  // White under the image. A transparent PNG drawn onto a transparent canvas
  // composites black-on-black, and Tesseract reads exactly nothing from it —
  // a silent false negative on a very common screenshot format.
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(bitmap, 0, 0, width, height);

  return ocrCanvas;
}

/**
 * Read the text printed in an image.
 *
 * @param {string} source data: or http(s) URL.
 * @returns {Promise<
 *   {ok: true, text: string, confidence: number|null, poorRead: boolean}
 *   | {ok: false, code: string}
 * >}
 *
 * `ok: true` with `text: ''` is a real answer — the image was read and carried
 * no recognisable text. It is reported separately from every `ok: false` code
 * for the reason this whole codebase is built around: "nothing found" and
 * "could not look" are different statements and merging them is how a tool
 * starts quietly lying.
 *
 * `poorRead` is the third state between those two: text was found and the
 * recogniser was not confident about it, so a clean verdict on this image is
 * worth less than a clean verdict on a sharp one. It is false when there was no
 * text at all — see OCR_LOW_CONFIDENCE.
 */
async function ocrImage(source) {
  let bitmap;
  try {
    bitmap = await loadBitmap(source);
  } catch (error) {
    return { ok: false, code: error.code || 'unreachable' };
  }

  try {
    const worker = await ensureOcrWorker();
    const target = prepareForOcr(bitmap);

    const { data } = await withTimeout(
      worker.recognize(target),
      OCR_RECOGNISE_TIMEOUT_MS,
      'unreadable',
    );

    const text = typeof data?.text === 'string' ? data.text.trim() : '';
    // Tesseract reports mean word confidence as 0 when it found no words, which
    // is not the same as "confident it is empty". Null keeps the distinction.
    const confidence = typeof data?.confidence === 'number' && text.length > 0
      ? Math.round(data.confidence)
      : null;

    return {
      ok: true,
      text: text.slice(0, OCR_MAX_CHARS),
      confidence,
      poorRead: confidence !== null && confidence < OCR_LOW_CONFIDENCE,
    };
  } catch (error) {
    return { ok: false, code: error.code || 'unreadable' };
  } finally {
    bitmap.close();
    if (ocrCanvas) {
      // Release the surface but keep the worker: the next image in this batch
      // still wants it.
      ocrCanvas.width = 1;
      ocrCanvas.height = 1;
    }
  }
}

// A closing offscreen document does not run `finally` blocks. This is the only
// hook that fires on `chrome.offscreen.closeDocument()`.
self.addEventListener('pagehide', () => {
  void releaseOcrWorker();
});

// ---------------------------------------------------------------------------
// Message plumbing
// ---------------------------------------------------------------------------

/**
 * chrome.runtime.sendMessage broadcasts to *every* extension context, so the
 * service worker's own listener and this one both see every message. The
 * `target` field is how each decides the message was meant for it. Without it
 * the two listeners race to call sendResponse and one of them wins arbitrarily.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target !== 'sentinel-offscreen') return false;
  // Belt and braces: an offscreen document is not reachable from a web page,
  // but it is reachable from another extension that guessed the id, and this
  // one will fetch a URL of the sender's choosing.
  if (sender.id !== chrome.runtime.id) return false;

  if (message.type === 'decode-qr') {
    const source = message.payload?.source;
    if (typeof source !== 'string' || source.length === 0) {
      sendResponse({ ok: false, code: 'unreachable' });
      return false;
    }
    decodeQr(source).then(sendResponse);
    return true; // async reply
  }

  if (message.type === 'ocr-image') {
    const source = message.payload?.source;
    if (typeof source !== 'string' || source.length === 0) {
      sendResponse({ ok: false, code: 'unreachable' });
      return false;
    }
    // No .catch: ocrImage is total — every failure path inside it returns a
    // tagged {ok: false}. If that ever stops being true the response never
    // arrives and the caller's own timeout reports it, which is preferable to
    // a catch here that would flatten a bug into "unreadable".
    ocrImage(source).then(sendResponse);
    return true;
  }

  if (message.type === 'ocr-release') {
    releaseOcrWorker().then(() => sendResponse({ ok: true }));
    return true;
  }

  return false;
});
