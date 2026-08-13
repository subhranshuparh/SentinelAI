/**
 * Local image decoding for the dashboard (Modules 9 & 12).
 *
 * The browser half of the screenshot checker: it turns a file the user dropped
 * into (a) the string a QR code in it contains and (b) the words printed on it.
 * Nothing here judges either result — that is `services/qr/` and
 * `services/pii/`, over the network, in Python.
 *
 * ## The image never leaves this tab
 *
 * `createImageBitmap` on the `File`, a canvas, jsQR, and a WebAssembly build of
 * Tesseract in a worker. No upload, no vision API, no `FormData` anywhere in
 * this directory. A screenshot checker that uploaded the screenshot would be
 * performing the exact act it exists to warn about, and the only way to make
 * that guarantee inspectable is for the code path to have no way to send one.
 *
 * ## Where the engines come from
 *
 * `http://127.0.0.1:8000/vendor/…` — the backend serves the *extension's* own
 * vendored copies read-only. No CDN: the demo has to survive an unplugged
 * network, and a security tool that downloads several megabytes of executable
 * code at runtime cannot claim its binaries were reviewed. The SHA-256 of every
 * file is in `docs/INTEGRATION_NOTES.md`, and because there is exactly one copy
 * on disk, those checksums cover the dashboard and the extension at once.
 *
 * ## One setting differs from the extension, and it matters
 *
 * The extension passes `workerBlobURL: false`; **this file must not**. The two
 * surfaces have opposite constraints:
 *
 *   * In the extension, the assets are same-origin and the manifest CSP
 *     (`script-src 'self'`) refuses to spawn a worker from a `blob:` URL — so
 *     Tesseract has to load `worker.min.js` directly.
 *   * Here, the assets are cross-origin (the dashboard is served by Vite on
 *     :5173, the assets by uvicorn on :8000) and `new Worker(crossOriginUrl)` is
 *     blocked by every browser regardless of CORS. Tesseract's default — fetch
 *     the script, wrap it in a Blob, spawn from that — produces a *same-origin*
 *     blob URL and works. The dashboard has no CSP forbidding it.
 *
 * So the default is correct here and wrong there, which is why it is written
 * down rather than left to whoever reads the two files next. The cross-origin
 * fetches this relies on are covered by the existing `CORS_ALLOW_ORIGINS`:
 * `importScripts` inside the worker is exempt from CORS, and `langPath` is
 * fetched by XHR from the dashboard's own origin list.
 */

import { VENDOR_URL } from '../api/client'

/** 8 MB, matching the extension's cap. Above this the browser stalls visibly,
 *  and a screenshot of a document is never this big. */
export const MAX_IMAGE_BYTES = 8 * 1024 * 1024

/** Refuse absurd dimensions even when the byte count passed: a small, heavily
 *  compressed file can still decode to a gigapixel bitmap. */
const MAX_IMAGE_SIDE = 8000

/** jsQR's cost is linear in pixel count. First pass downscaled, second pass at
 *  native resolution only if that missed — cheapest attempt first. */
const QR_FAST_PASS_MAX_SIDE = 1600

/** OEM 1 = LSTM only; the legacy engine is absent from `tessdata_fast`. */
const OCR_ENGINE_MODE = 1
const OCR_LANG = 'eng'

/** See the extension's offscreen document for the reasoning on all four: OCR
 *  accuracy tracks glyph pixel height, so downscaling costs accuracy — but a
 *  12 MP photo is minutes of CPU for no extra characters, and a 640px card
 *  screenshot has ~10px digits that a 2x upscale materially improves. */
const OCR_MAX_SIDE = 2400
const OCR_UPSCALE_BELOW_SIDE = 1000

/** Matches `MAX_TEXT_LENGTH` in `schemas/pii.py`. */
const OCR_MAX_CHARS = 20_000

/** Mean per-word confidence below which a read is called unreliable — and only
 *  when text was actually found. An image with no glyphs at all is a clean read
 *  of a picture that had nothing to read; flagging those would put a "might
 *  have missed something" warning on most images anybody uploads. */
const OCR_LOW_CONFIDENCE = 55

/** Ceilings on the two things that can hang rather than fail. If the wasm
 *  module never compiles, `createWorker` does not reject — it sits there, and a
 *  spinner that never resolves is indistinguishable from "found nothing". */
const OCR_INIT_TIMEOUT_MS = 40_000
const OCR_RECOGNISE_TIMEOUT_MS = 45_000

/** Machine-readable failure reasons. Never shown raw; `ScreenshotChecker` owns
 *  the sentences, so the same code can read differently in different panels. */
export type ReadFailure =
  | 'engine-unavailable'
  | 'not-an-image'
  | 'too-large'
  | 'unreadable'
  | 'no-qr-found'

export type TextRead =
  | { ok: true; text: string; confidence: number | null; poorRead: boolean }
  | { ok: false; code: ReadFailure }

export type QrRead = { ok: true; payload: string } | { ok: false; code: ReadFailure }

// ---------------------------------------------------------------------------
// Vendored engines
// ---------------------------------------------------------------------------

interface TesseractWorker {
  recognize(image: HTMLCanvasElement): Promise<{ data?: { text?: string; confidence?: number } }>
  terminate(): Promise<void>
}

interface TesseractNamespace {
  createWorker(
    lang: string,
    oem: number,
    options: Record<string, unknown>,
  ): Promise<TesseractWorker>
}

type JsQrFn = (
  data: Uint8ClampedArray,
  width: number,
  height: number,
  options?: { inversionAttempts?: string },
) => { data?: string } | null

declare global {
  interface Window {
    Tesseract?: TesseractNamespace
    jsQR?: JsQrFn
  }
}

/** In-flight and completed script loads, so two dropped files load one copy. */
const scriptLoads = new Map<string, Promise<void>>()

function loadScript(url: string): Promise<void> {
  const existing = scriptLoads.get(url)
  if (existing) return existing

  const pending = new Promise<void>((resolve, reject) => {
    const element = document.createElement('script')
    element.src = url
    element.async = true
    element.onload = () => resolve()
    element.onerror = () => {
      // Forget the failure so a later attempt may retry. A backend that was not
      // running when the page loaded should not disable the panel for the
      // lifetime of the tab.
      scriptLoads.delete(url)
      element.remove()
      reject(new Error('engine-unavailable'))
    }
    document.head.append(element)
  })

  scriptLoads.set(url, pending)
  return pending
}

function withTimeout<T>(promise: Promise<T>, ms: number, code: ReadFailure): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const expiry = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(code)), ms)
  })
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer))
}

// ---------------------------------------------------------------------------
// Pixels
// ---------------------------------------------------------------------------

/** Reused across reads. Creating a canvas per call leaks in a long session. */
let canvas: HTMLCanvasElement | null = null

function ensureCanvas(width: number, height: number): HTMLCanvasElement {
  canvas ??= document.createElement('canvas')
  canvas.width = width
  canvas.height = height
  return canvas
}

/** Release the backing surface. An 8000x8000 canvas held across an idle tab is
 *  256 MB of nothing. */
function shrinkCanvas() {
  if (canvas) {
    canvas.width = 1
    canvas.height = 1
  }
}

async function toBitmap(file: File): Promise<ImageBitmap> {
  if (!file.type.toLowerCase().startsWith('image/')) throw new Error('not-an-image')
  if (file.size === 0) throw new Error('not-an-image')
  if (file.size > MAX_IMAGE_BYTES) throw new Error('too-large')

  let bitmap: ImageBitmap
  try {
    bitmap = await createImageBitmap(file)
  } catch {
    // Rejects on anything that is not a decodable image, including a file whose
    // name and MIME type both claim otherwise.
    throw new Error('not-an-image')
  }

  if (bitmap.width > MAX_IMAGE_SIDE || bitmap.height > MAX_IMAGE_SIDE) {
    bitmap.close()
    throw new Error('too-large')
  }
  return bitmap
}

function failureOf(error: unknown): ReadFailure {
  const code = error instanceof Error ? error.message : ''
  return code === 'engine-unavailable' ||
    code === 'not-an-image' ||
    code === 'too-large' ||
    code === 'no-qr-found'
    ? code
    : 'unreadable'
}

// ---------------------------------------------------------------------------
// Module 9 — QR
// ---------------------------------------------------------------------------

function decodeAt(jsQR: JsQrFn, bitmap: ImageBitmap, scale: number): string | null {
  const width = Math.max(1, Math.round(bitmap.width * scale))
  const height = Math.max(1, Math.round(bitmap.height * scale))

  // willReadFrequently: every use of this canvas is a getImageData. Without it
  // Chrome keeps the surface on the GPU and each read stalls on a readback.
  const context = ensureCanvas(width, height).getContext('2d', { willReadFrequently: true })
  if (context === null) throw new Error('unreadable')

  context.drawImage(bitmap, 0, 0, width, height)
  const pixels = context.getImageData(0, 0, width, height)

  // attemptBoth covers codes printed light-on-dark, common on posters and on the
  // dark-mode screenshots people forward in chat apps.
  const found = jsQR(pixels.data, width, height, { inversionAttempts: 'attemptBoth' })

  // jsQR returns an object with an empty `data` for some partial reads. An empty
  // payload is not a payload.
  return typeof found?.data === 'string' && found.data.length > 0 ? found.data : null
}

/**
 * Decode the first QR code in an image.
 *
 * `no-qr-found` is a real answer — most screenshots contain no QR code, and the
 * caller must be able to tell that from "the picture could not be read".
 */
export async function readQr(file: File): Promise<QrRead> {
  let bitmap: ImageBitmap
  try {
    await loadScript(`${VENDOR_URL}/jsqr.js`)
    bitmap = await toBitmap(file)
  } catch (error) {
    return { ok: false, code: failureOf(error) }
  }

  const jsQR = window.jsQR
  if (typeof jsQR !== 'function') {
    bitmap.close()
    return { ok: false, code: 'engine-unavailable' }
  }

  try {
    const longest = Math.max(bitmap.width, bitmap.height)
    const scales =
      longest > QR_FAST_PASS_MAX_SIDE ? [QR_FAST_PASS_MAX_SIDE / longest, 1] : [1]

    for (const scale of scales) {
      const payload = decodeAt(jsQR, bitmap, scale)
      if (payload !== null) return { ok: true, payload }
    }
    return { ok: false, code: 'no-qr-found' }
  } catch (error) {
    return { ok: false, code: failureOf(error) }
  } finally {
    bitmap.close()
    shrinkCanvas()
  }
}

// ---------------------------------------------------------------------------
// Module 12 — OCR
// ---------------------------------------------------------------------------

let ocrWorker: TesseractWorker | null = null
let ocrWorkerPromise: Promise<TesseractWorker> | null = null

async function ensureOcrWorker(): Promise<TesseractWorker> {
  if (ocrWorker !== null) return ocrWorker
  if (ocrWorkerPromise !== null) return ocrWorkerPromise

  await loadScript(`${VENDOR_URL}/tesseract/tesseract.min.js`)
  const tesseract = window.Tesseract
  if (tesseract === undefined) throw new Error('engine-unavailable')

  ocrWorkerPromise = withTimeout(
    tesseract.createWorker(OCR_LANG, OCR_ENGINE_MODE, {
      workerPath: `${VENDOR_URL}/tesseract/worker.min.js`,
      // A *file*, not a directory. Given a directory Tesseract picks between the
      // SIMD and non-SIMD cores at runtime, and the point of vendoring is that
      // the binary which runs is the binary that was checksummed.
      corePath: `${VENDOR_URL}/tesseract/tesseract-core-simd.wasm.js`,
      langPath: `${VENDOR_URL}/tesseract/`,
      // NOT `workerBlobURL: false` — see this module's docstring. The default is
      // load-bearing here and would break the extension, and vice versa.
      gzip: false,
      // No progress logging. A security tool should not narrate the contents of
      // somebody's Aadhaar card to the browser console.
      logger: () => {},
      errorHandler: () => {},
    }),
    OCR_INIT_TIMEOUT_MS,
    'engine-unavailable',
  )
    .then((worker) => {
      ocrWorker = worker
      return worker
    })
    .catch((error: unknown) => {
      ocrWorkerPromise = null
      throw new Error(failureOf(error) === 'unreadable' ? 'engine-unavailable' : failureOf(error))
    })

  return ocrWorkerPromise
}

/**
 * Tear the engine down.
 *
 * Called when the panel is cleared. A live Tesseract worker is a ~40 MB wasm
 * heap plus a 4 MB language model, and a dashboard that polls every ten seconds
 * is a tab people leave open all day.
 */
export async function releaseOcr(): Promise<void> {
  const worker = ocrWorker
  ocrWorker = null
  ocrWorkerPromise = null
  shrinkCanvas()
  if (worker === null) return
  try {
    await worker.terminate()
  } catch {
    // Nothing the user can act on, and nothing worth surfacing.
  }
}

function prepareForOcr(bitmap: ImageBitmap): HTMLCanvasElement {
  const longest = Math.max(bitmap.width, bitmap.height)
  let scale = 1
  if (longest > OCR_MAX_SIDE) scale = OCR_MAX_SIDE / longest
  else if (longest < OCR_UPSCALE_BELOW_SIDE) scale = 2

  const width = Math.max(1, Math.round(bitmap.width * scale))
  const height = Math.max(1, Math.round(bitmap.height * scale))

  // No willReadFrequently: Tesseract reads this canvas once per image, so the
  // GPU-side surface is faster here — the opposite of the QR path above.
  const target = ensureCanvas(width, height)
  const context = target.getContext('2d')
  if (context === null) throw new Error('unreadable')

  context.imageSmoothingEnabled = true
  context.imageSmoothingQuality = 'high'

  // White under the image. A transparent PNG drawn onto a transparent canvas
  // composites black-on-black and Tesseract reads exactly nothing from it — a
  // silent false negative on one of the most common screenshot formats.
  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, width, height)
  context.drawImage(bitmap, 0, 0, width, height)

  return target
}

/**
 * Read the text printed in an image.
 *
 * `ok: true` with `text: ''` is a real answer — the image was read and carried
 * no recognisable text. It is reported separately from every failure code for
 * the reason this whole codebase is built around: "nothing found" and "could not
 * look" are different statements, and merging them is how a tool starts quietly
 * lying.
 *
 * `poorRead` is the third state between those two: text was found and the
 * recogniser was not confident about it, so a clean verdict on this image is
 * worth less than a clean verdict on a sharp one.
 */
export async function readText(file: File): Promise<TextRead> {
  let bitmap: ImageBitmap
  try {
    bitmap = await toBitmap(file)
  } catch (error) {
    return { ok: false, code: failureOf(error) }
  }

  try {
    const worker = await ensureOcrWorker()
    const target = prepareForOcr(bitmap)

    const { data } = await withTimeout(
      worker.recognize(target),
      OCR_RECOGNISE_TIMEOUT_MS,
      'unreadable',
    )

    const text = typeof data?.text === 'string' ? data.text.trim() : ''
    // Tesseract reports mean word confidence as 0 when it found no words, which
    // is not the same as "confident it is empty". Null keeps the distinction.
    const confidence =
      typeof data?.confidence === 'number' && text.length > 0 ? Math.round(data.confidence) : null

    return {
      ok: true,
      text: text.slice(0, OCR_MAX_CHARS),
      confidence,
      poorRead: confidence !== null && confidence < OCR_LOW_CONFIDENCE,
    }
  } catch (error) {
    return { ok: false, code: failureOf(error) }
  } finally {
    bitmap.close()
    // Release the surface but keep the worker: the next image the user drops
    // still wants it, and rebuilding it costs seconds.
    shrinkCanvas()
  }
}
