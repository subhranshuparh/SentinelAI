/**
 * The dashboard's only network code.
 *
 * One endpoint, one round trip — see the module docstring on
 * `schemas/dashboard.py` for why. That decision pays off here: this file has no
 * request orchestration, no partial-failure matrix, and no cascade of loading
 * states to reconcile.
 */

import type {
  AssistantResponse,
  DashboardSummary,
  EmailAnalysis,
  QrCheck,
  ReviewAnalysisResponse,
  ScanResult,
} from '../types'

/**
 * API base URL resolution:
 *
 * LOCAL DEV (Vite dev server, backend on port 8000):
 *   VITE_API_BASE is not set → falls back to 'http://127.0.0.1:8000'
 *   `127.0.0.1` rather than `localhost` on purpose. On Windows, `localhost`
 *   resolves to `::1` first, and uvicorn bound to IPv4 refuses it — which
 *   surfaces as an unexplained connection error that costs twenty minutes.
 *
 * RAILWAY (single service — backend serves the compiled SPA):
 *   Set VITE_API_BASE="" (empty string) in Railway env vars.
 *   Empty BASE_URL makes all fetch calls use relative paths (/api/v1/...)
 *   which resolve to the Railway-assigned domain automatically.
 *   No hardcoded URL, no CORS issue, works on any Railway subdomain.
 *
 *   Set VITE_API_BASE="https://your-backend.railway.app" in Vercel env vars.
 */
export const BASE_URL =
  import.meta.env.VITE_API_BASE !== undefined && import.meta.env.VITE_API_BASE !== ''
    ? import.meta.env.VITE_API_BASE
    : import.meta.env.DEV
      ? 'http://127.0.0.1:8000'
      : ''

/**
 * Build a valid URL object for API requests whether BASE_URL is set, relative, or in dev.
 */
export function buildApiUrl(path: string): URL {
  if (BASE_URL) {
    return new URL(path, BASE_URL)
  }
  if (typeof window !== 'undefined' && window.location?.origin) {
    return new URL(path, window.location.origin)
  }
  return new URL(path, 'http://127.0.0.1:8000')
}

/**
 * Where the vendored OCR and QR engines are served from (Modules 9 & 12).
 *
 * The backend mounts the *extension's* copy of these binaries read-only — see
 * the mount in `backend/app/main.py` for why that beats both an npm dependency
 * and a duplicated 9 MB in `public/`. The short version: one set of bytes on
 * disk, one set of checksums in `docs/INTEGRATION_NOTES.md`, no CDN fetch, and
 * the dashboard demonstrably runs the same engine as the extension.
 */
export const VENDOR_URL = BASE_URL ? `${BASE_URL}/vendor` : '/vendor'


/**
 * A slow backend must not hang the screen forever with no way out. `fetch` has
 * no default timeout, so an unreachable host can leave a skeleton on screen
 * indefinitely — the user cannot tell that from "still loading".
 */
const TIMEOUT_MS = 10_000

/**
 * The email check gets its own, longer budget. It may wait on a Gemini call that
 * is allowed 12 seconds server-side, and aborting at 10 would kill analyses the
 * backend was about to return — showing "timed out" for a request that
 * succeeded is worse than waiting three more seconds.
 */
const ANALYZE_TIMEOUT_MS = 20_000

/**
 * The screenshot checker's budget.
 *
 * Longer than either of the above, and not because the request is slow. The user
 * has already waited several seconds for a local OCR pass by the time this is
 * sent, and the recognised text can be a whole page — long enough to open the
 * Tier 2 gate server-side, which is a Gemini call with a 12-second allowance of
 * its own. Aborting at 10 would report "timed out" for scans that were about to
 * come back with an Aadhaar number in them.
 */
const SCAN_TIMEOUT_MS = 25_000

/** Matches `MAX_TEXT_LENGTH` in `schemas/pii.py`. Truncating client-side turns a
 *  422 on a dense page of text into a slightly shortened, still useful check. */
const MAX_SCAN_CHARS = 20_000

/** Matches `MAX_PAYLOAD_CHARS` in `services/qr/parse.py`, which is QR's own
 *  alphanumeric capacity — a longer string did not come from a real code. */
const MAX_QR_CHARS = 4_500

export class ApiError extends Error {
  /** Present when the server answered; absent when it was unreachable. */
  readonly status?: number

  // Written out rather than using a constructor parameter property: the Vite
  // template sets `erasableSyntaxOnly`, acquisition TS-only syntax that has no
  // JavaScript equivalent to strip.
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export async function fetchSummary(deviceId?: string): Promise<DashboardSummary> {
  const url = buildApiUrl('/api/v1/dashboard/summary')
  if (deviceId) url.searchParams.set('device_id', deviceId)

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)

  let response: Response
  try {
    response = await fetch(url, { signal: controller.signal })
  } catch (error) {
    // Distinguish the two failures the user can actually act on. "Timed out"
    // means retry; "could not reach" means start the backend. A single generic
    // "something went wrong" leaves them with nothing to do.
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError('The backend took too long to answer.')
    }
    throw new ApiError('Could not reach the SentinelAI backend.')
  } finally {
    clearTimeout(timer)
  }

  if (response.status === 404) {
    // Not an error condition — it is the documented "no history yet" answer.
    // Given its own status so the UI shows an onboarding state, not a red box.
    throw new ApiError('No activity recorded yet.', 404)
  }

  if (!response.ok) {
    throw new ApiError(`The backend returned an error (${response.status}).`, response.status)
  }

  return (await response.json()) as DashboardSummary
}

/**
 * The one POST path, shared by every panel the user drives with a button.
 *
 * All three of them throw rather than returning null, unlike a failed poll: they
 * run because somebody pressed something and is watching a spinner. "Could not
 * check" has to reach the screen — a silent failure would leave the *previous*
 * verdict on display, which is the one outcome here that could get a user
 * phished by a stale green box.
 *
 * `messages` is per-caller because generic copy is useless copy. "That email was
 * too long, paste the important part" tells the user what to do next; "422
 * Unprocessable Entity" does not, and neither does "something went wrong".
 */
async function postJson<T>(
  path: string,
  body: unknown,
  options: {
    timeoutMs: number
    /** Extra headers. Used only to carry the device id — see `scanText`. */
    headers?: Record<string, string>
    messages: { timeout: string } & Partial<Record<number, string>>
  },
): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), options.timeoutMs)

  let response: Response
  try {
    response = await fetch(buildApiUrl(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...options.headers },
      signal: controller.signal,
      body: JSON.stringify(body),
    })
  } catch (error) {
    // Distinguish the two failures the user can actually act on. "Timed out"
    // means retry; "could not reach" means start the backend. A single generic
    // "something went wrong" leaves them with nothing to do.
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError(options.messages.timeout)
    }
    throw new ApiError('Could not reach the SentinelAI backend.')
  } finally {
    clearTimeout(timer)
  }

  if (!response.ok) {
    const specific = options.messages[response.status]
    throw new ApiError(
      specific ?? `The backend returned an error (${response.status}).`,
      response.status,
    )
  }

  return (await response.json()) as T
}

/**
 * Send one pasted email for analysis (Module 3).
 *
 * Nothing sent here is stored by the backend. See `routers/phishing.py`.
 */
export function analyzeEmail(input: {
  body: string
  sender?: string
  reply_to?: string
  subject?: string
}): Promise<EmailAnalysis> {
  return postJson<EmailAnalysis>('/api/v1/phishing/analyze', input, {
    timeoutMs: ANALYZE_TIMEOUT_MS,
    messages: {
      timeout: 'The check took too long. Try again with a shorter email.',
      429: 'Too many checks in a row. Wait a few seconds and try again.',
      422: 'That email was too long to check. Paste the important part.',
    },
  })
}

/**
 * Scan text recognised from an image for sensitive information (Module 12).
 *
 * The image is **not** an argument here and there is no version of this function
 * that takes one. Recognition happened in the browser, in a worker, against a
 * WebAssembly build served from this same host; what crosses the network is the
 * transcript. A screenshot checker that uploaded the screenshot would be
 * performing the exact act it exists to prevent.
 *
 * `deviceId` is required rather than optional, and the caller passes the id the
 * dashboard is currently *displaying* (`summary.device_id`). Two reasons: the
 * endpoint is rate-limited per device and refuses an anonymous caller, and a
 * finding recorded against some freshly-invented id would never appear in the
 * timeline on screen — the user would see "Aadhaar found" in the panel and an
 * unchanged score above it, which reads as a broken product.
 */
export function scanText(input: { text: string; deviceId: string }): Promise<ScanResult> {
  return postJson<ScanResult>(
    '/api/v1/pii/scan',
    {
      text: input.text.slice(0, MAX_SCAN_CHARS),
      // The dashboard's own origin, which is the literal truth: this text was
      // submitted from this page. The origin field is persisted, and guessing at
      // the site the screenshot came *from* would be inventing provenance the
      // browser never gave us.
      site_origin: window.location.origin,
      field_kind: 'image',
      // The flag that permits `ocr_normalise` to repair a misread digit, and
      // only where a checksum can confirm the repair. Sending 'typed' here would
      // silently disable the correction this whole panel depends on.
      source: 'ocr',
      suppressed_types: [],
    },
    {
      timeoutMs: SCAN_TIMEOUT_MS,
      headers: { 'X-Sentinel-Device-Id': input.deviceId },
      messages: {
        timeout: 'The check took too long. Try a smaller or clearer image.',
        401: 'SentinelAI could not identify this device, so nothing was checked.',
        429: 'Too many checks in a row. Wait a few seconds and try again.',
        422: 'There was too much text in that image to check.',
      },
    },
  )
}

/**
 * Check one decoded QR payload (Module 9).
 *
 * As above: the decoding is local and only the resulting string is sent. Note
 * that this endpoint *may* write a `SiteCheck` row — a QR that resolves to a URL
 * is a site the device has now looked at, so it feeds Browsing. A UPI payload
 * has no domain and writes nothing rather than a fabricated row.
 */
export function checkQr(input: { payload: string; deviceId: string }): Promise<QrCheck> {
  return postJson<QrCheck>(
    '/api/v1/qr/check',
    { payload: input.payload.slice(0, MAX_QR_CHARS), source_url: window.location.origin },
    {
      timeoutMs: ANALYZE_TIMEOUT_MS,
      headers: { 'X-Sentinel-Device-Id': input.deviceId },
      messages: {
        timeout: 'Checking where that code goes took too long.',
        401: 'SentinelAI could not identify this device, so nothing was checked.',
        429: 'Too many checks in a row. Wait a few seconds and try again.',
        422: 'That code held more data than a scannable QR code can.',
      },
    },
  )
}

/**
 * Analyze a set of product reviews for manipulation tells (Module 5).
 */
export function analyzeReviews(input: {
  reviews: Array<{ body: string; rating?: number }>
  productTitle?: string
}): Promise<ReviewAnalysisResponse> {
  return postJson<ReviewAnalysisResponse>(
    '/api/v1/review/analyze',
    {
      reviews: input.reviews,
      product_title: input.productTitle,
    },
    {
      timeoutMs: ANALYZE_TIMEOUT_MS,
      messages: {
        timeout: 'Review analysis took too long to complete.',
        429: 'Too many checks in a row. Wait a moment and try again.',
        422: 'Invalid review payload submitted.',
      },
    },
  )
}

/**
 * Ask a question or inquire about security posture (Module 7).
 */
export function askAssistant(input: {
  question: string
  deviceId?: string
}): Promise<AssistantResponse> {
  return postJson<AssistantResponse>(
    '/api/v1/assistant/ask',
    {
      question: input.question,
      device_id: input.deviceId,
    },
    {
      timeoutMs: TIMEOUT_MS,
      messages: {
        timeout: 'The assistant took too long to answer.',
        429: 'Too many requests in a row. Wait a moment and try again.',
      },
    },
  )
}
