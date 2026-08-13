/**
 * Modules 9 & 12 — drop a screenshot, find out what is in it.
 *
 * The dashboard half of the screenshot guard, and the plan's stated fallback for
 * it: if MV3 ever refuses to compile the Tesseract wasm module inside the
 * extension, this panel still demonstrates the entire capability, because it
 * runs the identical binaries (see `lib/imageScan.ts`).
 *
 * It does two things to one image in one pass:
 *
 *   1. **Reads the printed text** and sends only that text to `/pii/scan` with
 *      `source: "ocr"`, which is the flag that permits a misread digit to be
 *      repaired — but only where a checksum can confirm the repair.
 *   2. **Decodes any QR code** and asks `/qr/check` where it actually goes.
 *      Most screenshots have no QR code, and "no QR code in this image" is
 *      printed as an answer rather than left as silence.
 *
 * ## Three rules this panel is built around
 *
 * **The image does not leave the tab.** Recognition and decoding are local; the
 * transcript is what crosses the network. There is no code path here that could
 * upload the file, which is the only form of that promise worth making.
 *
 * **The caveat is on every result, including the clean one.** The extension is
 * silent when it finds nothing, and silence there is honest because silence is
 * its default state. Here the user asked a direct question, so an answer of "no
 * sensitive details found" is a *claim* — and it is a claim about an OCR pass
 * that can miss handwriting, a low-resolution photo, or a rotated card. The
 * sentence saying so is declared once, below, so it cannot end up attached to
 * the alarming results and quietly missing from the reassuring one.
 *
 * **Nothing recognised is rendered as markup.** The text comes off an image a
 * stranger may have sent. React escapes by default and nothing here uses
 * `dangerouslySetInnerHTML`; the masked previews and evidence excerpts in
 * particular are deliberately plain text.
 */

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

import { ApiError, checkQr, scanText } from '../api/client'
import { MAX_IMAGE_BYTES, readQr, readText, releaseOcr } from '../lib/imageScan'
import type { ReadFailure, QrRead, TextRead } from '../lib/imageScan'
import type { Finding, QrCheck, QrSignal, ScanResult, SignalWeight, Verdict } from '../types'
import { RISK_STYLES, VERDICT_STYLES } from '../theme'
import { Panel } from './states'

/**
 * The sentence that makes silence safe to print. One declaration, attached to
 * every outcome — see the module docstring.
 */
const OCR_CAVEAT =
  'SentinelAI reads screenshots as text and can miss handwriting or low-resolution images.'

/** Why a read failed, in words the user can act on. */
const READ_FAILURE_COPY: Record<ReadFailure, string> = {
  'engine-unavailable':
    'SentinelAI could not load its local text reader. It is served by the backend — check that the backend is running, then try again.',
  'not-an-image': 'That file is not an image SentinelAI knows how to read.',
  'too-large': 'That image is larger than 8 MB, which is more than SentinelAI will open.',
  unreadable: 'SentinelAI could not read that image.',
  // Never rendered. "No QR code here" is an answer, not a failure, and it is
  // printed as one below.
  'no-qr-found': 'No QR code was found in this image.',
}

/** Marker per signal weight. Glyph *and* colour — never colour alone. */
const WEIGHT_MARK: Record<SignalWeight, { glyph: string; className: string; label: string }> = {
  bad: { glyph: '!', className: 'bg-red-500/15 text-red-300', label: 'Problem found' },
  good: { glyph: '✓', className: 'bg-emerald-500/15 text-emerald-300', label: 'Checked, clean' },
  unknown: { glyph: '?', className: 'bg-slate-500/15 text-slate-400', label: 'Could not check' },
}

const QR_VERDICT_HEADLINE: Record<Verdict, string> = {
  dangerous: 'Do not scan this code',
  suspicious: 'This code is worth a second look',
  safe: 'Nothing wrong with where this code goes',
  unknown: 'Where this code goes could not be checked',
}

/** What the panel is doing right now. Named stages rather than one spinner: the
 *  OCR pass can take several seconds and a user watching a bar with no label
 *  assumes it has hung. */
type Stage = 'reading' | 'recognising' | 'checking'

const STAGE_COPY: Record<Stage, string> = {
  reading: 'Opening the image…',
  recognising: 'Reading the text in it…',
  checking: 'Checking what it found…',
}

interface Outcome {
  fileName: string
  /** Local `blob:` URL for the thumbnail. Revoked when the panel is cleared. */
  previewUrl: string | null
  read: TextRead
  qr: QrRead
  /** The backend's verdict on the recognised text. Null when there was no text
   *  to send, or when the request itself failed — `scanError` says which. */
  scan: ScanResult | null
  scanError: string | null
  qrCheck: QrCheck | null
  qrError: string | null
}

export function ScreenshotChecker({ deviceId }: { deviceId: string | null }) {
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [stage, setStage] = useState<Stage | null>(null)
  const [dragging, setDragging] = useState(false)

  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  /** Guards the async gap: a user who drops one file and then another must not
   *  get the first file's verdict rendered under the second file's name. */
  const token = useRef(0)
  /** Revoked on unmount as well as on replace — a blob URL outlives the state
   *  that referenced it. */
  const previewRef = useRef<string | null>(null)

  useEffect(() => {
    return () => {
      if (previewRef.current) URL.revokeObjectURL(previewRef.current)
      // A live Tesseract worker is a ~40 MB wasm heap plus a 4 MB model, and this
      // is a tab people leave open all day.
      void releaseOcr()
    }
  }, [])

  function reset() {
    token.current += 1
    if (previewRef.current) {
      URL.revokeObjectURL(previewRef.current)
      previewRef.current = null
    }
    setOutcome(null)
    setStage(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  async function handle(file: File) {
    if (deviceId === null) return

    const mine = ++token.current
    const current = () => token.current === mine

    // Cleared before the work starts, not after it. A previous "nothing found"
    // sitting next to a new screenshot for the several seconds an OCR pass takes
    // is the one failure mode here that could actively mislead someone.
    if (previewRef.current) URL.revokeObjectURL(previewRef.current)
    previewRef.current = null
    setOutcome(null)
    setStage('reading')

    const previewUrl = file.size <= MAX_IMAGE_BYTES ? URL.createObjectURL(file) : null
    previewRef.current = previewUrl

    // QR first: it is milliseconds against the OCR pass's seconds, so the cheap
    // answer is already in hand by the time the expensive one starts.
    const qr = await readQr(file)
    if (!current()) return

    setStage('recognising')
    const read = await readText(file)
    if (!current()) return

    setStage('checking')

    let scan: ScanResult | null = null
    let scanError: string | null = null
    if (read.ok && read.text.length > 0) {
      try {
        scan = await scanText({ text: read.text, deviceId })
      } catch (caught) {
        scanError =
          caught instanceof ApiError
            ? caught.message
            : 'Something went wrong checking the text in that image.'
      }
    }

    let qrCheck: QrCheck | null = null
    let qrError: string | null = null
    if (qr.ok) {
      try {
        qrCheck = await checkQr({ payload: qr.payload, deviceId })
      } catch (caught) {
        qrError =
          caught instanceof ApiError
            ? caught.message
            : 'Something went wrong checking where that code goes.'
      }
    }

    if (!current()) return
    setOutcome({ fileName: file.name, previewUrl, read, qr, scan, scanError, qrCheck, qrError })
    setStage(null)
  }

  function accept(files: FileList | null) {
    const file = files?.[0]
    if (!file) return
    // One image at a time, deliberately. A queue would need its own progress
    // model and a partial-failure story, and the panel exists to demonstrate a
    // capability the extension already applies to a whole upload.
    void handle(file)
  }

  const busy = stage !== null

  return (
    <Panel title="Check a screenshot">
      <p className="mb-4 max-w-2xl text-sm leading-relaxed text-slate-400">
        Drop a screenshot before you send it to anyone. SentinelAI reads the text printed in it and
        decodes any QR code, then tells you what it found.{' '}
        <span className="text-slate-500">
          The image never leaves this computer — it is read here, in your browser, and only the
          text is checked.
        </span>
      </p>

      <label
        htmlFor={inputId}
        onDragOver={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault()
          setDragging(false)
          if (!busy) accept(event.dataTransfer.files)
        }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-4 py-8 text-center transition ${
          dragging
            ? 'border-sky-500/60 bg-sky-500/10'
            : 'border-ink-600 bg-ink-900/40 hover:border-ink-500'
        } ${busy ? 'pointer-events-none opacity-60' : ''}`}
      >
        <span aria-hidden className="mb-2 text-2xl opacity-70">
          🖼
        </span>
        <span className="text-sm font-medium text-slate-200">
          Drop an image here, or click to choose one
        </span>
        <span className="mt-1 text-xs text-slate-500">PNG, JPEG, or WebP · up to 8 MB</span>
        <input
          id={inputId}
          ref={inputRef}
          type="file"
          accept="image/*"
          className="sr-only"
          disabled={busy || deviceId === null}
          onChange={(event) => accept(event.target.files)}
        />
      </label>

      {deviceId === null && (
        <p className="mt-3 text-sm text-slate-500">
          Waiting for your score to load before checks can be recorded against this device.
        </p>
      )}

      {/* aria-live so a screen reader announces the result when it lands, rather
          than leaving it silently in the DOM below the drop zone. */}
      <div aria-live="polite" className="mt-4">
        {busy && <BusyState stage={stage} />}
        {outcome && !busy && <Result outcome={outcome} onClear={reset} />}
      </div>
    </Panel>
  )
}

function BusyState({ stage }: { stage: Stage }) {
  return (
    <div className="space-y-3" aria-busy="true">
      <p className="text-sm text-slate-400">{STAGE_COPY[stage]}</p>
      <div className="skeleton h-4 w-4/5" />
      <div className="skeleton h-4 w-3/5" />
      <div className="skeleton h-4 w-2/5" />
    </div>
  )
}

function Result({ outcome, onClear }: { outcome: Outcome; onClear: () => void }) {
  const { read, scan, scanError, qr, qrCheck, qrError } = outcome

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        {outcome.previewUrl && (
          // Rendered from a local blob URL. Nothing was uploaded to produce it.
          <img
            src={outcome.previewUrl}
            alt=""
            className="h-16 w-16 flex-none rounded-lg border border-ink-700 object-cover"
          />
        )}
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-slate-200">{outcome.fileName}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            {read.ok && read.confidence !== null
              ? `Text read with ${read.confidence}% confidence`
              : read.ok
                ? 'No printed text found in this image'
                : 'The text in this image could not be read'}
          </p>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="ml-auto flex-none text-sm text-slate-400 underline-offset-4 hover:text-slate-200 hover:underline"
        >
          Clear
        </button>
      </div>

      {/* --- what was printed in the image ---------------------------------- */}
      {!read.ok ? (
        <Notice tone="warn" title="Could not read this image">
          {READ_FAILURE_COPY[read.code]} Until it can be read, treat it as unchecked — do not assume
          there is nothing sensitive in it.
        </Notice>
      ) : scanError !== null ? (
        <Notice tone="warn" title="Could not check the text in this image">
          {scanError} The text was read here on your computer, but nothing has been checked against
          it.
        </Notice>
      ) : scan !== null && scan.findings.length > 0 ? (
        <TextFindings scan={scan} poorRead={read.poorRead} />
      ) : read.text.length === 0 ? (
        <Notice tone="info" title="No printed text in this image">
          SentinelAI found nothing to read — no words, no numbers. That is the normal answer for a
          photo, a logo, or a chart.
        </Notice>
      ) : read.poorRead ? (
        <Notice tone="warn" title="Nothing found, but this was a poor read">
          SentinelAI read the text in this image and found no sensitive details — but it was not
          confident about what it read. A sharper screenshot would give a more reliable answer.
        </Notice>
      ) : (
        <Notice tone="ok" title="No sensitive details found">
          SentinelAI read the text in this image and found no Aadhaar or PAN numbers, card or
          account numbers, or other personal details.
        </Notice>
      )}

      {/* --- and where any QR code in it goes -------------------------------- */}
      {qrError !== null ? (
        <Notice tone="warn" title="Could not check the QR code in this image">
          {qrError}
        </Notice>
      ) : qrCheck !== null ? (
        <QrResult check={qrCheck} />
      ) : qr.ok === false && qr.code === 'no-qr-found' ? (
        <p className="text-xs text-slate-500">No QR code was found in this image.</p>
      ) : null}

      <p className="border-t border-ink-700 pt-3 text-xs leading-relaxed text-slate-500">
        {OCR_CAVEAT}
      </p>
    </div>
  )
}

/**
 * The sensitive things printed in the image.
 *
 * Its own component so `scan` is a non-null parameter rather than an assertion:
 * a findings list is only ever rendered from a scan that came back, and saying
 * that in the type is cheaper than remembering it.
 */
function TextFindings({ scan, poorRead }: { scan: ScanResult; poorRead: boolean }) {
  const style = RISK_STYLES[scan.risk_level]
  const count = scan.findings.length

  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900/60 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${style.pill}`}>
          <span aria-hidden className="mr-1">
            {style.glyph}
          </span>
          {style.label}
        </span>
        <h3 className="text-base font-semibold text-slate-100">
          {count === 1
            ? 'This image contains something sensitive'
            : `This image contains ${count} sensitive details`}
        </h3>
        <span className="ml-auto text-right">
          <span className={`text-2xl font-semibold tabular-nums ${style.text}`}>
            {scan.risk_score}
          </span>
          {/* The direction, in words. This number is the inverse of every other
              score on the page and must not be read as a grade. */}
          <span className="ml-1.5 text-xs text-slate-500">/100 risk — higher is worse</span>
        </span>
      </div>

      <ul className="mt-4 space-y-3">
        {scan.findings.map((finding, index) => (
          <FindingRow key={`${finding.pii_type}-${finding.start}-${index}`} finding={finding} />
        ))}
      </ul>

      {poorRead && (
        <p className="mt-4 text-xs leading-relaxed text-amber-200/80">
          The text in this image was hard to read, so there may be more in it than the list above.
        </p>
      )}

      {!scan.tier_2_available && (
        <p className="mt-2 text-xs leading-relaxed text-slate-500">
          The AI tier did not run, so this is based on the offline pattern checks alone.
        </p>
      )}
    </div>
  )
}

function FindingRow({ finding }: { finding: Finding }) {
  const style = RISK_STYLES[finding.risk_level]
  // Module 12's own tier. The value only validated once characters an optical
  // reader commonly confuses were corrected — and only because a checksum
  // confirmed the correction. Said out loud rather than presented as a plain
  // read, because the user is entitled to know the tool changed a digit.
  const corrected = finding.detection_tier === 'ocr'

  return (
    <li className="rounded-lg border border-ink-700 bg-ink-800/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${style.pill}`}>
          <span aria-hidden className="mr-1">
            {style.glyph}
          </span>
          {finding.label}
        </span>
        {/* The value, masked. Never the original — the backend does not return
            one and there is no column that could hold one. */}
        <span className="font-mono text-sm text-slate-200">{finding.masked_preview}</span>
        {corrected && (
          <span className="rounded border border-ink-600 px-1.5 py-0.5 text-[11px] text-slate-400">
            corrected read
          </span>
        )}
      </div>
      <p className="mt-2 text-sm leading-relaxed text-slate-300">{finding.explanation}</p>
      <p className="mt-1.5 text-sm leading-relaxed text-slate-200">{finding.recommendation}</p>
      <p className="mt-2 text-xs leading-relaxed text-slate-500">
        {finding.reason} · Confidence {Math.round(finding.confidence * 100)}%
      </p>
    </li>
  )
}

function QrResult({ check }: { check: QrCheck }) {
  const style = VERDICT_STYLES[check.verdict]

  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900/60 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${style.pill}`}>
          <span aria-hidden className="mr-1">
            {style.glyph}
          </span>
          {style.label}
        </span>
        <h3 className="text-base font-semibold text-slate-100">
          {QR_VERDICT_HEADLINE[check.verdict]}
        </h3>
      </div>

      {/* The destination, first and largest. A QR code is unreadable to a human,
          so simply showing where it goes is most of the protection this feature
          provides — the score is secondary to it. */}
      <div className="mt-3 rounded-lg border border-ink-700 bg-ink-800 p-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          This code goes to
        </p>
        <p className="mt-1 break-words text-sm font-medium leading-relaxed text-slate-100">
          {check.destination}
        </p>
      </div>

      <p className="mt-3 text-sm leading-relaxed text-slate-300">{check.summary}</p>

      <ul className="mt-3 space-y-2.5">
        {check.signals.map((signal, index) => (
          <SignalRow key={`${signal.signal}-${index}`} signal={signal} />
        ))}
      </ul>

      <div className="mt-4 rounded-lg border border-ink-700 bg-ink-800 p-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">What to do</p>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-200">{check.recommendation}</p>
      </div>

      <p className="mt-3 text-xs leading-relaxed text-slate-600">
        Confidence {Math.round(check.confidence * 100)}%
        {check.domain && ` · ${check.domain}`}
        {check.trust_score !== null && ` · site trust ${check.trust_score}/100`}
      </p>
    </div>
  )
}

function SignalRow({ signal }: { signal: QrSignal }) {
  const mark = WEIGHT_MARK[signal.weight]

  return (
    <li className="flex gap-3">
      <span
        aria-hidden
        className={`mt-0.5 flex h-5 w-5 flex-none items-center justify-center rounded text-[11px] font-bold ${mark.className}`}
      >
        {mark.glyph}
      </span>
      <div className="min-w-0">
        <span className="sr-only">{mark.label}: </span>
        <p
          className={`text-sm leading-relaxed ${
            signal.weight === 'bad' ? 'text-slate-200' : 'text-slate-400'
          }`}
        >
          {signal.detail}
        </p>
        {signal.evidence && (
          // A literal substring of the decoded payload, quoted back so the user
          // can see exactly what matched. Rendered as text — React escapes it.
          <p className="mt-1 break-words border-l-2 border-ink-600 pl-2 font-mono text-xs text-slate-500">
            {signal.evidence}
          </p>
        )}
      </div>
    </li>
  )
}

/** One shared box for the several "here is a plain statement" outcomes, so the
 *  clean answer and the could-not-check answer are visibly the same kind of
 *  thing — differing in tone, not in whether they appear at all. */
function Notice({
  tone,
  title,
  children,
}: {
  tone: 'ok' | 'warn' | 'info'
  title: string
  children: ReactNode
}) {
  const accent =
    tone === 'warn'
      ? 'border-amber-500/30 bg-amber-500/5'
      : tone === 'ok'
        ? 'border-emerald-500/25 bg-emerald-500/5'
        : 'border-ink-700 bg-ink-800'

  return (
    <div className={`rounded-lg border p-4 ${accent}`} role={tone === 'warn' ? 'alert' : undefined}>
      <p className="text-sm font-medium text-slate-200">{title}</p>
      <p className="mt-1 text-sm leading-relaxed text-slate-400">{children}</p>
    </div>
  )
}
