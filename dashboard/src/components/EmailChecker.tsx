/**
 * Module 3 — paste an email, get an explained verdict.
 *
 * The only interactive panel on the dashboard. Everything else here renders
 * history; this asks the user a question and answers it, which brings three
 * requirements the read-only panels do not have:
 *
 * 1. **A real busy state.** The AI tier can take several seconds. A button that
 *    silently does nothing for four seconds gets clicked again, and a user who
 *    clicks twice deserves a queue, not two requests.
 * 2. **A real error state that is not green.** If the check fails, the panel
 *    must say so. The one thing it must never do is leave a previous "safe"
 *    verdict on screen next to a new email.
 * 3. **No content echoed as markup.** The pasted text is attacker-authored by
 *    assumption. React escapes by default, and nothing here uses
 *    `dangerouslySetInnerHTML` — the evidence excerpts in particular come
 *    straight from the email and are rendered as text, deliberately.
 *
 * The score shown here runs the opposite way to every other number on this
 * screen: higher is worse. That is stated in words beside it rather than left
 * for the user to infer from colour.
 */

import { useId, useState } from 'react'

import { ApiError, analyzeEmail } from '../api/client'
import type { EmailAnalysis, PhishingSignal, SignalWeight, Verdict } from '../types'
import { VERDICT_STYLES } from '../theme'
import { Panel } from './states'

/** Matches the backend's `MAX_BODY_CHARS`. Enforced here too so the user sees
 *  the limit while typing rather than as a 422 after waiting. */
const MAX_BODY_CHARS = 20_000

/** Marker per signal weight. Glyph *and* colour — never colour alone. */
const WEIGHT_MARK: Record<SignalWeight, { glyph: string; className: string; label: string }> = {
  bad: { glyph: '!', className: 'bg-red-500/15 text-red-300', label: 'Problem found' },
  good: { glyph: '✓', className: 'bg-emerald-500/15 text-emerald-300', label: 'Checked, clean' },
  unknown: { glyph: '?', className: 'bg-slate-500/15 text-slate-400', label: 'Could not check' },
}

/** Headline copy per verdict. Calm, specific, and never the word "safe" alone. */
const VERDICT_HEADLINE: Record<Verdict, string> = {
  dangerous: 'This looks like a phishing email',
  suspicious: 'Parts of this do not add up',
  safe: 'No phishing signs found',
  unknown: 'Not enough to judge',
}

export function EmailChecker() {
  const [body, setBody] = useState('')
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [result, setResult] = useState<EmailAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const bodyId = useId()
  const senderId = useId()
  const subjectId = useId()

  async function run() {
    if (!body.trim() || busy) return

    setBusy(true)
    // Cleared before the request, not after it. A stale verdict sitting next to
    // a new email for the duration of a slow call is the one failure mode that
    // could actively mislead someone.
    setResult(null)
    setError(null)

    try {
      const analysis = await analyzeEmail({
        body,
        sender: sender.trim() || undefined,
        subject: subject.trim() || undefined,
      })
      setResult(analysis)
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'Something went wrong checking that email.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel title="Check an email">
      <p className="mb-4 max-w-2xl text-sm leading-relaxed text-slate-400">
        Paste an email you are unsure about. SentinelAI checks where its links really go, who it
        actually came from, and what it is asking you to do — then explains the answer.{' '}
        <span className="text-slate-500">
          Nothing you paste here is saved. It is analysed and forgotten.
        </span>
      </p>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field id={senderId} label="From (optional)" hint="Paste the whole From line if you can">
          <input
            id={senderId}
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="Alerts &lt;alerts@example.com&gt;"
            className="input"
            autoComplete="off"
          />
        </Field>
        <Field id={subjectId} label="Subject (optional)">
          <input
            id={subjectId}
            type="text"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="Urgent: verify your account"
            className="input"
            autoComplete="off"
          />
        </Field>
      </div>

      <div className="mt-3">
        <Field id={bodyId} label="The email itself">
          <textarea
            id={bodyId}
            value={body}
            onChange={(e) => setBody(e.target.value.slice(0, MAX_BODY_CHARS))}
            rows={7}
            placeholder="Paste the full message here…"
            className="input resize-y font-normal"
          />
        </Field>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void run()}
          disabled={busy || !body.trim()}
          className="rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-sm font-medium text-sky-200 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? 'Checking…' : 'Check this email'}
        </button>
        {(result || error) && (
          <button
            type="button"
            onClick={() => {
              setBody('')
              setSender('')
              setSubject('')
              setResult(null)
              setError(null)
            }}
            className="text-sm text-slate-400 underline-offset-4 hover:text-slate-200 hover:underline"
          >
            Clear
          </button>
        )}
        <span className="ml-auto text-xs tabular-nums text-slate-600">
          {body.length.toLocaleString()} / {MAX_BODY_CHARS.toLocaleString()}
        </span>
      </div>

      {/* aria-live so a screen reader announces the verdict when it lands,
          rather than leaving it silently in the DOM below the button. */}
      <div aria-live="polite" className="mt-4">
        {busy && <BusyState />}
        {error && !busy && (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4" role="alert">
            <p className="text-sm font-medium text-amber-200">Could not check this email</p>
            <p className="mt-1 text-sm text-slate-400">
              {error} Until it can be checked, treat the email as unverified — do not click its
              links.
            </p>
          </div>
        )}
        {result && !busy && <Result analysis={result} />}
      </div>
    </Panel>
  )
}

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-xs font-medium text-slate-400">
        {label}
        {hint && <span className="ml-2 font-normal text-slate-600">{hint}</span>}
      </label>
      {children}
    </div>
  )
}

function BusyState() {
  return (
    <div className="space-y-3" aria-busy="true">
      <span className="sr-only">Checking this email…</span>
      <div className="skeleton h-5 w-1/2" />
      <div className="skeleton h-4 w-4/5" />
      <div className="skeleton h-4 w-3/5" />
    </div>
  )
}

function Result({ analysis }: { analysis: EmailAnalysis }) {
  const style = VERDICT_STYLES[analysis.verdict]
  const findings = analysis.signals.filter((s) => s.weight === 'bad')

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
          {VERDICT_HEADLINE[analysis.verdict]}
        </h3>

        {analysis.verdict !== 'unknown' && (
          <span className="ml-auto text-right">
            <span className={`text-2xl font-semibold tabular-nums ${style.text}`}>
              {analysis.risk_score}
            </span>
            {/* The direction, in words. This number is the inverse of every
                other score on the page and must not be read as a grade. */}
            <span className="ml-1.5 text-xs text-slate-500">/100 risk — higher is worse</span>
          </span>
        )}
      </div>

      <p className="mt-3 text-sm leading-relaxed text-slate-300">{analysis.summary}</p>

      {findings.length > 0 && (
        <p className="mt-1 text-sm text-slate-400">
          {findings.length} {findings.length === 1 ? 'thing' : 'things'} about it{' '}
          {findings.length === 1 ? 'is' : 'are'} wrong.
        </p>
      )}

      <ul className="mt-4 space-y-2.5">
        {analysis.signals.map((signal, index) => (
          <SignalRow key={`${signal.signal}-${index}`} signal={signal} />
        ))}
      </ul>

      <div className="mt-4 rounded-lg border border-ink-700 bg-ink-800 p-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">What to do</p>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-200">{analysis.recommendation}</p>
      </div>

      <p className="mt-3 text-xs leading-relaxed text-slate-600">
        Confidence {Math.round(analysis.confidence * 100)}%
        {analysis.intent_label && ` · AI read this as: ${analysis.intent_label}`}
        {analysis.heuristics_only &&
          ' · The AI check did not run, so this is based on the offline pattern checks alone.'}
      </p>
    </div>
  )
}

function SignalRow({ signal }: { signal: PhishingSignal }) {
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
          // The user's own pasted text, quoted back so they can see exactly what
          // was matched. Rendered as text inside a quote block — React escapes
          // it, and nothing here would let it become markup.
          <p className="mt-1 break-words border-l-2 border-ink-600 pl-2 font-mono text-xs text-slate-500">
            {signal.evidence}
          </p>
        )}
      </div>
    </li>
  )
}
