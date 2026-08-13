/**
 * The score in sentences — Module 8.
 *
 * `ScoreBreakdown`, directly below this, proves the arithmetic: 47 = 37 x 0.5 +
 * 55 x 0.5, every weight published. That panel is correct and most people will
 * not read it. This one is what they read instead, so it sits above the
 * arithmetic rather than below it.
 *
 * Three rules the markup enforces:
 *
 * 1. **Large type, plain sentences.** Target users include senior citizens. The
 *    body text here is deliberately a step larger than every other panel.
 * 2. **A missing cost renders as an em dash, never a digit.** Same rule, same
 *    reason, and the same glyph as `UnmeasuredCard` in `ScoreBreakdown`: `null`
 *    means "not measured", and a zero in its place is a lie about certainty.
 * 3. **The lever shows both numbers.** "47 → 65" is checkable; "improve your
 *    score" is not. The backend computed that 65 by actually re-running the
 *    score, so showing the pair is what makes the claim falsifiable.
 *
 * Every string rendered here is authored in Python. Nothing on this panel comes
 * from a language model or from site-supplied text.
 */

import type { Driver, Narrative } from '../types'
import { EmptyState, Panel } from './states'

/**
 * Severity only sets the marker colour. It deliberately does not set the text
 * colour — a wall of orange sentences is the over-alerting this product argues
 * against, and it makes the one line that matters harder to find, not easier.
 */
const MARKER: Record<Driver['severity'], string> = {
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-slate-500',
  info: 'bg-sky-400',
}

export function ScoreNarrative({ narrative }: { narrative: Narrative }) {
  const { headline, coverage, drivers, biggest_lever: lever } = narrative

  return (
    <Panel title="Why your score is what it is">
      <p className="text-lg font-medium leading-relaxed text-slate-100">{headline}</p>

      {drivers.length === 0 ? (
        <div className="mt-2">
          <EmptyState
            icon="🙂"
            title="Nothing is pulling your score down"
            detail="No sensitive details went out unprotected and no risky sites came up in this window."
          />
        </div>
      ) : (
        <ul className="mt-5 space-y-3.5">
          {drivers.map((driver, index) => (
            // Keyed on code plus index: `identity_breached` legitimately repeats,
            // once per breached password, so the code alone is not unique.
            <li key={`${driver.code}-${index}`} className="flex items-start gap-3">
              <span
                aria-hidden
                className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${MARKER[driver.severity]}`}
              />
              <span className="min-w-0 flex-1 text-base leading-relaxed text-slate-300">
                {driver.sentence}
              </span>
              <PointCost points={driver.points} />
            </li>
          ))}
        </ul>
      )}

      {lever && (
        <div className="mt-5 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-4">
          <h3 className="text-sm font-medium text-emerald-300">
            <span aria-hidden className="mr-1.5">
              ↑
            </span>
            Your biggest single improvement
          </h3>
          <p className="mt-1.5 text-base leading-relaxed text-slate-200">{lever.sentence}</p>
          <p className="mt-2.5 flex items-center gap-2 text-sm text-slate-400">
            <span className="tabular-nums">{lever.current_score}</span>
            <span aria-hidden>→</span>
            <span className="font-semibold tabular-nums text-emerald-300">
              {lever.projected_score}
            </span>
            <span className="text-slate-500">
              {/* Stated plainly, because a projection that looks like a promise
                  is worse than no projection. This one is a recomputation of the
                  same score with that cause resolved — nothing is estimated. */}
              out of 100, worked out by re-running your score without it
            </span>
          </p>
        </div>
      )}

      {/* Always rendered, never conditional. This sentence is what stops a score
          built from two of three areas from reading like a complete one. */}
      <p className="mt-5 border-t border-ink-700 pt-4 text-sm leading-relaxed text-slate-500">
        {coverage}
      </p>
    </Panel>
  )
}

/**
 * The point cost, or an em dash when it could not be worked out.
 *
 * The dash is not decoration. A driver whose cost is unknown must not print a
 * `0`, because `0` says "this is free" and the truth is "we do not know" — the
 * same distinction the whole scoring model is built around.
 */
function PointCost({ points }: { points: number | null }) {
  if (points === null) {
    return (
      <span
        className="shrink-0 text-sm tabular-nums text-slate-600"
        title="Cost to your score could not be worked out"
      >
        —
      </span>
    )
  }

  if (points === 0) {
    // A real, measured zero. Says so in words rather than printing "0 pts",
    // which reads as a rounding error rather than a deliberate statement.
    return <span className="shrink-0 text-sm text-slate-600">not counted</span>
  }

  return (
    <span className="shrink-0 text-sm tabular-nums text-slate-500" title="Points off your score">
      −{points}
    </span>
  )
}
