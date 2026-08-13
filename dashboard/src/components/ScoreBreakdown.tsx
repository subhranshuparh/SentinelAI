/**
 * Privacy / Browsing / Identity — the arithmetic behind the hero number.
 *
 * This component is where the explainability claim either holds up or doesn't.
 * Each card shows the sub-score, the weight *actually applied*, and the points
 * it contributed, so a judge can add three numbers and land on the hero score.
 *
 * The Identity card is the important one. Module 4 is not built, so its score is
 * `null` — and a `null` that renders as a green 100, or as a red 0, would both
 * be lies. It renders as a dashed grey "not set up" card with its weight visibly
 * redistributed to the other two. That is the same missing-signal rule the site
 * engine and risk engine enforce, made visible at the pixel level.
 */

import type { Contribution } from '../types'
import { COMPONENT_COLORS, COMPONENT_LABELS } from '../theme'

function scoreColour(score: number): string {
  if (score >= 80) return '#34d399'
  if (score >= 60) return '#fbbf24'
  if (score >= 35) return '#fb923c'
  return '#f87171'
}

function MeasuredCard({ contribution }: { contribution: Contribution }) {
  const score = contribution.score as number
  const accent = COMPONENT_COLORS[contribution.component]
  const label = COMPONENT_LABELS[contribution.component]

  // Redistribution is only worth mentioning when it actually happened.
  const boosted = contribution.weight_applied > contribution.weight + 0.001

  return (
    <div className="card">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-300">{label}</h3>
        <span className="text-2xl font-semibold tabular-nums" style={{ color: scoreColour(score) }}>
          {score}
        </span>
      </div>

      <div
        className="mt-3 h-1.5 overflow-hidden rounded-full bg-ink-700"
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${label} score`}
      >
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${score}%`, backgroundColor: accent }}
        />
      </div>

      <p className="mt-3 text-sm leading-snug text-slate-400">{contribution.detail}</p>

      <p className="mt-3 border-t border-ink-700 pt-3 text-xs tabular-nums text-slate-500">
        Weight {Math.round(contribution.weight_applied * 100)}%
        {boosted && (
          <span className="text-slate-600"> (up from {Math.round(contribution.weight * 100)}%)</span>
        )}{' '}
        · contributed {contribution.points.toFixed(1)} points
      </p>
    </div>
  )
}

function UnmeasuredCard({ contribution }: { contribution: Contribution }) {
  const label = COMPONENT_LABELS[contribution.component]

  return (
    <div className="rounded-xl border border-dashed border-ink-600 bg-ink-800/40 p-5">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-400">{label}</h3>
        {/* An em dash, never a number. There is no honest digit to put here. */}
        <span className="text-2xl font-semibold text-slate-600" aria-label="Not measured">
          —
        </span>
      </div>

      <div className="mt-3 h-1.5 rounded-full bg-ink-700/50" />

      <p className="mt-3 text-sm leading-snug text-slate-500">{contribution.detail}</p>

      <p className="mt-3 border-t border-ink-700 pt-3 text-xs text-slate-500">
        Its {Math.round(contribution.weight * 100)}% share was shared out between the other two, so
        your score is not padded by an area we cannot see.
      </p>
    </div>
  )
}

export function ScoreBreakdown({ contributions }: { contributions: Contribution[] }) {
  return (
    <div>
      <h2 className="card-title mb-3">What makes up your score</h2>
      <div className="grid gap-3 sm:grid-cols-3">
        {contributions.map((contribution) =>
          contribution.score === null ? (
            <UnmeasuredCard key={contribution.component} contribution={contribution} />
          ) : (
            <MeasuredCard key={contribution.component} contribution={contribution} />
          ),
        )}
      </div>
    </div>
  )
}
