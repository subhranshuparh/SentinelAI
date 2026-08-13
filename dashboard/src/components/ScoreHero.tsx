/**
 * The unified score — the one thing on this page that has to land instantly.
 *
 * This is where the product's thesis becomes visible: a single number that
 * typing behaviour and browsing context both feed. Everything below it exists to
 * justify this number, which is why the headline sentence sits directly beside
 * it rather than in a tooltip.
 *
 * The ring is hand-drawn SVG rather than a chart library. It is one circle with a
 * dash offset; pulling in a gauge component to draw it would add a dependency
 * for thirty lines of geometry.
 */

import type { DashboardSummary } from '../types'
import { RISK_STYLES } from '../theme'

const RADIUS = 78
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

export function ScoreHero({ summary }: { summary: DashboardSummary }) {
  const style = RISK_STYLES[summary.risk_level]
  const dash = (summary.overall_score / 100) * CIRCUMFERENCE

  // Confidence below 1 means a component could not be measured. Surfaced as a
  // sentence rather than a raw decimal, because "0.8" means nothing to the
  // senior citizens and shoppers this product names as target users.
  const partial = summary.confidence < 1

  return (
    <section className="card flex flex-col items-center gap-7 sm:flex-row sm:items-center sm:gap-9">
      <div className="relative shrink-0">
        <svg
          width="184"
          height="184"
          viewBox="0 0 184 184"
          role="img"
          aria-label={`Security score ${summary.overall_score} out of 100. ${style.label}.`}
        >
          <circle cx="92" cy="92" r={RADIUS} fill="none" stroke="#1b2334" strokeWidth="13" />
          <circle
            cx="92"
            cy="92"
            r={RADIUS}
            fill="none"
            stroke={style.hex}
            strokeWidth="13"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
            // Start the arc at 12 o'clock instead of 3 o'clock, which is where
            // SVG puts angle zero.
            transform="rotate(-90 92 92)"
          />
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-5xl font-semibold tabular-nums text-slate-50">
            {summary.overall_score}
          </span>
          <span className="text-xs text-slate-500">out of 100</span>
        </div>
      </div>

      <div className="min-w-0 text-center sm:text-left">
        <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
          <h1 className="text-xl font-semibold text-slate-100">Your security score</h1>
          <span
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${style.pill}`}
          >
            <span aria-hidden className="mr-1">
              {style.glyph}
            </span>
            {style.label}
          </span>
        </div>

        {/* The headline is authored by the backend so the dashboard and any
            other client always say the same thing about the same score. */}
        <p className="mt-2.5 text-base leading-relaxed text-slate-300">{summary.headline}</p>

        <p className="mt-3 text-sm text-slate-500">
          Based on the last {summary.window_days} days.{' '}
          {partial && (
            <>
              One area could not be measured, so the rest count for more —{' '}
              <span className="text-slate-400">
                {Math.round(summary.confidence * 100)}% of the full picture.
              </span>
            </>
          )}
        </p>
      </div>
    </section>
  )
}

/** Compact counters. Derived server-side so a truncated timeline cannot skew them. */
export function StatStrip({ summary }: { summary: DashboardSummary }) {
  const stats = [
    { label: 'Sensitive details caught', value: summary.total_pii_events },
    { label: 'Masked before sending', value: summary.total_masked },
    { label: 'Risky sites flagged', value: summary.total_sites_flagged },
  ]

  return (
    <div className="grid grid-cols-3 gap-3">
      {stats.map((stat) => (
        <div key={stat.label} className="card py-4 text-center">
          <div className="text-2xl font-semibold tabular-nums text-slate-100">{stat.value}</div>
          <div className="mt-1 text-xs leading-snug text-slate-500">{stat.label}</div>
        </div>
      ))}
    </div>
  )
}
