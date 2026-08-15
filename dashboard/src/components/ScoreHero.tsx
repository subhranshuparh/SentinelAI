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

import { useEffect, useRef } from 'react'
import type { DashboardSummary } from '../types'
import { RISK_STYLES } from '../theme'

const RADIUS = 78
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

export function ScoreHero({ summary }: { summary: DashboardSummary }) {
  const style = RISK_STYLES[summary.risk_level]
  const dash = (summary.overall_score / 100) * CIRCUMFERENCE
  const arcRef = useRef<SVGCircleElement>(null)

  // Confidence below 1 means a component could not be measured. Surfaced as a
  // sentence rather than a raw decimal, because "0.8" means nothing to the
  // senior citizens and shoppers this product names as target users.
  const partial = summary.confidence < 1

  // Animate the ring drawing on mount
  useEffect(() => {
    const arc = arcRef.current
    if (!arc) return
    arc.style.strokeDasharray = `0 ${CIRCUMFERENCE}`
    arc.style.transition = 'none'
    // Force reflow
    void arc.getBoundingClientRect()
    arc.style.transition = 'stroke-dasharray 1.2s cubic-bezier(0.4, 0, 0.2, 1)'
    arc.style.strokeDasharray = `${dash} ${CIRCUMFERENCE}`
  }, [dash])

  return (
    <section className="card-glass flex flex-col items-center gap-7 sm:flex-row sm:items-center sm:gap-9 animate-fade-in-up">
      {/* Score ring */}
      <div className="relative shrink-0">
        {/* Outer glow ring */}
        <div
          className="absolute inset-0 rounded-full opacity-20 blur-xl"
          style={{ background: style.hex }}
          aria-hidden
        />
        <svg
          width="184"
          height="184"
          viewBox="0 0 184 184"
          role="img"
          aria-label={`Security score ${summary.overall_score} out of 100. ${style.label}.`}
        >
          {/* Track ring */}
          <circle cx="92" cy="92" r={RADIUS} fill="none" stroke="#1b2334" strokeWidth="13" />
          {/* Progress ring with glow */}
          <circle
            cx="92"
            cy="92"
            r={RADIUS}
            fill="none"
            stroke={style.hex}
            strokeWidth="13"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
            // Start the arc at 12 o'clock instead of 3 o'clock
            transform="rotate(-90 92 92)"
            ref={arcRef}
            style={{
              filter: `drop-shadow(0 0 8px ${style.hex}80) drop-shadow(0 0 20px ${style.hex}30)`,
            }}
          />
          {/* Subtle inner ring decoration */}
          <circle cx="92" cy="92" r="62" fill="none" stroke="#1b2334" strokeWidth="0.5" strokeDasharray="3 6" opacity="0.4" />
        </svg>

        {/* Score number centered in ring */}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-5xl font-bold tabular-nums"
            style={{ color: style.hex, textShadow: `0 0 20px ${style.hex}60` }}
          >
            {summary.overall_score}
          </span>
          <span className="text-xs text-slate-500">out of 100</span>
        </div>
      </div>

      {/* Score text */}
      <div className="min-w-0 text-center sm:text-left animate-fade-in-up stagger-2">
        <div className="flex flex-wrap items-center justify-center gap-2 sm:justify-start">
          <h1 className="text-xl font-semibold text-slate-100">Your security score</h1>
          <span
            className={`badge ${style.pill}`}
            style={{ boxShadow: `0 0 10px ${style.hex}30` }}
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
    { label: 'Sensitive details caught', value: summary.total_pii_events, icon: '🔍' },
    { label: 'Masked before sending', value: summary.total_masked, icon: '🛡️' },
    { label: 'Risky sites flagged', value: summary.total_sites_flagged, icon: '⚠️' },
  ]

  return (
    <div className="grid grid-cols-3 gap-3">
      {stats.map((stat, i) => (
        <div
          key={stat.label}
          className={`card-glass py-4 text-center animate-fade-in-up stagger-${i + 1}`}
        >
          <div className="mb-1 text-lg">{stat.icon}</div>
          <div className="text-2xl font-bold tabular-nums text-slate-100">{stat.value}</div>
          <div className="mt-1 text-xs leading-snug text-slate-500">{stat.label}</div>
        </div>
      ))}
    </div>
  )
}
