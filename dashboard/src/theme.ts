/**
 * The single source of truth for risk colour.
 *
 * Every tier, verdict, and severity in the UI resolves through this file. The
 * roadmap's rule — *red is reserved for genuinely high risk only, because
 * over-alerting trains users to ignore warnings* — is a property of this map
 * rather than a convention each component has to remember.
 *
 * Every entry carries a `label` and a `glyph` alongside the colour. Roughly one
 * in twelve men has a red/green colour vision deficiency, so hue is never the
 * only channel carrying the verdict.
 */

import type { RiskLevel, Severity, Verdict } from './types'

export interface TierStyle {
  /** Human word. Shown, not just implied by colour. */
  label: string
  /** Non-colour redundant channel. */
  glyph: string
  /** Tailwind classes for a filled pill. */
  pill: string
  /** Tailwind text colour for standalone numbers. */
  text: string
  /** Raw hex, for Recharts and inline SVG which cannot take Tailwind classes. */
  hex: string
}

export const RISK_STYLES: Record<RiskLevel, TierStyle> = {
  low: {
    label: 'Low risk',
    glyph: '✓',
    pill: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    text: 'text-emerald-300',
    hex: '#34d399',
  },
  medium: {
    label: 'Some risk',
    glyph: '•',
    pill: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    text: 'text-amber-300',
    hex: '#fbbf24',
  },
  high: {
    label: 'High risk',
    glyph: '!',
    pill: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
    text: 'text-orange-300',
    hex: '#fb923c',
  },
  critical: {
    label: 'Needs attention now',
    glyph: '!!',
    pill: 'bg-red-500/15 text-red-300 border-red-500/30',
    text: 'text-red-300',
    hex: '#f87171',
  },
}

export const VERDICT_STYLES: Record<Verdict, TierStyle> = {
  safe: RISK_STYLES.low,
  suspicious: { ...RISK_STYLES.medium, label: 'Suspicious' },
  dangerous: { ...RISK_STYLES.critical, label: 'Dangerous' },
  // Grey, never green. An unchecked site is unverified, not safe — the same rule
  // the backend enforces, made visible.
  unknown: {
    label: 'Could not check',
    glyph: '?',
    pill: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
    text: 'text-slate-400',
    hex: '#94a3b8',
  },
}

/** Severity on a timeline entry uses the same scale as the overall risk level. */
export const SEVERITY_STYLES: Record<Severity, TierStyle> = {
  low: { ...RISK_STYLES.low, label: 'Low' },
  medium: { ...RISK_STYLES.medium, label: 'Medium' },
  high: { ...RISK_STYLES.high, label: 'High' },
  critical: { ...RISK_STYLES.critical, label: 'Critical' },
}

/** Per-component accent for the breakdown cards and the trend chart series. */
export const COMPONENT_COLORS = {
  privacy: '#818cf8',
  browsing: '#38bdf8',
  identity: '#94a3b8',
} as const

export const COMPONENT_LABELS = {
  privacy: 'Privacy',
  browsing: 'Browsing',
  identity: 'Identity',
} as const

/**
 * Relative time in words. `Intl.RelativeTimeFormat` is built in, so no date
 * library is installed for what is fifteen lines.
 */
export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''

  const seconds = Math.round((then - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.35],
    ['month', 12],
  ]

  let value = seconds
  for (const [unit, size] of units) {
    if (Math.abs(value) < size) return formatter.format(Math.round(value), unit)
    value /= size
  }
  return formatter.format(Math.round(value), 'year')
}
