/**
 * The single dashboard screen.
 *
 * One screen, no routing, no tabs. The whole argument of this page is that
 * typing behaviour and browsing context feed *one* score — splitting that across
 * routes would be arguing against the product.
 *
 * Polling rather than websockets. Checkpoint 5 requires that an action taken in
 * the extension shows up here "within seconds", and a 10-second poll against a
 * single local endpoint delivers that for about four lines of code. A websocket
 * would add a connection lifecycle, a reconnect policy, and a new failure mode
 * on stage, to shave a few seconds off a demo nobody is timing.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import { ApiError, fetchSummary } from './api/client'
import type { DashboardSummary } from './types'
import { EmailChecker } from './components/EmailChecker'
import { FlaggedSites } from './components/FlaggedSites'
import { Recommendations } from './components/Recommendations'
import { ReviewChecker } from './components/ReviewChecker'
import { RiskTrendChart } from './components/RiskTrendChart'
import { ScoreBreakdown } from './components/ScoreBreakdown'
import { ScoreHero, StatStrip } from './components/ScoreHero'
import { ScoreNarrative } from './components/ScoreNarrative'
import { ScreenshotChecker } from './components/ScreenshotChecker'
import { SecurityAssistant } from './components/SecurityAssistant'
import { ThreatTimeline } from './components/ThreatTimeline'
import { CardSkeleton, ErrorState } from './components/states'
import { timeAgo } from './theme'

const POLL_INTERVAL_MS = 10_000

/**
 * `?device=…` overrides which device is shown. Without it the backend falls back
 * to the most recently active one, which during a demo is always the machine
 * just used — so the URL stays clean and nobody has to copy a UUID out of the
 * extension popup before the screen works.
 */
function deviceFromUrl(): string | undefined {
  return new URLSearchParams(window.location.search).get('device') ?? undefined
}

/** Inline SVG brand logo — shield with S, lock, eye, circuit traces. */
function BrandLogo({ size = 36 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 200 200"
      fill="none"
      aria-hidden="true"
      className="shrink-0 animate-glow-pulse"
    >
      <defs>
        <linearGradient id="hShieldGrad" x1="100" y1="10" x2="100" y2="185" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1e3a6e" />
          <stop offset="50%" stopColor="#0f1f4a" />
          <stop offset="100%" stopColor="#080f2a" />
        </linearGradient>
        <linearGradient id="hBorderGrad" x1="20" y1="10" x2="180" y2="185" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4a90e2" />
          <stop offset="60%" stopColor="#60a5fa" />
          <stop offset="100%" stopColor="#93c5fd" />
        </linearGradient>
        <linearGradient id="hSGrad" x1="80" y1="60" x2="130" y2="140" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#e2e8f0" />
          <stop offset="55%" stopColor="#c8d8f0" />
          <stop offset="100%" stopColor="#60a5fa" />
        </linearGradient>
        <filter id="hGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <pattern id="hHex" x="0" y="0" width="18" height="20" patternUnits="userSpaceOnUse" patternTransform="translate(100,100)">
          <polygon points="9,1 17,5.5 17,14.5 9,19 1,14.5 1,5.5" fill="none" stroke="#1a3a6a" strokeWidth="0.6" opacity="0.5" />
        </pattern>
        <clipPath id="hClip">
          <path d="M100 12 L170 38 L170 100 Q170 155 100 185 Q30 155 30 100 L30 38 Z" />
        </clipPath>
      </defs>
      <path d="M100 8 L176 36 L176 100 Q176 160 100 192 Q24 160 24 100 L24 36 Z"
            fill="none" stroke="url(#hBorderGrad)" strokeWidth="3" opacity="0.7" filter="url(#hGlow)" />
      <path d="M100 12 L172 39 L172 100 Q172 157 100 188 Q28 157 28 100 L28 39 Z"
            fill="url(#hShieldGrad)" />
      <g clipPath="url(#hClip)">
        <rect x="100" y="0" width="80" height="200" fill="url(#hHex)" />
      </g>
      <path d="M100 16 L168 42 L168 100 Q168 154 100 184 Q32 154 32 100 L32 42 Z"
            fill="none" stroke="#2a5298" strokeWidth="1.5" opacity="0.6" />
      <g stroke="#38bdf8" strokeWidth="1.2" opacity="0.85" strokeLinecap="round" fill="none">
        <line x1="52" y1="50" x2="52" y2="120" />
        <line x1="52" y1="65" x2="68" y2="65" />
        <line x1="52" y1="80" x2="62" y2="80" />
        <line x1="52" y1="100" x2="70" y2="100" />
        <circle cx="52" cy="65" r="2.5" fill="#38bdf8" />
        <circle cx="52" cy="80" r="2" fill="#38bdf8" />
        <circle cx="52" cy="100" r="2.5" fill="#60a5fa" />
        <circle cx="68" cy="65" r="2" fill="#38bdf8" />
        <line x1="62" y1="80" x2="62" y2="90" />
        <circle cx="62" cy="90" r="1.8" fill="#38bdf8" />
      </g>
      <text x="102" y="140" fontFamily="Arial Black, sans-serif" fontSize="90" fontWeight="900"
            fill="#1a3a6e" textAnchor="middle" dominantBaseline="middle" opacity="0.4">S</text>
      <text x="100" y="138" fontFamily="Arial Black, sans-serif" fontSize="90" fontWeight="900"
            fill="url(#hSGrad)" textAnchor="middle" dominantBaseline="middle" filter="url(#hGlow)">S</text>
      <g transform="translate(145, 52)" filter="url(#hGlow)">
        <path d="M-14,0 Q0,-9 14,0 Q0,9 -14,0 Z" fill="#0f1f4a" stroke="#60a5fa" strokeWidth="1.2" />
        <circle cx="0" cy="0" r="5" fill="#1e3a8a" />
        <circle cx="0" cy="0" r="3" fill="#60a5fa" />
        <circle cx="1.5" cy="-1.5" r="1" fill="#bfdbfe" opacity="0.9" />
      </g>
      <g transform="translate(100, 162)" filter="url(#hGlow)">
        <rect x="-10" y="-2" width="20" height="16" rx="3" fill="#1e3a8a" stroke="#60a5fa" strokeWidth="1.3" />
        <path d="M-6,-2 L-6,-9 Q-6,-16 0,-16 Q6,-16 6,-9 L6,-2" fill="none" stroke="#60a5fa" strokeWidth="1.8" strokeLinecap="round" />
        <circle cx="0" cy="6" r="3" fill="#60a5fa" />
        <rect x="-1.5" y="7" width="3" height="4" rx="1" fill="#60a5fa" />
      </g>
    </svg>
  )
}

export default function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)

  // Keeps the poll from flipping the whole screen back to a skeleton every ten
  // seconds. Only the first fetch is allowed to show a loading state.
  const hasLoaded = useRef(false)

  const load = useCallback(async () => {
    try {
      const data = await fetchSummary(deviceFromUrl())
      setSummary(data)
      setError(null)
      setLastUpdated(new Date().toISOString())
    } catch (caught) {
      const apiError =
        caught instanceof ApiError
          ? caught
          : new ApiError('Something went wrong loading your score.')
      // A failed *poll* must not blank a screen that is already showing good
      // data. The header shows a staleness note instead; the numbers stay put.
      setError(apiError)
    } finally {
      hasLoaded.current = true
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = setInterval(() => void load(), POLL_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [load])

  // --- Page-level states ---------------------------------------------------

  if (loading && !summary) {
    return (
      <Shell>
        <CardSkeleton lines={4} title="Your security score" />
        <div className="grid gap-3 sm:grid-cols-3">
          <CardSkeleton lines={2} />
          <CardSkeleton lines={2} />
          <CardSkeleton lines={2} />
        </div>
        <CardSkeleton lines={5} title="Score over time" />
      </Shell>
    )
  }

  if (error && !summary) {
    // 404 is not a fault — it is the documented "nothing recorded yet" answer,
    // so it gets onboarding copy and a neutral tone rather than a red alarm.
    const firstRun = error.status === 404
    return (
      <Shell>
        <ErrorState
          tone={firstRun ? 'info' : 'error'}
          title={firstRun ? 'No activity recorded yet' : 'Cannot reach SentinelAI'}
          detail={
            firstRun
              ? 'Install the extension and browse for a minute, or run "python -m app.db.seed" in the backend folder to load a demo history.'
              : `${error.message} Check that the backend is running on port 8000, then try again.`
          }
          onRetry={() => {
            setLoading(true)
            void load()
          }}
        />
      </Shell>
    )
  }

  if (!summary) return null

  // --- Loaded --------------------------------------------------------------

  return (
    <Shell lastUpdated={lastUpdated} stale={error !== null}>
      <ScoreHero summary={summary} />
      <StatStrip summary={summary} />

      {/* Sentences before arithmetic. The breakdown below proves the number;
          this explains it, and explaining is what most visitors came for. */}
      <ScoreNarrative narrative={summary.narrative} />
      <ScoreBreakdown contributions={summary.contributions} />
      <RiskTrendChart trend={summary.trend} />

      {/* Timeline and flagged sites side by side: they answer "what happened"
          and "where", and reading them together is how the correlation lands. */}
      <div className="grid gap-4 lg:grid-cols-2">
        <ThreatTimeline events={summary.timeline} />
        <FlaggedSites sites={summary.flagged_sites} />
      </div>

      <Recommendations recommendations={summary.recommendations} />

      {/* Last, and deliberately so. Everything above is history the user did
          not have to ask for; these are the things they come here to *do*, and
          putting a text box at the top would bury the score it exists beside.

          The screenshot checker follows the email checker because it is the
          heavier of the two: it pulls several megabytes of OCR engine the first
          time it is used, and only on demand. Its findings are recorded against
          the device shown above, so anything it catches appears in the timeline
          on the next poll rather than in a panel that agrees with nothing. */}
      <SecurityAssistant deviceId={summary.device_id} />
      <EmailChecker />
      <ReviewChecker />
      <ScreenshotChecker deviceId={summary.device_id} />
    </Shell>
  )
}

function Shell({
  children,
  lastUpdated,
  stale,
}: {
  children: ReactNode
  lastUpdated?: string | null
  stale?: boolean
}) {
  return (
    <div className="min-h-screen bg-ink-900 bg-grid">
      {/* ── Header ── */}
      <header className="sticky top-0 z-50 border-b border-ink-700/60 bg-ink-900/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <BrandLogo size={36} />
            <div className="flex flex-col leading-none">
              <span className="text-base font-bold tracking-tight text-gradient-brand">
                SentinelAI
              </span>
              <span className="text-[10px] uppercase tracking-[0.12em] text-slate-500">
                Security Dashboard
              </span>
            </div>
          </div>

          {/* Status / last updated */}
          <div className="flex items-center gap-3">
            {lastUpdated && (
              <span className="text-xs text-slate-500">
                {stale ? (
                  <span className="flex items-center gap-1.5 text-amber-400/80">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-400/80" />
                    Offline · data from {timeAgo(lastUpdated)}
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-slate-500">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400 status-live" />
                    Updated {timeAgo(lastUpdated)}
                  </span>
                )}
              </span>
            )}
          </div>
        </div>

        {/* Accent gradient line below header */}
        <div
          className="h-px w-full"
          style={{
            background: 'linear-gradient(90deg, transparent 0%, rgba(96,165,250,0.4) 30%, rgba(56,189,248,0.6) 50%, rgba(96,165,250,0.4) 70%, transparent 100%)',
          }}
        />
      </header>

      {/* ── Content ── */}
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 animate-fade-in">
        <main className="space-y-4">{children}</main>

        {/* ── Footer ── */}
        <footer className="mt-12 border-t border-ink-700/40 pt-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <BrandLogo size={20} />
              <span className="text-xs font-medium text-slate-500">SentinelAI</span>
            </div>
            <p className="text-xs leading-relaxed text-slate-600 max-w-md">
              SentinelAI never stores the sensitive text it detects — only the type of
              information, why it was flagged, and a masked preview.
            </p>
            <div className="flex items-center gap-1 text-[10px] text-slate-600">
              <span
                className="inline-block h-1.5 w-1.5 rounded-full"
                style={{ background: 'linear-gradient(135deg,#60a5fa,#38bdf8)' }}
              />
              Privacy · Protection · Peace of Mind
            </div>
          </div>
        </footer>
      </div>
    </div>
  )
}
