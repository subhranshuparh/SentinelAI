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
    <div className="min-h-screen bg-ink-900">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
        <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <span className="text-lg font-semibold tracking-tight text-slate-100">SentinelAI</span>
            <span className="ml-2 text-sm text-slate-500">Security dashboard</span>
          </div>

          {lastUpdated && (
            <span className="text-xs text-slate-500">
              {/* When a poll has failed, say the data is stale rather than
                  showing a timestamp that implies it is current. */}
              {stale ? (
                <span className="text-amber-400/80">
                  Backend unreachable · showing data from {timeAgo(lastUpdated)}
                </span>
              ) : (
                <>Updated {timeAgo(lastUpdated)}</>
              )}
            </span>
          )}
        </header>

        <main className="space-y-4">{children}</main>

        <footer className="mt-10 text-xs leading-relaxed text-slate-600">
          SentinelAI never stores the sensitive text it detects — only the type of information, why
          it was flagged, and a masked preview.
        </footer>
      </div>
    </div>
  )
}
