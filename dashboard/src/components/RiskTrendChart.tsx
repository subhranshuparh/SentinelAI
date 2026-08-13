/**
 * Score over time.
 *
 * The points are read back from `score_snapshots`, not recomputed from raw
 * events. That distinction matters: recomputing would retroactively rewrite the
 * chart every time a weight is tuned, so the line would silently change shape
 * mid-hackathon. A snapshot records what the score actually *was*.
 *
 * Overall is drawn as a filled area; the two sub-scores as thin lines behind it.
 * Three equally-weighted areas would be unreadable, and the question this chart
 * answers is "is my score moving?" — the sub-scores are there to explain *why*
 * once the eye has found the answer.
 */

import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import type { TrendPoint } from '../types'
import { COMPONENT_COLORS } from '../theme'
import { EmptyState, Panel } from './states'

interface Row {
  label: string
  overall: number
  privacy: number
  browsing: number
}

function TrendTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null

  return (
    <div className="rounded-lg border border-ink-600 bg-ink-900/95 px-3 py-2 text-xs shadow-lg">
      <div className="mb-1 font-medium text-slate-300">{label}</div>
      {payload.map((entry: any) => (
        <div key={entry.dataKey} className="flex items-center gap-2 text-slate-400">
          <span
            aria-hidden
            className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="capitalize">{entry.dataKey}</span>
          <span className="ml-auto tabular-nums text-slate-200">{entry.value}</span>
        </div>
      ))}
    </div>
  )
}

export function RiskTrendChart({ trend }: { trend: TrendPoint[] }) {
  // One point is a dot, not a trend. Saying so is more honest than drawing a
  // flat line that implies stability nobody has observed yet.
  if (trend.length < 2) {
    return (
      <Panel title="Score over time">
        <EmptyState
          icon="📈"
          title="Not enough history yet"
          detail="Your score is recorded each time you open this page. Come back tomorrow to see the line."
        />
      </Panel>
    )
  }

  const rows: Row[] = trend.map((point) => ({
    label: new Date(point.captured_at).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
    }),
    overall: point.overall,
    privacy: point.privacy,
    browsing: point.browsing,
  }))

  return (
    <Panel title="Score over time">
      <div className="h-56 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={rows} margin={{ top: 6, right: 8, bottom: 0, left: -22 }}>
            <defs>
              <linearGradient id="overallFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.32} />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
              </linearGradient>
            </defs>

            <CartesianGrid stroke="#1b2334" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: '#64748b', fontSize: 12 }}
              tickLine={false}
              axisLine={{ stroke: '#1b2334' }}
              minTickGap={24}
            />
            {/* Fixed 0-100 domain. Auto-scaling would turn a 4-point wobble into
                a dramatic cliff, which is exactly the over-alerting the spec
                warns against. */}
            <YAxis
              domain={[0, 100]}
              ticks={[0, 50, 100]}
              tick={{ fill: '#64748b', fontSize: 12 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<TrendTooltip />} cursor={{ stroke: '#2a3448' }} />

            <Area
              type="monotone"
              dataKey="overall"
              stroke="#38bdf8"
              strokeWidth={2.5}
              fill="url(#overallFill)"
              dot={false}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="privacy"
              stroke={COMPONENT_COLORS.privacy}
              strokeWidth={1.5}
              strokeDasharray="4 3"
              dot={false}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="browsing"
              stroke={COMPONENT_COLORS.browsing}
              strokeWidth={1.5}
              strokeDasharray="4 3"
              dot={false}
              isAnimationActive={false}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      {/* Hand-rolled legend rather than Recharts', so the dashes match the lines
          and the labels stay in plain language. */}
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
        <span className="flex items-center gap-1.5">
          <span aria-hidden className="h-0.5 w-4 rounded bg-sky-400" /> Overall
        </span>
        <span className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-0.5 w-4 rounded"
            style={{ backgroundColor: COMPONENT_COLORS.privacy }}
          />{' '}
          Privacy
        </span>
        <span className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-0.5 w-4 rounded"
            style={{ backgroundColor: COMPONENT_COLORS.browsing }}
          />{' '}
          Browsing
        </span>
      </div>
    </Panel>
  )
}
