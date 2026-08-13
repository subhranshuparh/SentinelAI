/**
 * What to do next, ranked.
 *
 * A score without a next step is a guilt trip. This panel is the difference
 * between the dashboard reporting on the user and the dashboard helping them.
 *
 * Every string here is authored in Python, from the shape of the data — no part
 * of a recommendation is assembled from site-supplied text. That is deliberate:
 * a recommendation is the most action-provoking sentence in the whole product,
 * so nothing an attacker controls gets to write one.
 *
 * The backend caps the list at four. A list of eleven urgent items is a list of
 * zero urgent items, and that cap lives server-side so every client inherits it.
 */

import type { Recommendation } from '../types'
import { EmptyState, Panel } from './states'

const PRIORITY: Record<Recommendation['priority'], { label: string; pill: string; glyph: string }> =
  {
    high: {
      label: 'Do this first',
      glyph: '!',
      pill: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
    },
    medium: {
      label: 'Worth checking',
      glyph: '•',
      pill: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    },
    low: {
      label: 'When you have time',
      glyph: '·',
      pill: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
    },
  }

export function Recommendations({ recommendations }: { recommendations: Recommendation[] }) {
  if (recommendations.length === 0) {
    return (
      <Panel title="What to do next">
        <EmptyState
          icon="✅"
          title="Nothing needs your attention"
          detail="You are on top of things. SentinelAI will speak up here if that changes."
        />
      </Panel>
    )
  }

  return (
    <Panel title="What to do next" count={recommendations.length}>
      <ol className="space-y-3">
        {recommendations.map((rec, index) => {
          const priority = PRIORITY[rec.priority]
          return (
            // Keyed on `action` — a stable machine tag from the backend, not the
            // English title, which is templated and can repeat.
            <li
              key={`${rec.action}-${index}`}
              className="rounded-lg border border-ink-700 bg-ink-900/40 p-4"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <h3 className="min-w-0 font-medium leading-snug text-slate-200">{rec.title}</h3>
                <span
                  className={`shrink-0 rounded border px-1.5 py-0.5 text-xs ${priority.pill}`}
                >
                  <span aria-hidden className="mr-1">
                    {priority.glyph}
                  </span>
                  {priority.label}
                </span>
              </div>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{rec.detail}</p>
            </li>
          )
        })}
      </ol>
    </Panel>
  )
}
