/**
 * PII findings and site verdicts, interleaved on one spine.
 *
 * Interleaved rather than two separate lists, because the correlation *is* the
 * product. "Typed a card number, then visited a flagged domain" only reads as
 * one story when both appear on the same timeline — two side-by-side lists make
 * the reader do the join themselves, and they won't.
 *
 * Everything rendered here comes from the backend already classified and already
 * masked. `masked_preview` is the only form of the detected string that exists
 * anywhere — there is no column holding the original, so this component cannot
 * leak raw PII even by mistake.
 */

import type { TimelineEvent } from '../types'
import { SEVERITY_STYLES, timeAgo } from '../theme'
import { EmptyState, Panel } from './states'

function Entry({ event }: { event: TimelineEvent }) {
  const style = SEVERITY_STYLES[event.severity]

  return (
    <li className="relative pl-6">
      {/* Dot on the rail. Colour plus position; the severity word is also in
          the pill below, so hue is never the only signal. */}
      <span
        aria-hidden
        className="absolute left-0 top-2 h-2.5 w-2.5 rounded-full ring-4 ring-ink-800"
        style={{ backgroundColor: style.hex }}
      />

      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="font-medium text-slate-200">{event.title}</span>
        <time
          className="text-xs text-slate-500"
          dateTime={event.occurred_at}
          title={new Date(event.occurred_at).toLocaleString()}
        >
          {timeAgo(event.occurred_at)}
        </time>
      </div>

      {/* The reason is carried through from the detector rather than re-derived
          here, so the dashboard and the extension toast never disagree about
          why something was flagged. */}
      <p className="mt-1 text-sm leading-snug text-slate-400">{event.detail}</p>

      <div className="mt-1.5 flex flex-wrap items-center gap-2">
        <span className={`rounded border px-1.5 py-0.5 text-xs ${style.pill}`}>
          <span aria-hidden className="mr-1">
            {style.glyph}
          </span>
          {style.label}
        </span>
        {event.masked_preview && (
          <code className="rounded bg-ink-700 px-1.5 py-0.5 font-mono text-xs text-slate-400">
            {event.masked_preview}
          </code>
        )}
      </div>
    </li>
  )
}

export function ThreatTimeline({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return (
      <Panel title="Recent activity">
        <EmptyState
          icon="🛡"
          title="Nothing caught yet — that's good news"
          detail="When SentinelAI spots sensitive text or a risky site, it will show up here with the reason."
        />
      </Panel>
    )
  }

  return (
    <Panel title="Recent activity" count={events.length}>
      {/* max-h + scroll rather than pagination: 25 entries is one flick of a
          wheel, and a pager would hide the most recent item behind a click. */}
      <ol className="relative max-h-[26rem] space-y-5 overflow-y-auto pr-1">
        <span aria-hidden className="absolute bottom-2 left-[4.5px] top-2 w-px bg-ink-700" />
        {events.map((event, index) => (
          <Entry key={`${event.kind}-${event.occurred_at}-${index}`} event={event} />
        ))}
      </ol>
    </Panel>
  )
}
