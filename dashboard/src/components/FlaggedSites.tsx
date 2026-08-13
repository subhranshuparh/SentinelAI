/**
 * Sites that did not pass, with the itemised reasons that made the call.
 *
 * The reasons are carried through verbatim from the site engine, so this list
 * and the extension popup show identical evidence for the same domain. If they
 * ever diverge, one of them is lying about why a site was flagged.
 *
 * Domain names are rendered as plain text, never as links. A dashboard that
 * offers a one-click path to a domain it has just called dangerous is worse than
 * useless, and rendering attacker-controlled text as an anchor is how a phishing
 * list becomes a phishing vector.
 */

import type { FlaggedSite } from '../types'
import { VERDICT_STYLES, timeAgo } from '../theme'
import { EmptyState, Panel } from './states'

const REASON_MARK: Record<string, { glyph: string; className: string }> = {
  bad: { glyph: '✕', className: 'text-red-400' },
  unknown: { glyph: '?', className: 'text-slate-500' },
  good: { glyph: '✓', className: 'text-emerald-400' },
}

function Row({ site }: { site: FlaggedSite }) {
  const style = VERDICT_STYLES[site.verdict] ?? VERDICT_STYLES.unknown

  // Only the reasons that argued against the site. A "good" line inside a
  // dangerous verdict reads as mitigation and muddies the call.
  const concerns = site.reasons.filter((reason) => reason.weight !== 'good').slice(0, 3)

  return (
    <li className="border-t border-ink-700 py-3 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="break-all font-mono text-sm text-slate-200">{site.domain}</span>
        <span className={`shrink-0 rounded border px-1.5 py-0.5 text-xs ${style.pill}`}>
          <span aria-hidden className="mr-1">
            {style.glyph}
          </span>
          {style.label}
        </span>
      </div>

      <div className="mt-1 text-xs text-slate-500">
        Trust {site.trust_score}/100 · {site.visits} visit{site.visits === 1 ? '' : 's'} · last{' '}
        {timeAgo(site.last_seen)}
      </div>

      {concerns.length > 0 && (
        <ul className="mt-2 space-y-1">
          {concerns.map((reason, index) => {
            const mark = REASON_MARK[reason.weight ?? 'unknown'] ?? REASON_MARK.unknown
            return (
              <li key={index} className="flex gap-2 text-sm leading-snug text-slate-400">
                <span aria-hidden className={`shrink-0 ${mark.className}`}>
                  {mark.glyph}
                </span>
                <span>{reason.detail}</span>
              </li>
            )
          })}
        </ul>
      )}
    </li>
  )
}

export function FlaggedSites({ sites }: { sites: FlaggedSite[] }) {
  if (sites.length === 0) {
    return (
      <Panel title="Sites worth a second look">
        <EmptyState
          icon="🌐"
          title="Every site checked out fine"
          detail="SentinelAI checks each page you open against Google Safe Browsing, domain age, and brand lookalikes."
        />
      </Panel>
    )
  }

  return (
    <Panel title="Sites worth a second look" count={sites.length}>
      <ul className="max-h-[26rem] overflow-y-auto pr-1">
        {sites.map((site) => (
          <Row key={site.domain} site={site} />
        ))}
      </ul>
    </Panel>
  )
}
