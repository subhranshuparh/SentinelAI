/**
 * The three states every widget owes the user, in one place.
 *
 * Written once and reused rather than improvised per component, because the
 * failure mode is not "the empty state looks slightly different" — it is that
 * one widget quietly renders nothing at all and looks broken. Sharing these
 * makes forgetting a state a visible omission.
 */

import type { ReactNode } from 'react'

export function CardSkeleton({ lines = 3, title }: { lines?: number; title?: string }) {
  return (
    <section className="card" aria-busy="true" aria-live="polite">
      {title && <h2 className="card-title mb-4">{title}</h2>}
      <span className="sr-only">Loading {title ?? 'content'}…</span>
      <div className="space-y-3">
        {Array.from({ length: lines }, (_, i) => (
          // Varying widths. Equal-length bars read as a loading *pattern*;
          // ragged ones read as text that has not arrived yet.
          <div key={i} className="skeleton h-4" style={{ width: `${92 - i * 13}%` }} />
        ))}
      </div>
    </section>
  )
}

/**
 * An empty list is usually good news here, and the copy has to say so.
 * "No data" reads as a broken widget; "Nothing caught yet" reads as safety.
 */
export function EmptyState({ icon, title, detail }: { icon: string; title: string; detail: string }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
      <div aria-hidden className="mb-3 text-3xl opacity-60">
        {icon}
      </div>
      <p className="font-medium text-slate-300">{title}</p>
      <p className="mt-1 max-w-xs text-sm text-slate-500">{detail}</p>
    </div>
  )
}

/**
 * Deliberately not red unless it is genuinely a fault. A backend that is not
 * running yet is an instruction, not an alarm — the same "calm, not alarmist"
 * rule the extension toast follows.
 */
export function ErrorState({
  title,
  detail,
  onRetry,
  tone = 'error',
}: {
  title: string
  detail: string
  onRetry?: () => void
  tone?: 'error' | 'info'
}) {
  const accent = tone === 'error' ? 'border-red-500/30 bg-red-500/5' : 'border-ink-700 bg-ink-800'

  return (
    <section className={`rounded-xl border p-8 text-center ${accent}`} role="alert">
      <div aria-hidden className="mb-3 text-3xl opacity-70">
        {tone === 'error' ? '⚠' : '👋'}
      </div>
      <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
      <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">{detail}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-5 rounded-lg border border-ink-600 bg-ink-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-ink-600"
        >
          Try again
        </button>
      )}
    </section>
  )
}

/** Wraps a card so an empty body still renders the heading and stays in the grid. */
export function Panel({
  title,
  count,
  children,
  className = '',
}: {
  title: string
  count?: number
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`card ${className}`}>
      <header className="mb-4 flex items-baseline justify-between gap-2">
        <h2 className="card-title">{title}</h2>
        {count !== undefined && count > 0 && (
          <span className="text-xs tabular-nums text-slate-500">{count}</span>
        )}
      </header>
      {children}
    </section>
  )
}
