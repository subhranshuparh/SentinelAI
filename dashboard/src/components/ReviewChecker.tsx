/**
 * Module 5 — Fake Review Detector panel.
 *
 * Allows pasting a set of product reviews to detect automated template bodies,
 * superlative stuffing, sponsored disclosures, and cross-review duplication.
 */

import { useState } from 'react'
import { analyzeReviews, ApiError } from '../api/client'
import type { ReviewAnalysisResponse } from '../types'

export function ReviewChecker() {
  const [text, setText] = useState('')
  const [productTitle, setProductTitle] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ReviewAnalysisResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyze = async () => {
    const rawReviews = text
      .split(/\n\s*\n/)
      .map((r) => r.trim())
      .filter((r) => r.length > 5)

    if (rawReviews.length === 0) {
      setError('Please paste at least one review body.')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const res = await analyzeReviews({
        reviews: rawReviews.map((body, i) => ({ id: `rev_${i + 1}`, body })),
        productTitle: productTitle.trim() || undefined,
      })
      setResult(res)
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Review check failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const verdictColor =
    result?.verdict === 'manipulated'
      ? 'border-red-500/40 bg-red-500/10 text-red-300'
      : result?.verdict === 'suspicious'
        ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
        : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-200">
            Module 5 — Fake Review Detector
          </h2>
          <p className="text-xs text-slate-400">
            Paste product reviews (separated by blank lines) to check for template spam, paid disclosures, and duplicate text.
          </p>
        </div>
      </div>

      <div className="space-y-3">
        <input
          type="text"
          value={productTitle}
          onChange={(e) => setProductTitle(e.target.value)}
          placeholder="Optional product name / title..."
          className="w-full rounded-lg border border-slate-700/80 bg-slate-950 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
        />

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          placeholder="Paste review set here (separate individual reviews with a blank line)..."
          className="w-full rounded-lg border border-slate-700/80 bg-slate-950 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
        />

        {error && <p className="text-xs text-red-400">{error}</p>}

        <button
          onClick={handleAnalyze}
          disabled={loading || !text.trim()}
          className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-cyan-500 disabled:opacity-50"
        >
          {loading ? 'Analyzing Review Set...' : 'Analyze Reviews'}
        </button>
      </div>

      {result && (
        <div className="mt-5 space-y-3 border-t border-slate-800 pt-4">
          <div className={`rounded-lg border p-3.5 ${verdictColor}`}>
            <div className="flex items-center justify-between">
              <span className="font-semibold uppercase tracking-wider text-xs">
                Verdict: {result.verdict}
              </span>
              <span className="text-xs font-bold">
                Risk Score: {result.risk_score}/100
              </span>
            </div>
            <p className="mt-1 text-xs">{result.summary}</p>
            <p className="mt-1 text-xs opacity-80">{result.recommendation}</p>
          </div>

          {result.signals.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300">
                Itemised Findings ({result.signals.length}):
              </h4>
              <div className="space-y-1.5">
                {result.signals.map((sig, idx) => (
                  <div
                    key={idx}
                    className="rounded border border-slate-800 bg-slate-950/80 p-2 text-xs text-slate-300"
                  >
                    <div className="flex items-center justify-between font-medium">
                      <span className="text-cyan-400">{sig.rule}</span>
                      <span className="capitalize text-slate-400">{sig.severity}</span>
                    </div>
                    <p className="mt-0.5 text-slate-300">{sig.description}</p>
                    {sig.evidence && (
                      <p className="mt-0.5 font-mono text-[11px] text-amber-300/90">
                        Excerpt: &quot;{sig.evidence}&quot;
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
