/**
 * AI Security Assistant panel.
 *
 * Provides a conversational grounded interface over cybersecurity knowledge cards
 * and the user's active risk posture ("Why is my score 38?", "How do QR scams work?").
 */

import { useState } from 'react'
import { askAssistant, ApiError } from '../api/client'
import type { AssistantResponse } from '../types'

const STARTER_QUESTIONS = [
  'Why is my score so low?',
  'What should I fix first to improve my score?',
  'How do QR code scams work?',
  'How does password breach checking work without sending my password?',
]

export function SecurityAssistant({ deviceId }: { deviceId?: string }) {
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [response, setResponse] = useState<AssistantResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAsk = async (qText?: string) => {
    const activeQ = (qText || question).trim()
    if (!activeQ) return

    setQuestion(activeQ)
    setLoading(true)
    setError(null)

    try {
      const res = await askAssistant({ question: activeQ, deviceId })
      setResponse(res)
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Assistant request failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card-glass animate-fade-in-up">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            {/* Animated brain/AI icon */}
            <div
              className="flex h-8 w-8 items-center justify-center rounded-lg text-base"
              style={{
                background: 'linear-gradient(135deg, rgba(99,102,241,0.25), rgba(56,189,248,0.25))',
                border: '1px solid rgba(99,102,241,0.3)',
              }}
            >
              🤖
            </div>
            <h2 className="text-base font-semibold text-slate-100">
              AI Security Assistant
            </h2>
          </div>
          <p className="text-xs text-slate-500 leading-relaxed">
            Ask questions grounded in cybersecurity knowledge and your active risk posture.
          </p>
        </div>

        {/* Mode badge */}
        {response && (
          <span
            className="shrink-0 rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide animate-fade-in"
            style={{
              background: 'rgba(56,189,248,0.1)',
              border: '1px solid rgba(56,189,248,0.25)',
              color: '#38bdf8',
            }}
          >
            {response.mode}
          </span>
        )}
      </div>

      {/* Starter question chips */}
      <div className="mb-4 flex flex-wrap gap-2">
        {STARTER_QUESTIONS.map((sq, i) => (
          <button
            key={i}
            onClick={() => void handleAsk(sq)}
            disabled={loading}
            className="rounded-full border border-slate-700/80 bg-ink-800/80 px-3 py-1.5 text-[11px] font-medium text-slate-400 transition-all duration-200 hover:border-sky-500/50 hover:bg-ink-700 hover:text-sky-300 disabled:opacity-50"
          >
            {sq}
          </button>
        ))}
      </div>

      {/* Input row */}
      <div className="flex gap-2">
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void handleAsk()}
          placeholder="Ask about your risk score or any security threat…"
          disabled={loading}
          className="input flex-1 text-sm disabled:opacity-60"
        />
        <button
          id="assistant-ask-btn"
          onClick={() => void handleAsk()}
          disabled={loading || !question.trim()}
          className="btn-primary flex items-center gap-2 whitespace-nowrap px-5"
        >
          {loading ? (
            <>
              <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
              Thinking…
            </>
          ) : (
            <>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="22" y1="2" x2="11" y2="13" />
                <polygon points="22 2 15 22 11 13 2 9 22 2" />
              </svg>
              Ask
            </>
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          {error}
        </div>
      )}

      {/* Response */}
      {response && (
        <div className="mt-5 space-y-3 border-t border-slate-800/60 pt-5 animate-fade-in">
          {/* Answer card */}
          <div
            className="rounded-xl p-4"
            style={{
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(56,189,248,0.2)',
              boxShadow: '0 0 20px rgba(56,189,248,0.05)',
            }}
          >
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {response.personal_context_used && (
                <span
                  className="rounded-full px-2.5 py-0.5 text-[10px] font-semibold"
                  style={{
                    background: 'rgba(99,102,241,0.15)',
                    border: '1px solid rgba(99,102,241,0.3)',
                    color: '#a5b4fc',
                  }}
                >
                  ✦ Grounded in your posture
                </span>
              )}
            </div>

            <p className="whitespace-pre-line text-sm leading-relaxed text-slate-200">
              {response.answer}
            </p>

            {response.recommendation && (
              <div
                className="mt-3 flex items-start gap-2 rounded-lg px-3 py-2.5"
                style={{ background: 'rgba(56,189,248,0.06)', border: '1px solid rgba(56,189,248,0.15)' }}
              >
                <span className="mt-0.5 text-xs text-cyan-400">💡</span>
                <p className="text-xs text-cyan-300/90 font-medium leading-relaxed">
                  {response.recommendation}
                </p>
              </div>
            )}
          </div>

          {/* Sources */}
          {response.sources.length > 0 && (
            <div>
              <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Knowledge Sources ({response.sources.length})
              </h4>
              <div className="flex flex-wrap gap-2">
                {response.sources.map((src) => (
                  <div
                    key={src.id}
                    className="rounded-lg border border-slate-800 bg-ink-800/60 px-3 py-2 text-xs transition hover:border-slate-700"
                  >
                    <span className="font-semibold text-slate-300">{src.title}</span>
                    <span className="ml-2 text-[10px] text-slate-600">[{src.id}]</span>
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
