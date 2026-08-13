/**
 * Module 7 — Grounded Security Assistant panel.
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
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg">
      <div className="mb-4">
        <h2 className="text-base font-semibold text-slate-200">
          Module 7 — AI Security Assistant
        </h2>
        <p className="text-xs text-slate-400">
          Ask questions grounded in cybersecurity knowledge cards and your active risk posture.
        </p>
      </div>

      <div className="mb-3 flex flex-wrap gap-1.5">
        {STARTER_QUESTIONS.map((sq, i) => (
          <button
            key={i}
            onClick={() => void handleAsk(sq)}
            className="rounded-full border border-slate-700 bg-slate-800/60 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-500/50 hover:bg-slate-800"
          >
            {sq}
          </button>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void handleAsk()}
          placeholder="Ask about your risk score or security threats..."
          className="flex-1 rounded-lg border border-slate-700/80 bg-slate-950 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
        />
        <button
          onClick={() => void handleAsk()}
          disabled={loading || !question.trim()}
          className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-cyan-500 disabled:opacity-50"
        >
          {loading ? 'Thinking...' : 'Ask Assistant'}
        </button>
      </div>

      {error && <p className="mt-2 text-xs text-red-400">{error}</p>}

      {response && (
        <div className="mt-4 space-y-3 border-t border-slate-800 pt-4">
          <div className="rounded-lg border border-cyan-500/30 bg-slate-950 p-3.5">
            <div className="mb-2 flex items-center justify-between text-[11px]">
              <span className="font-semibold text-cyan-400">
                Mode: {response.mode.toUpperCase()}
              </span>
              {response.personal_context_used && (
                <span className="rounded bg-indigo-500/20 px-2 py-0.5 font-medium text-indigo-300">
                  Grounded in your posture
                </span>
              )}
            </div>

            <p className="whitespace-pre-line text-xs leading-relaxed text-slate-200">
              {response.answer}
            </p>

            {response.recommendation && (
              <p className="mt-2 text-xs text-cyan-300/90 font-medium">
                Recommendation: {response.recommendation}
              </p>
            )}
          </div>

          {response.sources.length > 0 && (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-slate-400">
                Cited Knowledge Sources ({response.sources.length}):
              </h4>
              <div className="flex flex-wrap gap-2">
                {response.sources.map((src) => (
                  <div
                    key={src.id}
                    className="rounded border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300"
                  >
                    <span className="font-semibold text-slate-200">{src.title}</span>
                    <span className="ml-2 text-[10px] text-slate-500">[{src.id}]</span>
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
