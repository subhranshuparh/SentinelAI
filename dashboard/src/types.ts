/**
 * Hand-mirrored from `backend/app/schemas/dashboard.py`.
 *
 * No codegen and no OpenAPI client generator: this is ~50 lines that change
 * twice, against a toolchain that costs an hour to wire and breaks when the
 * backend is not running. If these drift, `npm run build` fails at the usage
 * site, which is the only guarantee that actually matters here.
 *
 * The nullable fields below are nullable *on purpose* and are the whole point of
 * the model — `null` means "we could not measure this", which the UI must render
 * differently from a zero. Typing them as `number | null` makes the compiler
 * refuse to let a component forget.
 */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Verdict = 'safe' | 'suspicious' | 'dangerous' | 'unknown'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type ComponentName = 'privacy' | 'browsing' | 'identity'

export interface Contribution {
  component: ComponentName
  /** null when the component could not be measured at all. Never render as 0. */
  score: number | null
  weight: number
  /** Higher than `weight` when another component was unavailable. */
  weight_applied: number
  points: number
  detail: string
  event_count: number
}

export interface Recommendation {
  priority: 'high' | 'medium' | 'low'
  title: string
  detail: string
  /** Machine tag, so a click routes without parsing English. */
  action: string
}

// --- Module 8: the score, explained in sentences ----------------------------

export type DriverSeverity = 'high' | 'medium' | 'low' | 'info'

export interface Driver {
  /** Machine tag. Group and route on this, never on `sentence`. */
  code: string
  sentence: string
  /**
   * Points the overall score would recover if this were resolved, measured by
   * re-running the score without it.
   *
   * `null` means the cost could not be computed — **never** that it was zero.
   * Rendered as an em dash, the same way `ScoreBreakdown` renders an unmeasured
   * component, so a blank can never be misread as a number.
   */
  points: number | null
  severity: DriverSeverity
  count: number
}

export interface Lever {
  code: string
  sentence: string
  current_score: number
  projected_score: number
  /** Always positive. A lever that changes nothing is not offered at all. */
  delta: number
  action: string
}

export interface Narrative {
  headline: string
  /** What the score could not see. Never phrased as reassurance. */
  coverage: string
  drivers: Driver[]
  /** `null` when nothing the user can do would move the number. */
  biggest_lever: Lever | null
}

export interface TimelineEvent {
  kind: 'pii' | 'site' | 'identity'
  occurred_at: string
  title: string
  detail: string
  severity: Severity
  /** Always the masked form. There is no column holding the original. */
  masked_preview: string | null
  site: string | null
}

export interface FlaggedSite {
  domain: string
  verdict: Verdict
  trust_score: number
  last_seen: string
  visits: number
  reasons: { detail?: string; weight?: string }[]
}

export interface TrendPoint {
  captured_at: string
  overall: number
  privacy: number
  browsing: number
}

export interface DashboardSummary {
  device_id: string
  overall_score: number
  risk_level: RiskLevel
  headline: string
  /** Share of the model's weight that was measurable. 0.8 = one area is dark. */
  confidence: number
  privacy_score: number | null
  browsing_score: number | null
  identity_score: number | null
  narrative: Narrative
  contributions: Contribution[]
  recommendations: Recommendation[]
  timeline: TimelineEvent[]
  flagged_sites: FlaggedSite[]
  trend: TrendPoint[]
  total_pii_events: number
  total_masked: number
  total_sites_flagged: number
  window_days: number
}

// --- Module 3: phishing email check ----------------------------------------
//
// Mirrored from `backend/app/schemas/phishing.py`. Note that this response is
// never stored and never appears in `DashboardSummary` — the email is analysed
// and forgotten, so there is nothing to fold into the score.

/** `bad` = a finding · `good` = checked and clean · `unknown` = not checked. */
export type SignalWeight = 'bad' | 'good' | 'unknown'

export interface PhishingSignal {
  signal: string
  detail: string
  weight: SignalWeight
  /** A verbatim excerpt from the pasted email, when the row has one. */
  evidence: string | null
}

export interface EmailAnalysis {
  verdict: Verdict
  /**
   * 0-100, and the direction is **inverted** compared with every other score in
   * this app: here HIGHER MEANS MORE DANGEROUS. The component that renders it
   * says so in words next to the number, because a bare "90" next to a green
   * "92" elsewhere on the same screen would be read as good news.
   */
  risk_score: number
  confidence: number
  summary: string
  recommendation: string
  signals: PhishingSignal[]
  intent: string | null
  intent_label: string | null
  /** True when the AI tier did not answer and only pattern checks ran. */
  heuristics_only: boolean
}

// --- Modules 9 & 12: the screenshot checker --------------------------------
//
// Mirrored from `backend/app/schemas/pii.py` and `schemas/qr.py`. Both of these
// are used by one component — `ScreenshotChecker` — which reads an image locally
// and sends only the *text* it extracted. The image itself never reaches the
// backend, so there is no request type here that carries one.

/** One thing found in text. `FindingOut` in `schemas/pii.py`. */
export interface Finding {
  pii_type: string
  label: string
  risk_level: RiskLevel
  confidence: number
  /**
   * `regex` · `llm` · `ocr`. The last is Module 12's: the value only validated
   * after characters an optical reader commonly confuses were corrected, and a
   * finding carrying it is a *corrected read*, which the UI says out loud.
   */
  detection_tier: string
  reason: string
  explanation: string
  recommendation: string
  start: number
  end: number
  masked_preview: string
  suggested_replacement: string
  /** Module 10. `null` on any scan that was not a paste — "not assessed". */
  destination_fit: string | null
  destination_note: string | null
}

export interface ScanResult {
  /** 0-100, and **inverted** like `EmailAnalysis.risk_score`: higher is worse. */
  risk_score: number
  risk_level: RiskLevel
  /** False only when the AI tier should have run and could not. */
  tier_2_available: boolean
  tier_2_status: 'ran' | 'skipped' | 'disabled' | 'unavailable'
  findings: Finding[]
  destination: {
    origin: string
    name: string
    kind: string
    kind_label: string
    recognised: boolean
  } | null
}

export interface QrSignal {
  signal: string
  detail: string
  weight: SignalWeight
  evidence: string | null
}

export interface QrCheck {
  kind: string
  verdict: Verdict
  /** Inverted, as above. */
  risk_score: number
  confidence: number
  summary: string
  recommendation: string
  /**
   * Where the code actually goes, in plain words — "Pays INR 50,000 to
   * someone@ybl". The most important field in the response: a QR code is
   * unreadable to a human, so simply showing its destination is most of the
   * protection this feature provides.
   */
  destination: string
  signals: QrSignal[]
  domain: string | null
  trust_score: number | null
}

// --- Module 5: Fake Review Detector ------------------------------------------

export interface ReviewItem {
  id?: string
  title?: string
  body: string
  rating?: number
  reviewer_name?: string
  posted_at?: string
  verified_purchase?: boolean
}

export interface ReviewSignal {
  rule: string
  group: 'language' | 'pattern' | 'reviewer' | 'ai_tier'
  severity: Severity
  description: string
  evidence?: string | null
  affected_review_ids: string[]
}

export interface ReviewItemResult {
  id: string
  verdict: 'manipulated' | 'suspicious' | 'organic' | 'unknown'
  risk_score: number
  signals: ReviewSignal[]
}

export interface ReviewAnalysisResponse {
  verdict: 'manipulated' | 'suspicious' | 'organic' | 'unknown'
  risk_score: number
  confidence: number
  summary: string
  recommendation: string
  signals: ReviewSignal[]
  reviews: ReviewItemResult[]
  tier: 'heuristics_only' | 'full'
}

// --- Module 7: Grounded Security Assistant ------------------------------------

export interface AssistantSourceCard {
  id: string
  title: string
  summary: string
  tags: string[]
}

export interface AssistantResponse {
  answered: boolean
  answer: string
  mode: 'extractive' | 'generated'
  sources: AssistantSourceCard[]
  personal_context_used: boolean
  recommendation?: string | null
}
