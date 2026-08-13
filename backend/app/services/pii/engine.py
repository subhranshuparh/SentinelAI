"""PII scan orchestration — the service the router calls.

Responsibilities, in order:

1. Run Tier 1 (regex + checksums). Always. No network.
2. Run Tier 2 (Gemini) only when the gate below opens — short text and text
   Tier 1 is already decisive about never reach the model. Failure is absorbed:
   the semantic tier can be dead and this function still returns.
3. Score the message.
4. Persist a *masked* record.

No FastAPI imports. Everything below is callable from a test or a REPL.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from sqlalchemy.orm import Session

from app.db.models import Device, PiiEvent, RiskLevel, utcnow
from app.services.llm.gemini import analyze_context
from app.services.pii.destinations import Destination, classify, note_for
from app.services.pii.detectors import Finding, resolve_overlaps, scan_text
from app.services.pii.ocr_normalise import recover

# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------
#
# Per-message *risk* score: 0 = nothing sensitive, 100 = do not send this.
# Note the direction. The dashboard's Security Score runs the other way (higher
# is better) — they are different quantities and are deliberately never mixed.

_LEVEL_SCORE = {
    RiskLevel.LOW.value: 25,
    RiskLevel.MEDIUM.value: 50,
    RiskLevel.HIGH.value: 80,
    RiskLevel.CRITICAL.value: 100,
}

# Each additional finding beyond the first adds this much, capped below.
# Rationale: three separate items in one message is materially worse than one —
# it is the difference between a slip and a full identity packet. But the
# increment is small because severity, not count, should dominate: ten email
# addresses must never outrank one leaked API key.
_ADDITIONAL_FINDING_BONUS = 6
_MAX_BONUS = 18


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    """Return ``(risk_score, risk_level)`` for one message.

    The base is the single worst finding, weighted by its confidence, so a
    low-confidence guess cannot alone produce an alarming number. Volume adds a
    capped bonus on top.
    """
    if not findings:
        return 0, RiskLevel.LOW.value

    worst = max(findings, key=lambda f: (_LEVEL_SCORE[f.risk_level], f.confidence))
    base = _LEVEL_SCORE[worst.risk_level] * worst.confidence

    bonus = min(_MAX_BONUS, (len(findings) - 1) * _ADDITIONAL_FINDING_BONUS)
    score = min(100, round(base + bonus))

    # Derive the displayed band from the final score so the badge and the number
    # can never disagree — a "92 / low risk" toast destroys trust instantly.
    if score >= 85:
        level = RiskLevel.CRITICAL.value
    elif score >= 60:
        level = RiskLevel.HIGH.value
    elif score >= 30:
        level = RiskLevel.MEDIUM.value
    else:
        level = RiskLevel.LOW.value
    return score, level


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    risk_score: int
    risk_level: str
    #: False *only* when the semantic tier should have run and could not. The UI
    #: must surface this: "found nothing" and "could not fully check" are
    #: different answers and merging them is how a tool quietly starts lying.
    tier_2_available: bool
    #: The precise story, for the dashboard and for debugging on stage:
    #:   ran         - the semantic tier answered; its findings are included
    #:   skipped     - not needed (text too short, or Tier 1 already certain)
    #:   disabled    - no key, or the feature flag is off
    #:   unavailable - it should have run and failed. The only status that
    #:                 sets tier_2_available to False.
    tier_2_status: str = "skipped"
    #: Module 10. Populated only by ``assess_destination`` — so ``None`` here
    #: means "this was a typed scan and the question was never asked", which is
    #: a different statement from "we asked and the site was fine".
    destination: Destination | None = None


# --------------------------------------------------------------------------
# Tier-2 gate
# --------------------------------------------------------------------------
#
# Every call here costs real money and ~600ms. The gate is what makes a hybrid
# architecture cheaper than "just call the LLM", so it is a first-class piece of
# the design rather than an optimisation bolted on later.

#: Context-dependent PII lives in prose. "42 Oak Street, Bandra" is 21 chars;
#: below roughly this length there is not enough sentence to judge.
MIN_TIER_2_CHARS = 40

#: A long string with no word structure is a token, a URL, or base64 — all of
#: which Tier 1 handles and none of which need semantic reading.
MIN_TIER_2_WORDS = 6

#: When Tier 1 has already found something at these levels, the user is being
#: warned firmly and the message is going to be edited anyway. A second network
#: round trip to possibly add a fourth line to the toast is not worth 600ms.
_TIER_1_DECISIVE = frozenset({"high", "critical"})


def should_run_tier_2(text: str, findings: list[Finding]) -> bool:
    """Decide whether ``text`` is worth an LLM call.

    Kept public and pure so the cost model is a function a judge can read, and
    so the "why not just call the LLM every time?" question has a code answer.
    """
    if any(f.risk_level in _TIER_1_DECISIVE for f in findings):
        return False
    stripped = text.strip()
    if len(stripped) < MIN_TIER_2_CHARS:
        return False
    return len(stripped.split()) >= MIN_TIER_2_WORDS


def scan(
    text: str,
    suppressed_types: frozenset[str] | None = None,
    *,
    enable_tier_2: bool = False,
    from_ocr: bool = False,
) -> ScanResult:
    """Scan ``text`` and return findings with a message-level risk score.

    Tier 1 always runs and always completes. Tier 2 runs only when the gate
    above opens, and its failure is absorbed here — ``analyze_context`` returns
    ``None`` rather than raising, so there is no path in which a dead Gemini
    turns into a failed scan.

    ``from_ocr`` enables the Module 12 recovery pass. It defaults to False and
    every existing caller leaves it there, because rewriting characters is only
    ever justified when a camera and a neural net stood between the user and the
    text. On typed input the correction would be pure fabrication.
    """
    suppressed = suppressed_types or frozenset()
    findings = scan_text(text, suppressed)

    if from_ocr:
        # Merged through ``resolve_overlaps`` rather than appended, so a number
        # the direct scan already matched cannot also be reported as a corrected
        # read of itself. Placed *before* the Tier-2 gate on purpose: an Aadhaar
        # recovered here is a high-risk finding, and the gate's whole job is to
        # skip a paid LLM call once Tier 1 is already decisive.
        recovered = recover(text, suppressed)
        if recovered:
            findings = resolve_overlaps(findings + recovered)

    tier_2_status = "disabled" if not enable_tier_2 else "skipped"

    if enable_tier_2 and should_run_tier_2(text, findings):
        semantic = analyze_context(text)
        if semantic is None:
            # Ran, or wanted to, and got no answer. This is the one case the
            # extension shows as "couldn't fully check".
            tier_2_status = "unavailable"
        else:
            tier_2_status = "ran"
            # Suppression is applied to Tier 2 as well: "always allow here" is a
            # promise about a category, not about which tier happened to find it.
            semantic = [f for f in semantic if f.pii_type not in suppressed]
            findings = resolve_overlaps(findings + semantic)

    risk_score, risk_level = score_findings(findings)
    return ScanResult(
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        tier_2_available=tier_2_status != "unavailable",
        tier_2_status=tier_2_status,
    )


def assess_destination(result: ScanResult, site_origin: str) -> ScanResult:
    """Attach "…and it was going *there*" to every finding. Module 10.

    Called only for paste scans. Two things it deliberately does not do:

    * **It does not change the risk score.** Destination is context for the
      human, not an input to the arithmetic. Letting a recognised site lower a
      score would mean a convincing clone of a bank could argue its way out of a
      warning, and letting an unrecognised one raise it would fire on every
      intranet in the world.
    * **It does not drop findings.** A credential pasted into the AWS console is
      graded ``expected`` and still reported. The user gets a calmer sentence,
      not silence — the extension decides what to do with that, and only after
      it has been told what was found.

    Pure and total: ``classify`` never raises, so this cannot turn a successful
    scan into a failed request.
    """
    destination = classify(site_origin)
    annotated: list[Finding] = []
    for finding in result.findings:
        fit, note = note_for(finding.label, finding.pii_type, destination)
        annotated.append(replace(finding, destination_fit=fit.value, destination_note=note))
    return replace(result, findings=annotated, destination=destination)


def persist_scan(
    db: Session,
    device_id: str,
    result: ScanResult,
    site_origin: str,
    field_kind: str,
) -> None:
    """Record findings for the dashboard.

    Writes ``masked_preview`` and never the matched substring — the raw value
    exists only in the request body and this function's caller frame, and there
    is no column that could hold it even by mistake.

    Deliberately silent when there is nothing to record: writing a row per
    keystroke would swamp the timeline and make the demo unreadable.
    """
    if not result.findings:
        return

    device = db.get(Device, device_id)
    if device is None:
        device = Device(id=device_id)
        db.add(device)
    else:
        device.last_seen_at = utcnow()

    for finding in result.findings:
        db.add(
            PiiEvent(
                device_id=device_id,
                site_origin=site_origin,
                field_kind=field_kind,
                pii_type=finding.pii_type,
                risk_level=finding.risk_level,
                confidence=finding.confidence,
                detection_tier=finding.detection_tier,
                reason=finding.reason,
                masked_preview=finding.masked_preview,
            )
        )
    db.commit()
