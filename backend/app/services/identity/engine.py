"""Identity scoring — turning a breach count into an explainable verdict.

Pure functions over already-fetched values. No HTTP, no DB session, no clock, so
the whole Identity sub-score is testable in milliseconds and the band boundaries
below can be argued about with a test in hand.

Two design decisions in this file are worth defending out loud, because both go
against what the other two modules do:

**1. Identity does not time-decay.** Privacy and Browsing decay with a seven-day
half-life, because behaviour changes and an old mistake should stop dominating.
A breached password is not behaviour — it is a fact about a credential that
stays true until the credential changes. Decaying it would mean the score
quietly recovers because the user *waited*, which is the precise opposite of
what we want to teach.

**2. A re-check supersedes, rather than accumulates.** Checks are keyed by their
label (or, unlabelled, by hash prefix) and only the most recent per key counts.
That is the resolution path: check "Gmail" → breached → change the password →
re-check "Gmail" → clean → the score recovers, immediately and visibly. Without
supersession there is no action a user can take that improves this number, and a
score you cannot move is a score you stop reading.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.db.models import IdentityCheck

#: Prevalence bands, and the penalty each carries into the sub-score.
#:
#: These are prevalence, not severity of the breach — a password appearing in
#: 3 million accounts is not "worse leaked" than one appearing in 5, it is
#: *guessed sooner*. Credential-stuffing lists are ordered by prevalence, so
#: prevalence is a direct proxy for how early in an attack this password is
#: tried. That is why the curve is steep at the bottom: going from 0 to 1 is the
#: qualitative jump (from "unknown to attackers" to "known"), and going from
#: 10,000 to 3,000,000 only moves you a few seconds earlier in the queue.
_BANDS: tuple[tuple[int, float, str, str], ...] = (
    # (minimum count, penalty, risk level, reason template)
    (
        100_000,
        100.0,
        "critical",
        "This password appears in {count:,} breached accounts — it is one of the first "
        "an attacker tries",
    ),
    (
        1_000,
        85.0,
        "critical",
        "This password appears in {count:,} breached accounts and is on every "
        "credential-stuffing list",
    ),
    (
        10,
        65.0,
        "high",
        "This password appears in {count:,} breached accounts, so it is already in "
        "attackers' word lists",
    ),
    (
        1,
        45.0,
        "high",
        "This password appears in {count:,} breached account(s) in the Have I Been "
        "Pwned corpus",
    ),
)

_CLEAN_REASON = (
    "This password was not found in any of the 900 million breached credentials "
    "in the Have I Been Pwned corpus"
)

#: An exact hash match against a known corpus is about as certain as this
#: product's evidence ever gets — far firmer than a semantic LLM judgement and
#: on a par with a Verhoeff-validated Aadhaar. It is not 1.0 because absence
#: from the corpus is not proof of safety: it means "not in *these* breaches".
CONFIDENCE_VERIFIED = 0.95

#: Used when the range API could not corroborate a non-zero count. The finding
#: still stands — the user watched their own browser compute it — but the number
#: went unconfirmed and the response says so rather than rounding up.
CONFIDENCE_UNVERIFIED = 0.75


@dataclass(frozen=True)
class PasswordVerdict:
    """One password's result, in both registers.

    Every field except ``breach_count`` exists to satisfy the explainability
    contract, and they are all non-optional for the same reason the Pydantic
    models make them required: a bare "breached" with no number and no next step
    is the alert that gets dismissed.
    """

    breached: bool
    breach_count: int
    risk_level: str  # low | high | critical
    confidence: float
    reason: str
    explanation: str
    recommendation: str
    penalty: float


def evaluate_password(breach_count: int, *, verified: bool | None = None) -> PasswordVerdict:
    """Turn a prevalence count into a full, explainable verdict.

    ``verified`` is the result of :func:`~app.services.identity.pwned.count_is_plausible`:
    ``True`` corroborated, ``False`` contradicted, ``None`` could not check.
    Only an outright contradiction lowers confidence to the unverified band —
    "could not check" is a network fact, and the site engine's rule applies here
    too: a signal that did not answer must not be reported as one that did.
    """
    count = max(0, int(breach_count))

    if count == 0:
        return PasswordVerdict(
            breached=False,
            breach_count=0,
            risk_level="low",
            confidence=CONFIDENCE_VERIFIED,
            reason=_CLEAN_REASON,
            explanation=(
                "Not appearing in a breach list means this password is not one attackers "
                "already have. It does not mean it is strong — a short password nobody has "
                "leaked yet is still guessable."
            ),
            recommendation="Nothing to do. Keep using a different password on every site.",
            penalty=0.0,
        )

    for threshold, penalty, level, template in _BANDS:
        if count >= threshold:
            return PasswordVerdict(
                breached=True,
                breach_count=count,
                risk_level=level,
                confidence=CONFIDENCE_VERIFIED if verified is not False else CONFIDENCE_UNVERIFIED,
                reason=template.format(count=count),
                explanation=(
                    "Attackers take passwords leaked from one website and try them on "
                    "everywhere else — banks, email, shopping. If you have used this "
                    "password anywhere else, those accounts are the ones at risk."
                ),
                recommendation=(
                    "Change this password now, starting with your email account, and do not "
                    "reuse it anywhere."
                ),
                penalty=penalty,
            )

    # Unreachable: the lowest band starts at 1 and count > 0 here. Kept because
    # a band table someone edits later should fail closed, not fall off the end.
    return evaluate_password(0, verified=verified)


def dedupe_key(check: IdentityCheck) -> str:
    """What counts as "the same password" for supersession.

    Label when the user gave one, prefix otherwise. Prefix collisions across
    genuinely different passwords are ~1 in a million and would merely merge two
    rows in a personal dashboard, so the simpler key wins over a composite.

    Public because ``services/risk/narrative.py`` singles out one password to
    build its counterfactual and must agree with this function about which rows
    are "the same password". A second definition there would let the narrative
    offer to fix a password the score has already superseded.
    """
    if check.label:
        return f"label:{check.label.strip().lower()}"
    return f"prefix:{check.hash_prefix}"


def current_checks(checks: list[IdentityCheck]) -> list[IdentityCheck]:
    """Collapse history to one row per password — the newest wins.

    Exported rather than inlined because the score, the recommendation, and the
    Identity card must all agree on which checks are live. Three call sites
    re-deriving supersession independently is how a dashboard ends up telling a
    user to change a password they changed yesterday.

    Sorting rather than trusting caller order: the dashboard query is
    newest-first and the seed script is oldest-first, and depending on that is
    the same latent bug ``score_browsing`` carries a comment about.
    """
    latest: dict[str, IdentityCheck] = {}
    for check in sorted(checks, key=lambda c: c.occurred_at):
        latest[dedupe_key(check)] = check
    return list(latest.values())


def breached_labels(checks: list[IdentityCheck]) -> list[str]:
    """Names of the passwords that are breached *right now*, after supersession.

    Falls back to a generic phrase for unlabelled checks. Deliberately never
    includes the hash prefix: this string is rendered in a recommendation the
    user may screenshot, and a prefix plus a nickname is more than this product
    should ever put on a screen together.
    """
    return [
        check.label or "One of your passwords"
        for check in current_checks(checks)
        if check.breach_count > 0
    ]


def score_identity(checks: list[IdentityCheck]) -> tuple[int | None, int]:
    """Identity sub-score from stored checks. Returns ``(score, checks_counted)``.

    ``None`` when there are no checks at all — and that is the whole point of the
    return type. Before Module 4 existed, Identity was ``None`` because the
    module was missing; now it is ``None`` because *this user* has not run a
    check. Both are "we do not know", and neither may be scored as 100. A user
    who never opens the password checker must not be rewarded with a clean bill
    of health for it.
    """
    if not checks:
        return None, 0

    live = current_checks(checks)

    # Deferred import: the risk engine owns the penalty -> score curve, and both
    # modules are imported by the dashboard router. Importing at module scope
    # would be a cycle waiting for someone to add one reference in the other
    # direction. Reusing that curve rather than writing a second one is the point
    # — three sub-scores on one screen must share a definition of what 60 means.
    from app.services.risk.engine import penalty_to_score

    penalty = sum(evaluate_password(c.breach_count).penalty for c in live)
    return penalty_to_score(penalty), len(live)


def identity_detail(score: int | None, counted: int, breached: int) -> str:
    """The sentence the dashboard's Identity card renders. Never empty."""
    if score is None:
        return "No password checked yet. Check one to complete your score."
    if breached == 0:
        return f"{counted} password{'s' if counted != 1 else ''} checked, none found in a breach."
    return (
        f"{breached} of {counted} checked password{'s' if counted != 1 else ''} "
        # The verb agrees with `breached`, not `counted` — "1 of 1 checked
        # password appear" is the kind of sentence that makes a user trust the
        # number less than they should.
        f"{'appears' if breached == 1 else 'appear'} in known data breaches."
    )
