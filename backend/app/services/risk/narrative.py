"""Module 8 — the story behind the number.

``ScoreBreakdown`` already proves the arithmetic: 46 = 37 x 0.5 + 55 x 0.5, every
weight published, every point traceable. That is a *correct* explanation and, for
most of the people this product is written for, an unreadable one. "Privacy 37,
weight 50%, contributed 18.5 points" is not a sentence a worried 68-year-old
reads twice.

This module turns the same rows into three things a person can act on:

1. **Drivers** — one line per real cause, in plain language, each carrying the
   points it actually cost.
2. **The biggest lever** — the single change that would move the score furthest,
   with the number it would move it to.
3. **Coverage** — what the score could not see, said out loud.

Two design decisions are the whole substance of this file.

**No language model, anywhere.** Every sentence below is a Python template keyed
by a machine tag. The only values interpolated are integers, domain names, and
the user's own password labels. That is not a shortcut — a narrative is the most
action-provoking text in the product, and the one place where a fluent
hallucination would do the most damage. ``services/phishing`` makes the same call
for the same reason: the model classifies, Python writes.

**The lever is a counterfactual, not an opinion.** ``risk/engine.compute`` is a
pure function of rows, so "change your Amazon password and your score goes 46 to
58" is answerable by *re-running the score with that password changed*. Every
number in a lever sentence is arithmetic the user could redo by hand. Nothing
here estimates, and nothing here rounds a guess into a promise.

The missing-signal rule holds as it does everywhere else. A cause whose cost
cannot be computed honestly reports ``points=None`` — "not measured" — and is
barred from becoming the lever. A zero is never substituted for a blank.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.db.models import IdentityCheck, PiiEvent, SiteCheck, UserAction

# ---------------------------------------------------------------------------
# Shape of the output
# ---------------------------------------------------------------------------

#: Same cap, and the same reasoning, as ``_build_recommendations``: a list of
#: eleven explanations is a list of zero explanations. Four lines is what fits on
#: a phone screen without scrolling and what a person reads before deciding.
MAX_DRIVERS = 4

#: A cause worth fewer points than this is dropped. "This cost you 0 points" is
#: noise dressed as insight, and it pushes a cause that matters off the list.
MIN_REPORTABLE_POINTS = 1

#: Password labels are user-supplied. The column already bounds them, but this
#: file renders them into a sentence someone may screenshot, so the bound is
#: restated here rather than assumed from a schema three layers away.
MAX_LABEL_CHARS = 40

_SEVERE_LEVELS = frozenset({"high", "critical"})
_UNRESOLVED_ACTIONS = frozenset({UserAction.NONE.value, UserAction.IGNORED.value})
_RESOLVED_ACTIONS = frozenset({UserAction.MASKED.value, UserAction.ALLOWLISTED.value})

#: Display order when two drivers cost the same. Lower sorts first.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Driver:
    """One reason the score is what it is.

    ``points`` is the honest, load-bearing field: how many points the overall
    score would recover if this one cause were resolved. It is measured by
    re-running the score without the cause, not derived from a penalty table, so
    a driver can never claim a cost the score does not actually reflect.

    ``None`` means the cost could not be computed — never that it was zero.
    """

    #: Machine tag. The UI groups and routes on this; it never parses ``sentence``.
    code: str
    #: Plain language, authored in Python. Required, never empty.
    sentence: str
    #: Points the overall score would recover. ``None`` = not measured.
    points: int | None
    severity: str  # high | medium | low | info
    #: How many rows are behind this line. Zero only for structural drivers.
    count: int


@dataclass(frozen=True)
class Lever:
    """The one change worth making first, with the score it would produce.

    Every field is a number the user could verify by doing the thing and
    refreshing. That is the only reason this is allowed to exist as advice.
    """

    #: The ``Driver.code`` this lever resolves.
    code: str
    sentence: str
    current_score: int
    projected_score: int
    #: ``projected_score - current_score``. Always positive; a lever that does not
    #: improve the score is not offered.
    delta: int
    #: Machine tag, shared vocabulary with ``Recommendation.action`` so a click
    #: routes the same way from either surface.
    action: str


@dataclass(frozen=True)
class Narrative:
    """Everything the score explains about itself, in prose.

    ``coverage`` is required and never empty on purpose: it is the sentence that
    stops a partial score from reading as a clean one.
    """

    headline: str
    coverage: str
    drivers: list[Driver] = field(default_factory=list)
    #: ``None`` when nothing the user can do would move the number. Silence beats
    #: filler advice — inventing a lever teaches users the advice is decorative.
    biggest_lever: Lever | None = None


# ---------------------------------------------------------------------------
# Candidate causes (internal)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Candidate:
    """A cause, plus exactly which rows to remove to price it.

    The removal sets are what make the counterfactual exact. A candidate that
    described itself in prose but could not say which rows it owned would have to
    price itself from a penalty table, and a second copy of the penalty table is
    how a breakdown starts disagreeing with its own total.
    """

    code: str
    sentence: str
    severity: str
    count: int
    #: Positions in the ``events`` list this candidate accounts for.
    event_indices: frozenset[int] = frozenset()
    #: Domains this candidate accounts for. Removal is by domain because
    #: ``score_browsing`` already collapses repeat visits to one per domain.
    domains: frozenset[str] = frozenset()
    #: ``identity.dedupe_key`` values whose passwords this candidate accounts for.
    identity_keys: frozenset[str] = frozenset()
    #: Survives the ``MIN_REPORTABLE_POINTS`` filter even at zero cost. For causes
    #: whose point cost is zero but whose *absence from the score* is the message.
    always_show: bool = False
    #: False when this cause is real but its cost cannot be computed — reported as
    #: ``points=None``. Distinct from a candidate with empty removal sets, which
    #: prices honestly at zero. Without this flag the two are indistinguishable
    #: and an unmeasured cost silently becomes a measured "free".
    priceable: bool = True
    #: Whether this may become the biggest lever. False for causes where the user
    #: has already done the right thing, or where the cost is ours not theirs.
    can_be_lever: bool = False
    #: Sentence used when this becomes the lever. Requires the projected score, so
    #: it is a template with a single ``{score}`` placeholder.
    lever_template: str = ""
    lever_action: str = ""


def _host(origin: str) -> str:
    """Strip the scheme for display. The origin is already path-free by schema."""
    return origin.replace("https://", "").replace("http://", "")


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


def _and_others(names: list[str]) -> str:
    """"a.com", "a.com and 1 other site", "a.com and 3 other sites"."""
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    extra = len(names) - 1
    return f"{names[0]} and {extra} other {_plural(extra, 'site')}"


def _safe_label(label: str | None) -> str:
    """Render a user-supplied password nickname, bounded and never empty.

    Truncated rather than rejected: a long nickname is a UI problem, not a
    security event, and dropping the line entirely would hide a breached
    password. Note what is deliberately *not* here — no hash prefix, no hint of
    the password. Same rule as ``identity.breached_labels``.
    """
    cleaned = (label or "").strip()
    if not cleaned:
        return "One of your passwords"
    if len(cleaned) > MAX_LABEL_CHARS:
        return f"{cleaned[: MAX_LABEL_CHARS - 1]}…"
    return cleaned


# ---------------------------------------------------------------------------
# Building the candidate list
# ---------------------------------------------------------------------------


def _pii_candidates(events: list[PiiEvent]) -> list[_Candidate]:
    """Split typing findings into causes the user can tell apart.

    Three groups, and the split is the point. "Six findings" tells a user
    nothing; "two you sent unprotected, four SentinelAI hid for you" tells them
    where they stand and credits them for the part they got right.
    """
    severe: list[int] = []
    minor: list[int] = []
    resolved: list[int] = []

    for index, event in enumerate(events):
        if event.action_taken in _RESOLVED_ACTIONS:
            resolved.append(index)
        elif event.risk_level in _SEVERE_LEVELS:
            severe.append(index)
        elif event.action_taken in _UNRESOLVED_ACTIONS:
            minor.append(index)
        else:
            # Unknown action value — a row written by a future version. Counted
            # with the unresolved group, because assuming it was handled would be
            # the optimistic reading, and this file does not take those.
            minor.append(index)

    candidates: list[_Candidate] = []

    if severe:
        sites = _and_others(sorted({_host(events[i].site_origin) for i in severe}))
        candidates.append(
            _Candidate(
                code="pii_sent_unprotected",
                sentence=(
                    f"You typed {len(severe)} sensitive "
                    f"{_plural(len(severe), 'detail')} on {sites} without hiding "
                    f"{_plural(len(severe), 'it', 'them')}."
                ),
                severity="high",
                count=len(severe),
                event_indices=frozenset(severe),
                can_be_lever=True,
                lever_template=(
                    "Hide sensitive details when SentinelAI offers to, instead of sending "
                    "them. Doing that would put your score at {score} out of 100."
                ),
                lever_action="review_pii",
            )
        )

    if minor:
        candidates.append(
            _Candidate(
                code="pii_minor_unprotected",
                sentence=(
                    f"{len(minor)} lower-risk {_plural(len(minor), 'detail')}, such as a "
                    f"phone number or email address, went out unprotected."
                ),
                severity="medium",
                count=len(minor),
                event_indices=frozenset(minor),
                can_be_lever=True,
                lever_template=(
                    "Hide the everyday details too — phone numbers and email addresses are "
                    "what junk callers buy. Your score would be {score} out of 100."
                ),
                lever_action="review_pii",
            )
        )

    if resolved:
        candidates.append(
            _Candidate(
                code="pii_protected",
                sentence=(
                    f"SentinelAI hid {len(resolved)} sensitive "
                    f"{_plural(len(resolved), 'detail')} before "
                    f"{_plural(len(resolved), 'it', 'they')} "
                    f"{_plural(len(resolved), 'was', 'were')} sent. "
                    f"{_plural(len(resolved), 'That barely counts', 'Those barely count')} "
                    f"against you."
                ),
                severity="low",
                count=len(resolved),
                event_indices=frozenset(resolved),
                # Never a lever. The user already did the right thing, and telling
                # them to fix it would punish them for taking the advice.
                can_be_lever=False,
            )
        )

    return candidates


def _site_candidates(checks: list[SiteCheck]) -> list[_Candidate]:
    """One cause per verdict band, over domains rather than visits.

    Deduplicated by domain to match ``score_browsing`` exactly: it prices the
    worst verdict per domain once, so a narrative counting visits would quote a
    cost the score never charged.
    """
    worst: dict[str, str] = {}
    rank = {"dangerous": 3, "suspicious": 2, "unknown": 1, "safe": 0}
    for check in checks:
        if rank.get(check.verdict, 0) > rank.get(worst.get(check.domain, "safe"), 0):
            worst[check.domain] = check.verdict

    by_verdict: dict[str, list[str]] = {"dangerous": [], "suspicious": [], "unknown": []}
    for domain, verdict in worst.items():
        if verdict in by_verdict:
            by_verdict[verdict].append(domain)

    candidates: list[_Candidate] = []

    dangerous = sorted(by_verdict["dangerous"])
    if dangerous:
        candidates.append(
            _Candidate(
                code="site_dangerous",
                sentence=(
                    f"You visited {len(dangerous)} {_plural(len(dangerous), 'website')} "
                    f"that looked like a scam, including {dangerous[0]}."
                ),
                severity="high",
                count=len(dangerous),
                domains=frozenset(dangerous),
                can_be_lever=True,
                # Worded as avoidance, not undoing: the visit happened and cannot
                # be taken back. What is true is that it decays out of the score
                # over about a week, and staying away is what lets that happen.
                lever_template=(
                    "Stay away from {domain}. That visit fades from your score over the "
                    "next week, and without it you would be at {score} out of 100 today."
                ),
                lever_action="review_sites",
            )
        )

    suspicious = sorted(by_verdict["suspicious"])
    if suspicious:
        candidates.append(
            _Candidate(
                code="site_suspicious",
                sentence=(
                    f"{len(suspicious)} {_plural(len(suspicious), 'website')} did not look "
                    f"quite right, including {suspicious[0]}."
                ),
                severity="medium",
                count=len(suspicious),
                domains=frozenset(suspicious),
                can_be_lever=True,
                lever_template=(
                    "Check the web address carefully before using {domain} again. Without "
                    "it your score would be {score} out of 100."
                ),
                lever_action="review_sites",
            )
        )

    unknown = sorted(by_verdict["unknown"])
    if unknown:
        candidates.append(
            _Candidate(
                code="site_unchecked",
                sentence=(
                    f"{len(unknown)} {_plural(len(unknown), 'website')} could not be "
                    f"checked, so SentinelAI cannot vouch for "
                    f"{_plural(len(unknown), 'it', 'them')} either way."
                ),
                severity="low",
                count=len(unknown),
                domains=frozenset(unknown),
                # Never a lever, and this is the missing-signal rule showing up in
                # the advice layer: a check that could not run is our failure, not
                # the user's behaviour. Telling them to fix our offline lookup
                # would be blaming them for hotel wifi.
                can_be_lever=False,
            )
        )

    return candidates


def _identity_candidates(
    identity_checks: list[IdentityCheck] | None,
    identity_score: int | None,
    breached_passwords: list[str],
) -> list[_Candidate]:
    """One candidate per breached password, plus the not-measured case.

    Per password rather than one grouped line, because the lever has to be able
    to say *which* password to change. "Change one of your passwords" is advice
    nobody follows.
    """
    # Deferred: ``identity.engine`` imports the penalty curve from ``risk.engine``,
    # which imports this module. Same cycle-avoidance the identity module already
    # documents at its own ``penalty_to_score`` import.
    from app.services.identity.engine import current_checks, dedupe_key

    if identity_score is None:
        return [
            _Candidate(
                code="identity_unmeasured",
                sentence=(
                    "No password has been checked yet, so a third of your score is missing. "
                    "That gap is not counted as safe."
                ),
                severity="info",
                count=0,
                # Zero point cost by construction — an unmeasured area contributes
                # nothing. Shown anyway, because its absence from the score is
                # precisely the thing a user needs told.
                always_show=True,
                can_be_lever=False,
            )
        ]

    if identity_checks is None:
        # The aggregate score is known but the rows are not, so the per-password
        # counterfactual cannot be run. Name the passwords, price them as
        # unmeasured, and refuse to be the lever. See ``compute``'s docstring.
        return [
            _Candidate(
                code="identity_breached",
                sentence=(
                    f"{_safe_label(label)} appears in known data breaches, so attackers "
                    f"already have it."
                ),
                severity="high",
                count=1,
                always_show=True,
                can_be_lever=False,
                priceable=False,
            )
            for label in breached_passwords
        ]

    candidates: list[_Candidate] = []
    for check in current_checks(identity_checks):
        if check.breach_count <= 0:
            continue
        label = _safe_label(check.label)
        candidates.append(
            _Candidate(
                code="identity_breached",
                sentence=(
                    f"{label} appears in {check.breach_count:,} breached accounts, so "
                    f"attackers already have it."
                ),
                severity="high",
                count=1,
                identity_keys=frozenset({dedupe_key(check)}),
                can_be_lever=True,
                lever_template=(
                    f"Change your {label} password, starting with any account where you "
                    "reused it. Your score would go to {score} out of 100."
                ),
                lever_action="change_password",
            )
        )
    return candidates


# ---------------------------------------------------------------------------
# Pricing a candidate — the counterfactual
# ---------------------------------------------------------------------------


def _overall_without(
    candidate: _Candidate,
    events: list[PiiEvent],
    checks: list[SiteCheck],
    identity_checks: list[IdentityCheck] | None,
    identity_score: int | None,
    now: datetime,
) -> int | None:
    """Re-run the score as if this cause had been dealt with.

    Not "as if the row never existed" in the identity case — as if the password
    had been *changed and re-checked clean*. Deleting the row would drop Identity
    to ``None`` and redistribute its weight, which is what happens when a user
    never checks a password, not when they fix one. Modelling the wrong action
    would produce a lever that promises a score the user cannot reach.

    Returns ``None`` when the cost is not computable, which the caller reports as
    unmeasured rather than folding into a zero.
    """
    if not candidate.priceable:
        return None

    # Deferred for the same cycle reason as above: ``risk.engine`` imports this
    # module at import time, so this module cannot import it at module scope.
    from app.services.identity.engine import current_checks, dedupe_key, evaluate_password
    from app.services.risk.engine import (
        penalty_to_score,
        score_browsing,
        score_privacy,
        weighted_overall,
    )

    kept_events = [e for i, e in enumerate(events) if i not in candidate.event_indices]
    kept_checks = [c for c in checks if c.domain not in candidate.domains]

    new_identity = identity_score
    if candidate.identity_keys:
        if identity_checks is None:
            return None
        # The named passwords become clean checks rather than absent ones, so the
        # component keeps its weight and the delta reflects the real fix.
        penalty = sum(
            evaluate_password(check.breach_count).penalty
            for check in current_checks(identity_checks)
            if dedupe_key(check) not in candidate.identity_keys
        )
        new_identity = penalty_to_score(penalty)

    privacy, _ = score_privacy(kept_events, now)
    browsing, _ = score_browsing(kept_checks, now)
    overall, _, _ = weighted_overall(privacy, browsing, new_identity)
    return overall


# ---------------------------------------------------------------------------
# Sentences that describe the whole picture
# ---------------------------------------------------------------------------


def _coverage_sentence(confidence: float, unchecked_sites: int) -> str:
    """State what the score could not see. Required, and never reassuring.

    This sentence exists because a score built from two of three areas looks
    exactly like a score built from three. Everything else in this codebase
    refuses to let a missing signal read as a passing one; this is that rule in
    prose, on the screen, where a person will actually meet it.
    """
    parts: list[str] = []

    if confidence >= 0.999:
        parts.append(
            "This score looked at everything you typed, every site you visited, and "
            "every password you checked."
        )
    else:
        percent = int(round(confidence * 100))
        parts.append(
            f"This score is based on {percent}% of what SentinelAI measures. The rest "
            "could not be checked, and is not being treated as safe."
        )

    if unchecked_sites:
        parts.append(
            f"{unchecked_sites} {_plural(unchecked_sites, 'site')} could not be looked up, "
            f"so {_plural(unchecked_sites, 'it is', 'they are')} counted as unknown rather "
            "than safe."
        )

    return " ".join(parts)


def _narrative_headline(overall: int, drivers: list[Driver]) -> str:
    """One sentence framing the number, sized to how concentrated the causes are.

    "Most of it comes from one thing" is only said when the arithmetic supports
    it — the top driver has to cost at least as much as everything else combined.
    A narrative that overstates its own certainty is the same failure as a
    detector that does.
    """
    priced = [d for d in drivers if d.points]
    if not priced:
        if drivers:
            return (
                f"Your score is {overall} out of 100. Nothing you have done is pulling it "
                "down — see below for what is missing."
            )
        return (
            f"Your score is {overall} out of 100. Nothing is pulling it down right now."
        )

    top = priced[0].points or 0
    rest = sum(d.points or 0 for d in priced[1:])

    if len(priced) == 1:
        return f"Your score is {overall} out of 100, and one thing is holding it back."
    if top >= rest:
        return (
            f"Your score is {overall} out of 100, and most of that comes down to one thing."
        )
    return (
        f"Your score is {overall} out of 100. {len(priced)} things are pulling it down, "
        "none of them on its own."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_narrative(
    events: list[PiiEvent],
    checks: list[SiteCheck],
    *,
    identity_checks: list[IdentityCheck] | None,
    identity_score: int | None,
    breached_passwords: list[str] | None = None,
    overall: int,
    confidence: float,
    now: datetime,
) -> Narrative:
    """Explain a score in sentences, and price every claim by re-running it.

    Pure, like the rest of ``services/risk``: no session, no clock, no network.
    That is what lets the counterfactual be a real recomputation instead of an
    estimate — running the score four more times costs microseconds.

    ``overall`` and ``confidence`` are passed in rather than recomputed so the
    narrative cannot quote a current score that differs from the one on screen.

    ``breached_passwords`` is only consulted when ``identity_checks`` is absent —
    with the rows in hand the labels are read off them, so the two can never name
    a different set of passwords.
    """
    candidates = [
        *_pii_candidates(events),
        *_site_candidates(checks),
        *_identity_candidates(identity_checks, identity_score, breached_passwords or []),
    ]

    priced: list[tuple[_Candidate, int | None]] = []
    for candidate in candidates:
        without = _overall_without(
            candidate, events, checks, identity_checks, identity_score, now
        )
        # A counterfactual can come back lower than the current score — removing
        # a batch of masked findings can *raise* the privacy penalty share once
        # weights redistribute. Clamped at zero rather than shown as a negative
        # cost, because "fixing this would hurt you" is not a sentence a security
        # tool should ever print.
        cost = None if without is None else max(0, without - overall)
        priced.append((candidate, cost))

    def sort_key(entry: tuple[_Candidate, int | None]) -> tuple[int, int, str]:
        candidate, cost = entry
        return (-(cost or 0), _SEVERITY_RANK.get(candidate.severity, 9), candidate.code)

    priced.sort(key=sort_key)

    visible = [
        (candidate, cost)
        for candidate, cost in priced
        if candidate.always_show or cost is None or cost >= MIN_REPORTABLE_POINTS
    ]

    # The display cap must never be able to hide the fact that an area went
    # unmeasured. A cheap driver like "we hid 11 things for you" outranking "no
    # password has been checked" would let a two-thirds score read as a whole one,
    # which is the exact failure this codebase spends seven other places
    # preventing. So structural drivers claim their slots first.
    must_show = [entry for entry in visible if entry[0].always_show][:MAX_DRIVERS]
    optional = [entry for entry in visible if not entry[0].always_show]
    chosen = optional[: max(0, MAX_DRIVERS - len(must_show))] + must_show
    chosen.sort(key=sort_key)

    drivers = [
        Driver(
            code=candidate.code,
            sentence=candidate.sentence,
            points=cost,
            severity=candidate.severity,
            count=candidate.count,
        )
        for candidate, cost in chosen
    ]

    lever = _pick_lever(priced, overall)

    # Read off the candidate rather than recounting the checks, so the coverage
    # sentence and the driver line can never disagree about how many sites went
    # unchecked.
    unchecked_sites = next(
        (candidate.count for candidate, _ in priced if candidate.code == "site_unchecked"),
        0,
    )

    return Narrative(
        headline=_narrative_headline(overall, drivers),
        coverage=_coverage_sentence(confidence, unchecked_sites),
        drivers=drivers,
        biggest_lever=lever,
    )


def _pick_lever(priced: list[tuple[_Candidate, int | None]], overall: int) -> Lever | None:
    """The highest-value change the user can actually make, or nothing at all.

    Drawn from the full priced list rather than the truncated driver list: the
    thing most worth fixing does not stop being worth fixing because a display
    cap pushed its line off the screen.

    Returns ``None`` freely. A lever whose delta is zero, or whose only remaining
    causes are ones the user has already handled, is not advice — it is filler,
    and filler is how a user learns to stop reading the advice that matters.
    """
    for candidate, cost in priced:
        if not candidate.can_be_lever or not candidate.lever_template:
            continue
        if cost is None or cost < MIN_REPORTABLE_POINTS:
            continue

        projected = overall + cost
        domain = sorted(candidate.domains)[0] if candidate.domains else ""
        sentence = candidate.lever_template.format(score=projected, domain=domain)
        return Lever(
            code=candidate.code,
            sentence=sentence,
            current_score=overall,
            projected_score=projected,
            delta=cost,
            action=candidate.lever_action,
        )
    return None
