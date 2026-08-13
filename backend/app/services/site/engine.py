"""Site trust scoring — three signals, one explainable verdict.

The design problem here is not "how do we detect phishing". It is **what to do
when a signal is missing**, which is the normal case rather than the exception:
RDAP 404s constantly, Safe Browsing needs a key and a network, and only the
offline brand check is guaranteed to answer.

The naive approach — treat a missing signal as a passing signal — produces a
tool that reports "safe" most confidently exactly when it knows least. So:

* Each available signal contributes a weighted penalty.
* The denominator is the weight that was **actually available**, not the total.
  Missing weight is redistributed across what is left, so an unanswered RDAP
  makes the remaining signals count for more rather than silently voting clean.
* If too little weight was available to say anything, the verdict is
  ``unknown``. Not ``safe``. The extension shows a grey badge, and that is an
  honest answer.

One deliberate exception to the weighting: a Safe Browsing hit is an **override,
not a contribution**. Google is reporting an active malware or phishing campaign
on this exact URL. Averaging that against "the domain is nine years old" would
produce a middling score for a site that is currently attacking the user.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.core.cache import TTLCache
from app.core.config import get_settings
from app.db.models import SiteVerdict
from app.services.site.brand import check_brand, registrable_domain
from app.services.site.rdap import domain_age_days
from app.services.site.safebrowsing import lookup as safe_browsing_lookup

logger = logging.getLogger(__name__)
settings = get_settings()

#: Keyed by URL-without-query. Six hours because a domain's registration date
#: does not change and a Safe Browsing listing rarely changes within a session —
#: while a rehearsal loop can hit the same page twenty times in ten minutes.
_cache = TTLCache()


# ---------------------------------------------------------------------------
# Signal weights
# ---------------------------------------------------------------------------
#
# Stated as constants so the score can be defended out loud rather than
# reverse-engineered from behaviour.

#: Google's crawl of the whole web. Highest weight when it answers, but it is
#: also the slowest to learn about a domain registered this morning.
WEIGHT_SAFE_BROWSING = 0.45
#: A registry fact, not an opinion. Catches exactly what Safe Browsing misses.
WEIGHT_DOMAIN_AGE = 0.25
#: Always available, so it is the floor the whole module stands on.
WEIGHT_BRAND = 0.30

#: Below this much available weight, no verdict is offered. Set just above the
#: brand weight alone: "an offline string check found nothing" is not sufficient
#: evidence to tell a senior citizen a banking site is safe.
MIN_WEIGHT_FOR_VERDICT = 0.31

#: Age thresholds, in days. Chosen from how phishing infrastructure actually
#: behaves: campaigns run on domains days old, and almost never on domains that
#: have been paid for across two renewals.
AGE_VERY_NEW = 30
AGE_NEW = 180
AGE_ESTABLISHED = 365

#: How much a *clean* Safe Browsing result is worth when we cannot confirm the
#: domain is old enough to have been crawled. Google's list is built by
#: crawling and is therefore always behind a campaign that launched this
#: morning, so on a fresh domain an absence of evidence is barely evidence of
#: absence.
SAFE_BROWSING_LAG_DISCOUNT = 0.5

#: Ceiling on the trust score when the hostname is actively impersonating a
#: brand — see ``_is_active_impersonation``.
BRAND_OVERRIDE_MAX_SCORE = 25

CACHE_TTL_SECONDS = 6 * 60 * 60


def _blocklist_is_credible(age_days: int | None) -> bool:
    """True only when the domain is provably old enough for a crawl to be meaningful.

    Note the ``is not None``: an *unknown* age does not earn full credit either.
    Unknown age is exactly the case where the domain might have been registered
    this morning, and treating "we could not check" as "old enough to trust
    Google's silence" would smuggle the missing-signal fallacy back in through
    a second door.
    """
    return age_days is not None and age_days > AGE_VERY_NEW


def _is_active_impersonation(brand) -> bool:
    """True when the hostname is not merely unfamiliar but pretending.

    This is the offline mirror of a Safe Browsing hit, and it is treated the
    same way — as a finding that caps the score rather than a weight that gets
    averaged against other signals. ``arnazon.com``, or ``sbi`` next to
    ``verify``, is a positive observation about *this* hostname; it does not
    become less true because a blocklist has not caught up yet.

    Both corroborating conditions are required. A bare brand token with nothing
    else (``amazon-fanclub.net``) stays weighted and lands on "suspicious",
    which is the honest answer for something merely unofficial.
    """
    return brand.mismatch and (brand.lookalike or bool(brand.lures))


#: The two network signals are independent, so running them back-to-back would
#: make a page's badge wait for the sum of two timeouts (up to 11s) instead of
#: the larger of them. Two threads, both blocked on sockets — the GIL is not a
#: factor, and this is the difference between a badge that feels instant and one
#: the judge watches a spinner for.
_probes = ThreadPoolExecutor(max_workers=4, thread_name_prefix="site-probe")


def _gather_signals(url: str, domain: str) -> tuple[tuple[bool, list[str]] | None, int | None]:
    """Run Safe Browsing and RDAP concurrently. Neither failure can raise."""

    def _safe(fn, arg):
        try:
            return fn(arg)
        except Exception:  # noqa: BLE001 - an absent signal is a valid outcome
            logger.info("site signal %s failed", getattr(fn, "__name__", fn))
            return None

    sb_future = _probes.submit(_safe, safe_browsing_lookup, url)
    age_future = _probes.submit(_safe, domain_age_days, domain)
    return sb_future.result(), age_future.result()


@dataclass(frozen=True)
class Reason:
    """One itemised finding, in the two registers the UI needs.

    ``signal`` is for developers and the dashboard; ``detail`` is the sentence a
    person reads. Keeping both means the popup never has to render a machine
    token, and the API never has to be parsed out of English.
    """

    signal: str
    detail: str
    #: "bad" contributed to a worse score, "good" to a better one, "unknown"
    #: means the check could not run. Unknowns are shown, not hidden — a user
    #: deserves to know which half of the system is speaking.
    weight: str = "bad"


@dataclass(frozen=True)
class SiteResult:
    domain: str
    trust_score: int
    verdict: str
    #: Required by the explainability contract. Never empty — there is always at
    #: least one sentence, even when the answer is "we could not check".
    summary: str
    reasons: list[Reason] = field(default_factory=list)
    confidence: float = 0.0
    domain_age_days: int | None = None
    safe_browsing_hit: bool | None = None
    brand_mismatch: bool = False


def _age_penalty(age_days: int) -> tuple[float, Reason]:
    """Map a domain age to a penalty and the sentence explaining it."""
    if age_days <= 7:
        return 1.0, Reason(
            "domain_age",
            f"This web address was created {age_days} day{'s' if age_days != 1 else ''} ago. "
            "Real companies do not run their websites on brand-new addresses.",
        )
    if age_days <= AGE_VERY_NEW:
        return 0.8, Reason(
            "domain_age",
            f"This web address is only {age_days} days old, which is typical of scam sites.",
        )
    if age_days <= AGE_NEW:
        return 0.4, Reason(
            "domain_age",
            f"This web address is about {age_days // 30} months old — newer than most real businesses.",
        )
    if age_days <= AGE_ESTABLISHED:
        return 0.15, Reason(
            "domain_age",
            f"This web address is about {age_days // 30} months old.",
            weight="good",
        )
    years = age_days // 365
    return 0.0, Reason(
        "domain_age",
        f"This web address has existed for over {years} year{'s' if years != 1 else ''}.",
        weight="good",
    )


def _brand_penalty(result) -> float:
    """Severity of an impersonation match.

    A *lookalike* spelling is worse than a correct one: ``amazon-deals.xyz``
    could conceivably be an unaffiliated fan site, but nobody registers
    ``arnazon.com`` by accident. A lure word alongside either is close to a
    confession.
    """
    if not result.mismatch:
        return 0.0
    if result.lookalike:
        return 1.0
    return 0.9 if result.lures else 0.55


def _verdict_for(score: int, available_weight: float, reasons: list[Reason]) -> str:
    """Band the score, but refuse to say "safe" on thin evidence.

    The evidence floor is deliberately **one-sided**. Thin evidence blocks a
    clean bill of health; it never suppresses a warning. If the offline check
    alone found a bank's name on a domain that bank does not own, that is
    positive evidence of impersonation and stays true whether or not Google and
    the registry answered. Downgrading it to "unknown" because two *other*
    checks failed would throw away the one finding the system actually made —
    and it is precisely the hotel-wifi case this module was built for.

    The last rule keeps the verdict and the evidence from contradicting each
    other. A single weak finding — a brand name on an old, unlisted domain —
    scores in the 80s, which bands as "safe", and the popup would then print
    "No problems found" directly above a sentence describing a problem. Whatever
    the arithmetic says, "safe" has to mean the list is clean.
    """
    if score < 40:
        return SiteVerdict.DANGEROUS.value
    if available_weight < MIN_WEIGHT_FOR_VERDICT:
        return SiteVerdict.UNKNOWN.value
    if score < 75 or any(r.weight == "bad" for r in reasons):
        return SiteVerdict.SUSPICIOUS.value
    return SiteVerdict.SAFE.value


def _summarise(verdict: str, reasons: list[Reason]) -> str:
    """One plain sentence, because most users will read only this.

    Written at the reading level of the least technical person in the target
    list. No "reputation", no "heuristic", no "score" — those words tell a
    worried person nothing about what to do next.
    """
    if verdict == SiteVerdict.DANGEROUS.value:
        return "Do not enter personal details here. This site looks like a scam."
    if verdict == SiteVerdict.SUSPICIOUS.value:
        return "Be careful on this site. Something about it does not add up."
    if verdict == SiteVerdict.UNKNOWN.value:
        return "SentinelAI could not check this site. Treat it as unknown, not as safe."
    if any(r.weight == "unknown" for r in reasons):
        return "No problems found, though one check could not be completed."
    return "No problems found on this site."


def evaluate(url: str) -> SiteResult:
    """Score one URL. Cached for six hours; never raises.

    All three lookups fail independently and all three failures are survivable,
    so there is no path where a network problem turns into an error response.
    """
    parts = urlsplit(url if "//" in url else f"https://{url}")
    hostname = parts.hostname or ""
    if not hostname:
        return SiteResult(
            domain="",
            trust_score=0,
            verdict=SiteVerdict.UNKNOWN.value,
            summary="SentinelAI could not read this web address.",
            reasons=[Reason("input", "The address could not be understood.", weight="unknown")],
        )

    domain = registrable_domain(hostname)
    # Cache on the query-stripped URL: two pages on the same host can carry
    # different Safe Browsing verdicts, so the domain alone is too coarse a key.
    cache_key = f"{parts.scheme}://{hostname}{parts.path or '/'}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    reasons: list[Reason] = []
    penalty = 0.0
    available = 0.0

    # Both network lookups start here and are read where each is needed below.
    sb, age = _gather_signals(url, domain)

    # --- Signal 1: Safe Browsing (override, not a contribution) -------------
    sb_hit: bool | None = None
    if sb is None:
        reasons.append(
            Reason(
                "safe_browsing",
                "The known-threat database could not be reached, so that check was skipped.",
                weight="unknown",
            )
        )
    else:
        sb_hit, threats = sb
        if sb_hit:
            reasons.append(
                Reason("safe_browsing", f"Google lists this page for {threats[0]}.")
            )
            # Hard stop. Nothing else can redeem an active listing, and no other
            # signal is allowed to average it away.
            result = SiteResult(
                domain=domain,
                trust_score=2,
                verdict=SiteVerdict.DANGEROUS.value,
                summary="Leave this site. Google has confirmed it is being used to attack people.",
                reasons=reasons,
                confidence=0.99,
                domain_age_days=None,
                safe_browsing_hit=True,
                brand_mismatch=False,
            )
            _cache.set(cache_key, result, CACHE_TTL_SECONDS)
            return result
        reasons.append(
            Reason("safe_browsing", "Not on Google's list of known dangerous sites.", weight="good")
        )

    # --- Signal 2: brand impersonation (offline, always available) ----------
    brand = check_brand(hostname)
    available += WEIGHT_BRAND
    brand_score = _brand_penalty(brand)
    penalty += WEIGHT_BRAND * brand_score
    if brand.mismatch:
        reasons.extend(Reason("brand", detail) for detail in brand.reasons)

    # --- Signal 3: domain age ----------------------------------------------
    if age is None:
        reasons.append(
            Reason(
                "domain_age",
                "The age of this web address could not be looked up.",
                weight="unknown",
            )
        )
    else:
        available += WEIGHT_DOMAIN_AGE
        age_score, age_reason = _age_penalty(age)
        penalty += WEIGHT_DOMAIN_AGE * age_score
        reasons.append(age_reason)

    # --- Credit the clean Safe Browsing result, discounted for lag ----------
    #
    # Deferred to here because how much a clean result is worth depends on the
    # domain's age. Google's blocklist is built by crawling; a domain registered
    # last week has usually not been crawled yet, so "not on the list" is close
    # to no information rather than a vote of confidence. Giving it full weight
    # would let it dilute the two signals that *can* see a fresh attack —
    # exactly the site the user most needs warning about.
    if sb_hit is False:
        credit = 1.0 if _blocklist_is_credible(age) else SAFE_BROWSING_LAG_DISCOUNT
        available += WEIGHT_SAFE_BROWSING * credit

    # --- Combine -------------------------------------------------------------
    # Dividing by the *available* weight is the redistribution: a missing signal
    # makes the survivors count for proportionally more, instead of contributing
    # a silent zero that reads as evidence of innocence.
    normalised = penalty / available if available else 1.0
    trust_score = max(0, min(100, round(100 * (1 - normalised))))

    # Applied as a cap rather than an early return, so the age and Safe Browsing
    # sentences still reach the user. The verdict changes; the evidence list
    # stays complete.
    if _is_active_impersonation(brand):
        trust_score = min(trust_score, BRAND_OVERRIDE_MAX_SCORE)

    verdict = _verdict_for(trust_score, available, reasons)

    if verdict == SiteVerdict.UNKNOWN.value:
        # Do not publish a reassuring number next to "we do not know".
        trust_score = min(trust_score, 50)

    result = SiteResult(
        domain=domain,
        trust_score=trust_score,
        verdict=verdict,
        summary=_summarise(verdict, reasons),
        reasons=reasons,
        # Confidence is the share of the evidence we actually got. It is a real
        # quantity here, not a decorative number: 0.30 means only the offline
        # check ran, and the UI is expected to say so.
        confidence=round(available / (WEIGHT_SAFE_BROWSING + WEIGHT_BRAND + WEIGHT_DOMAIN_AGE), 2),
        domain_age_days=age,
        safe_browsing_hit=sb_hit,
        brand_mismatch=brand.mismatch,
    )
    _cache.set(cache_key, result, CACHE_TTL_SECONDS)
    return result


def clear_cache() -> None:
    """Test hook, and the demo's escape hatch if a verdict needs re-fetching."""
    _cache.clear()
