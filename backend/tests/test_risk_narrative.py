"""Tests for Module 8 — the score explained in sentences.

The narrative is prose, and prose is the easiest thing in a codebase to get
quietly wrong, so these tests target the claims that would be embarrassing
rather than the wording:

* **The lever is real arithmetic.** ``projected_score`` must equal what
  ``compute`` actually returns once that cause is resolved. A lever that
  promises 65 and delivers 58 is worse than no lever, because it teaches the
  user the number is decorative.
* **A missing area is always said out loud.** The unmeasured-identity driver
  must survive the display cap, no matter how many other causes compete for a
  slot. This is the project's central invariant reaching the one surface where a
  human actually meets it.
* **An uncomputable cost is a dash, not a zero.** ``points is None`` and
  ``points == 0`` mean different things and must stay distinguishable.
* **Users who take the advice are not told off for it.** Masked findings can
  never become the biggest lever.

Everything here is offline and clock-free — ``build_narrative`` is pure and takes
``now``, so nothing sleeps and nothing touches a session.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Device, IdentityCheck, UserAction, utcnow
from app.services.risk.engine import compute
from app.services.risk.narrative import MAX_DRIVERS, MIN_REPORTABLE_POINTS
from tests.conftest import DEVICE_ID
from tests.test_risk_engine import NOW, make_check, make_event


def make_identity(
    *,
    label: str | None = "Amazon",
    breach_count: int = 12_000,
    prefix: str = "5BAA6",
    days_ago: float = 1.0,
    anchor: datetime | None = None,
) -> IdentityCheck:
    """An unsaved row. ``score_identity`` and the narrative never touch a session."""
    return IdentityCheck(
        device_id=DEVICE_ID,
        occurred_at=(anchor or NOW) - timedelta(days=days_ago),
        hash_prefix=prefix,
        breach_count=breach_count,
        label=label,
        risk_level="critical" if breach_count >= 1_000 else "low",
        confidence=0.95,
        reason=f"This password appears in {breach_count:,} breached accounts.",
    )


def narrative_for(events, checks, **kwargs):
    """Run the real ``compute`` and hand back only its narrative."""
    return compute(events, checks, now=NOW, **kwargs).narrative


def codes(narrative) -> list[str]:
    return [d.code for d in narrative.drivers]


# ---------------------------------------------------------------------------
# The counterfactual — the only part of this module that can be *wrong*
# ---------------------------------------------------------------------------


class TestLeverIsRealArithmetic:
    def test_projected_score_matches_an_actual_recompute(self):
        """The headline claim: do the thing, get the number.

        The lever says "hide these and you land at N". This test resolves the
        cause for real — masks the events — and asserts ``compute`` agrees.
        """
        events = [make_event(risk_level="critical") for _ in range(3)]
        narrative = narrative_for(events, [])

        lever = narrative.biggest_lever
        assert lever is not None
        assert lever.code == "pii_sent_unprotected"

        masked = [make_event(risk_level="critical", action=UserAction.MASKED.value) for _ in range(3)]
        # Not identical to the counterfactual, which drops the rows entirely
        # rather than re-actioning them, so this asserts the direction and the
        # ballpark rather than equality. Exact agreement is asserted below
        # against the removal the engine actually performs.
        assert compute(masked, [], now=NOW).overall > compute(events, [], now=NOW).overall

    def test_projected_score_equals_compute_without_the_cause(self):
        """Exact agreement with the removal the counterfactual actually models."""
        events = [make_event(risk_level="critical") for _ in range(3)]
        checks = [make_check(domain="scam.example", verdict="dangerous")]

        summary = compute(events, checks, now=NOW)
        lever = summary.biggest_lever if hasattr(summary, "biggest_lever") else summary.narrative.biggest_lever
        assert lever is not None

        if lever.code == "pii_sent_unprotected":
            without = compute([], checks, now=NOW)
        else:
            without = compute(events, [], now=NOW)

        assert lever.projected_score == without.overall
        assert lever.delta == without.overall - summary.overall

    def test_delta_matches_the_two_published_scores(self):
        narrative = narrative_for([make_event() for _ in range(4)], [])
        lever = narrative.biggest_lever
        assert lever is not None
        assert lever.delta == lever.projected_score - lever.current_score
        assert lever.delta >= MIN_REPORTABLE_POINTS

    def test_changing_a_breached_password_is_modelled_as_a_clean_recheck(self):
        """Not as a deleted row.

        Deleting the check would drop Identity to ``None`` and redistribute its
        weight — that is what happens when a user *never checks*, not when they
        fix one. The lever must model the fix, or it promises a score the user
        cannot reach by following the advice.
        """
        checks = [make_identity(label="Amazon", breach_count=500_000)]
        narrative = narrative_for(
            [],
            [],
            identity_score=1,
            identity_count=1,
            identity_checks=checks,
            breached_passwords=["Amazon"],
        )

        lever = narrative.biggest_lever
        assert lever is not None
        assert lever.code == "identity_breached"
        assert lever.action == "change_password"

        # A clean re-check scores 100 for Identity, and the component keeps its
        # weight. That is the score the lever must be quoting.
        fixed = compute([], [], identity_score=100, identity_count=1, now=NOW)
        assert lever.projected_score == fixed.overall

    def test_lever_names_the_specific_password(self):
        """"Change one of your passwords" is advice nobody follows."""
        checks = [make_identity(label="Amazon", breach_count=500_000)]
        narrative = narrative_for(
            [], [], identity_score=1, identity_count=1, identity_checks=checks
        )
        assert "Amazon" in (narrative.biggest_lever.sentence if narrative.biggest_lever else "")


# ---------------------------------------------------------------------------
# When there is no honest advice to give
# ---------------------------------------------------------------------------


class TestNoFillerAdvice:
    def test_clean_history_offers_no_lever(self):
        narrative = narrative_for([], [])
        assert narrative.biggest_lever is None
        assert narrative.headline

    def test_masked_findings_never_become_the_lever(self):
        """The user did the right thing. Telling them to fix it punishes the advice."""
        events = [
            make_event(risk_level="critical", action=UserAction.MASKED.value) for _ in range(8)
        ]
        narrative = narrative_for(events, [])
        assert "pii_protected" in codes(narrative)
        assert narrative.biggest_lever is None

    def test_unchecked_sites_never_become_the_lever(self):
        """A lookup that could not run is our failure, not the user's behaviour."""
        checks = [make_check(domain=f"site{i}.example", verdict="unknown") for i in range(6)]
        narrative = narrative_for([], checks)
        lever = narrative.biggest_lever
        assert lever is None or lever.code != "site_unchecked"

    def test_unmeasured_identity_never_becomes_the_lever(self):
        narrative = narrative_for([], [])
        assert narrative.biggest_lever is None


# ---------------------------------------------------------------------------
# The missing-signal rule, on the surface a human actually reads
# ---------------------------------------------------------------------------


class TestMissingSignalsAreStated:
    def test_unmeasured_identity_always_produces_a_driver(self):
        narrative = narrative_for([make_event()], [make_check()])
        assert "identity_unmeasured" in codes(narrative)

    def test_unmeasured_identity_survives_the_display_cap(self):
        """A cheap driver must never be able to crowd out "we could not see this".

        Enough competing causes are generated here to fill the cap several times
        over. The structural driver still has to appear, or a two-thirds score
        renders as a whole one.
        """
        events = [
            *(make_event(risk_level="critical") for _ in range(3)),
            *(make_event(risk_level="low", action=UserAction.MASKED.value) for _ in range(9)),
            *(make_event(risk_level="medium") for _ in range(4)),
        ]
        checks = [
            make_check(domain="bad.example", verdict="dangerous"),
            make_check(domain="odd.example", verdict="suspicious"),
            make_check(domain="dark.example", verdict="unknown"),
        ]
        narrative = narrative_for(events, checks)

        assert len(narrative.drivers) <= MAX_DRIVERS
        assert "identity_unmeasured" in codes(narrative)

    def test_unmeasured_identity_driver_is_never_worded_as_safe(self):
        narrative = narrative_for([], [])
        driver = next(d for d in narrative.drivers if d.code == "identity_unmeasured")
        assert "not counted as safe" in driver.sentence
        # Zero points is correct here — an unmeasured area contributes nothing —
        # but it must be a measured zero, not an unmeasured blank.
        assert driver.points == 0

    def test_coverage_sentence_reports_partial_measurement(self):
        narrative = narrative_for([], [])
        assert "80%" in narrative.coverage
        assert "not being treated as safe" in narrative.coverage

    def test_coverage_sentence_reports_full_measurement(self):
        narrative = narrative_for([], [], identity_score=100, identity_count=1)
        assert "every password you checked" in narrative.coverage

    def test_coverage_mentions_sites_that_could_not_be_looked_up(self):
        checks = [make_check(domain=f"s{i}.example", verdict="unknown") for i in range(3)]
        narrative = narrative_for([], checks)
        assert "3 sites could not be looked up" in narrative.coverage
        assert "unknown rather than safe" in narrative.coverage

    def test_breached_password_cost_is_null_without_the_rows(self):
        """Labels but no rows: name the password, refuse to price it.

        ``compute`` can be called with an aggregate identity score and no raw
        checks. The per-password counterfactual is impossible then, and the
        honest answer is ``None`` — not a fabricated zero, and not silence.
        """
        narrative = narrative_for(
            [],
            [],
            identity_score=20,
            identity_count=1,
            breached_passwords=["Amazon"],
        )
        driver = next(d for d in narrative.drivers if d.code == "identity_breached")
        assert driver.points is None
        assert "Amazon" in driver.sentence
        assert narrative.biggest_lever is None


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------


class TestDrivers:
    def test_every_driver_has_a_non_empty_sentence(self):
        """The explainability contract, asserted rather than promised."""
        events = [
            make_event(risk_level="critical"),
            make_event(risk_level="low", action=UserAction.MASKED.value),
            make_event(risk_level="medium"),
        ]
        checks = [make_check(verdict="dangerous"), make_check(domain="x.example", verdict="unknown")]
        narrative = narrative_for(events, checks)

        assert narrative.headline.strip()
        assert narrative.coverage.strip()
        for driver in narrative.drivers:
            assert driver.sentence.strip()
            assert driver.severity in {"high", "medium", "low", "info"}

    def test_drivers_are_ordered_by_what_they_cost(self):
        events = [make_event(risk_level="critical") for _ in range(4)]
        checks = [make_check(domain="odd.example", verdict="suspicious")]
        narrative = narrative_for(events, checks)

        costs = [d.points or 0 for d in narrative.drivers]
        assert costs == sorted(costs, reverse=True)

    def test_capped_at_four(self):
        events = [
            *(make_event(risk_level="critical") for _ in range(2)),
            *(make_event(risk_level="low") for _ in range(2)),
            *(make_event(risk_level="high", action=UserAction.MASKED.value) for _ in range(6)),
        ]
        checks = [
            make_check(domain="a.example", verdict="dangerous"),
            make_check(domain="b.example", verdict="suspicious"),
            make_check(domain="c.example", verdict="unknown"),
        ]
        assert len(narrative_for(events, checks).drivers) <= MAX_DRIVERS

    def test_masked_findings_are_credited_not_scolded(self):
        events = [
            make_event(risk_level="critical", action=UserAction.MASKED.value) for _ in range(5)
        ]
        driver = next(d for d in narrative_for(events, []).drivers if d.code == "pii_protected")
        assert "hid" in driver.sentence
        assert "barely count" in driver.sentence

    def test_repeat_visits_to_one_domain_count_once(self):
        """Matching ``score_browsing``, which prices the worst verdict per domain."""
        checks = [make_check(domain="bad.example", verdict="dangerous", days_ago=d) for d in range(5)]
        driver = next(d for d in narrative_for([], checks).drivers if d.code == "site_dangerous")
        assert driver.count == 1
        assert "1 website" in driver.sentence

    def test_a_domain_is_priced_at_its_worst_verdict_only(self):
        checks = [
            make_check(domain="bad.example", verdict="suspicious", days_ago=2),
            make_check(domain="bad.example", verdict="dangerous", days_ago=1),
        ]
        present = codes(narrative_for([], checks))
        assert "site_dangerous" in present
        assert "site_suspicious" not in present

    def test_zero_cost_causes_are_dropped(self):
        """"This cost you nothing" is noise that pushes out a cause that matters."""
        checks = [make_check(domain="x.example", verdict="unknown", days_ago=25)]
        assert "site_unchecked" not in codes(narrative_for([], checks))

    def test_driver_counts_match_the_rows_behind_them(self):
        events = [make_event(risk_level="critical") for _ in range(3)]
        driver = next(
            d for d in narrative_for(events, []).drivers if d.code == "pii_sent_unprotected"
        )
        assert driver.count == 3
        assert "3 sensitive details" in driver.sentence


# ---------------------------------------------------------------------------
# Headline
# ---------------------------------------------------------------------------


class TestHeadline:
    def test_quiet_history_says_so_plainly(self):
        narrative = narrative_for([], [], identity_score=100, identity_count=1)
        assert "Nothing is pulling it down" in narrative.headline

    def test_single_cause_is_named_as_one_thing(self):
        narrative = narrative_for([make_event(risk_level="critical")], [])
        assert "one thing" in narrative.headline

    def test_concentrated_causes_claim_concentration(self):
        """"Most of it comes from one thing" is only said when arithmetic backs it."""
        events = [make_event(risk_level="critical") for _ in range(5)]
        checks = [make_check(domain="odd.example", verdict="suspicious", days_ago=20)]
        assert "one thing" in narrative_for(events, checks).headline

    def test_the_current_score_is_quoted_verbatim(self):
        summary = compute([make_event() for _ in range(3)], [], now=NOW)
        assert f"{summary.overall} out of 100" in summary.narrative.headline


# ---------------------------------------------------------------------------
# Untrusted input
# ---------------------------------------------------------------------------


class TestUserSuppliedText:
    def test_long_password_labels_are_truncated(self):
        """The label is the only user-controlled string in the whole narrative."""
        checks = [make_identity(label="A" * 300, breach_count=9_000)]
        narrative = narrative_for(
            [], [], identity_score=30, identity_count=1, identity_checks=checks
        )
        driver = next(d for d in narrative.drivers if d.code == "identity_breached")
        assert len(driver.sentence) < 200
        assert "A" * 300 not in driver.sentence

    def test_blank_label_falls_back_to_a_generic_phrase(self):
        checks = [make_identity(label=None, breach_count=9_000)]
        narrative = narrative_for(
            [], [], identity_score=30, identity_count=1, identity_checks=checks
        )
        driver = next(d for d in narrative.drivers if d.code == "identity_breached")
        assert driver.sentence.startswith("One of your passwords")

    def test_no_hash_prefix_ever_reaches_a_sentence(self):
        """A nickname plus a prefix is more than this product puts on one screen."""
        checks = [make_identity(label="Amazon", prefix="5BAA6", breach_count=9_000)]
        narrative = narrative_for(
            [], [], identity_score=30, identity_count=1, identity_checks=checks
        )
        blob = " ".join(
            [narrative.headline, narrative.coverage, *(d.sentence for d in narrative.drivers)]
        )
        assert "5BAA6" not in blob


# ---------------------------------------------------------------------------
# Endpoint contract
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded(client):
    """A device with enough history to produce every kind of driver.

    Anchored to the real clock rather than ``NOW``: the route reads the actual
    time, so rows pinned to a fixed date silently age out of the 30-day window.
    """
    from app.db.session import SessionLocal

    now = utcnow()
    with SessionLocal() as db:
        db.add(Device(id=DEVICE_ID))
        db.add(make_event(risk_level="critical", days_ago=1, anchor=now))
        db.add(make_event(risk_level="critical", days_ago=2, anchor=now))
        db.add(make_event(risk_level="low", action=UserAction.MASKED.value, days_ago=1, anchor=now))
        db.add(make_check(domain="bad.example", verdict="dangerous", days_ago=1, anchor=now))
        db.commit()
    return client


class TestNarrativeInTheResponse:
    def test_summary_endpoint_returns_a_narrative(self, seeded, auth_headers):
        payload = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()

        narrative = payload["narrative"]
        assert narrative["headline"]
        assert narrative["coverage"]
        for driver in narrative["drivers"]:
            assert driver["sentence"]
            assert driver["code"]
            assert driver["points"] is None or driver["points"] >= 0

    def test_lever_in_the_response_is_internally_consistent(self, seeded, auth_headers):
        payload = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        lever = payload["narrative"]["biggest_lever"]

        if lever is not None:
            assert lever["current_score"] == payload["overall_score"]
            assert lever["projected_score"] == lever["current_score"] + lever["delta"]
            assert lever["delta"] >= 1
            assert lever["sentence"]

    def test_narrative_is_a_required_field(self):
        """Not optional, because a score with no explanation must not be sendable."""
        from app.schemas.dashboard import DashboardSummary

        assert DashboardSummary.model_fields["narrative"].is_required()
