"""Tests for the unified risk engine and the dashboard endpoint.

The engine is the project's differentiator, so these tests are weighted toward
the claims that would be embarrassing to get wrong in front of a judge:

* **Masking is rewarded, not punished.** If a user who takes the advice scores
  the same as one who ignores it, the score measures alerts rather than risk and
  the whole product argument collapses.
* **A missing component is never a passing component.** Identity is unbuilt; it
  must return null, redistribute its weight, and lower the reported confidence.
* **The number is reconstructible.** Every contribution's points must actually
  sum to the overall score — the explainability claim has to survive arithmetic.

Everything here is offline. ``compute`` is pure and takes ``now`` explicitly, so
decay is tested with fabricated timestamps rather than ``sleep``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Device, PiiEvent, SiteCheck, UserAction, utcnow
from app.services.risk import engine as risk
from app.services.risk.engine import (
    DECAY_HALF_LIFE_DAYS,
    LOOKBACK_DAYS,
    WEIGHT_IDENTITY,
    compute,
    decay_factor,
    penalty_to_score,
    score_browsing,
    score_privacy,
)
from tests.conftest import DEVICE_ID

#: Fixed clock for the pure-function tests. ``compute`` takes ``now`` explicitly,
#: so decay can be tested with fabricated timestamps instead of ``sleep``.
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def make_event(
    *,
    risk_level: str = "critical",
    action: str = UserAction.NONE.value,
    days_ago: float = 0.0,
    confidence: float = 1.0,
    pii_type: str = "aadhaar",
    origin: str = "https://forum.example.com",
    anchor: datetime | None = None,
) -> PiiEvent:
    """An unsaved ORM instance. The engine never touches a session, so this is enough.

    ``anchor`` defaults to the frozen ``NOW``, which is right for the pure tests
    and wrong for the endpoint ones — the route reads the real clock, so a row
    anchored to a fixed date silently ages out of the 30-day window. Database
    fixtures pass ``anchor=utcnow()``.
    """
    return PiiEvent(
        device_id=DEVICE_ID,
        occurred_at=(anchor or NOW) - timedelta(days=days_ago),
        site_origin=origin,
        field_kind="input",
        pii_type=pii_type,
        risk_level=risk_level,
        confidence=confidence,
        detection_tier="regex",
        reason="Checksum-valid Aadhaar number.",
        masked_preview="XXXX XXXX 9014",
        action_taken=action,
    )


def make_check(
    *,
    domain: str = "amazon-login-security.xyz",
    verdict: str = "dangerous",
    trust_score: int = 25,
    days_ago: float = 0.0,
    anchor: datetime | None = None,
) -> SiteCheck:
    return SiteCheck(
        device_id=DEVICE_ID,
        occurred_at=(anchor or NOW) - timedelta(days=days_ago),
        domain=domain,
        trust_score=trust_score,
        verdict=verdict,
        reasons=[{"detail": "Uses a well-known brand name on a domain that brand does not own.", "weight": "bad"}],
        domain_age_days=4,
        safe_browsing_hit=False,
        brand_mismatch=True,
    )


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


class TestDecay:
    def test_fresh_event_counts_fully(self):
        assert decay_factor(NOW, NOW) == 1.0

    def test_one_half_life_halves_the_weight(self):
        older = NOW - timedelta(days=DECAY_HALF_LIFE_DAYS)
        assert decay_factor(older, NOW) == pytest.approx(0.5)

    def test_two_half_lives_quarter_it(self):
        older = NOW - timedelta(days=DECAY_HALF_LIFE_DAYS * 2)
        assert decay_factor(older, NOW) == pytest.approx(0.25)

    def test_future_timestamp_cannot_exceed_a_fresh_one(self):
        """A clock-skewed client must not be able to manufacture extra weight."""
        assert decay_factor(NOW + timedelta(days=5), NOW) == 1.0

    def test_score_recovers_as_events_age(self):
        """The point of decay: a user who stops doing the bad thing sees the score rise."""
        recent = compute([make_event(days_ago=0)], [], now=NOW)
        stale = compute([make_event(days_ago=21)], [], now=NOW)
        assert stale.overall > recent.overall


class TestPenaltyCurve:
    def test_zero_penalty_is_a_hundred(self):
        assert penalty_to_score(0) == 100

    def test_stays_in_range_under_absurd_load(self):
        assert 0 <= penalty_to_score(1_000_000) <= 100

    def test_never_actually_reaches_zero(self):
        """A saturating curve always has room left to move — that is why it was chosen."""
        assert penalty_to_score(10_000) > 0

    def test_is_monotonic(self):
        scores = [penalty_to_score(p) for p in (0, 25, 60, 100, 200, 400)]
        assert scores == sorted(scores, reverse=True)

    def test_one_unmasked_critical_lands_in_the_attention_band(self):
        """Tuning claim from the module docstring, asserted rather than trusted."""
        score, _ = score_privacy([make_event()], NOW)
        assert 50 <= score <= 75


# ---------------------------------------------------------------------------
# The action multiplier — the single most important behaviour in this file
# ---------------------------------------------------------------------------


class TestMaskingIsRewarded:
    def test_masking_scores_better_than_ignoring(self):
        masked, _ = score_privacy([make_event(action=UserAction.MASKED.value)], NOW)
        ignored, _ = score_privacy([make_event(action=UserAction.IGNORED.value)], NOW)
        assert masked > ignored

    def test_ignoring_is_no_better_than_not_responding(self):
        """Dismissing a warning is not a mitigation. It must not earn a discount."""
        ignored, _ = score_privacy([make_event(action=UserAction.IGNORED.value)], NOW)
        none, _ = score_privacy([make_event(action=UserAction.NONE.value)], NOW)
        assert ignored == none

    def test_masking_still_costs_something(self):
        """Residual weight for the behaviour that produced the finding.

        Zero would make the score blind to a user who repeatedly pastes their
        card number into random forms and masks it every time.
        """
        masked, _ = score_privacy([make_event(action=UserAction.MASKED.value)], NOW)
        assert masked < 100

    def test_low_confidence_findings_move_the_score_less(self):
        firm, _ = score_privacy([make_event(confidence=0.99)], NOW)
        shaky, _ = score_privacy([make_event(confidence=0.55)], NOW)
        assert shaky > firm

    def test_severity_is_ordered(self):
        scores = [
            score_privacy([make_event(risk_level=level)], NOW)[0]
            for level in ("critical", "high", "medium", "low")
        ]
        assert scores == sorted(scores)


# ---------------------------------------------------------------------------
# Browsing
# ---------------------------------------------------------------------------


class TestBrowsing:
    def test_repeat_visits_to_one_domain_count_once(self):
        """Reloading one bad page five times is not five times the exposure."""
        once, _ = score_browsing([make_check()], NOW)
        five, _ = score_browsing([make_check(days_ago=i * 0.01) for i in range(5)], NOW)
        assert once == five

    def test_distinct_bad_domains_do_accumulate(self):
        one, _ = score_browsing([make_check(domain="a.xyz")], NOW)
        two, _ = score_browsing([make_check(domain="a.xyz"), make_check(domain="b.xyz")], NOW)
        assert two < one

    def test_a_domain_is_scored_at_its_worst_verdict(self):
        """Order of arrival must not change the answer."""
        worst_first = score_browsing(
            [make_check(verdict="dangerous"), make_check(verdict="suspicious")], NOW
        )
        worst_last = score_browsing(
            [make_check(verdict="suspicious"), make_check(verdict="dangerous")], NOW
        )
        assert worst_first == worst_last
        assert worst_first[0] == score_browsing([make_check(verdict="dangerous")], NOW)[0]

    def test_result_does_not_depend_on_query_ordering(self):
        """Regression: equal-severity repeat visits used to keep whichever row came first.

        The dashboard query sorts newest-first and the seed script builds
        oldest-first, so identical data scored 55 one way and 86 the other — the
        trend chart disagreed with the number printed above it.
        """
        visits = [make_check(days_ago=d) for d in (0, 3, 9, 14, 20)]
        assert score_browsing(visits, NOW) == score_browsing(list(reversed(visits)), NOW)

    def test_a_repeat_offender_decays_from_its_most_recent_visit(self):
        """Visiting a bad site three weeks ago must not bury today's visit."""
        today_only, _ = score_browsing([make_check(days_ago=0)], NOW)
        today_and_long_ago, _ = score_browsing(
            [make_check(days_ago=0), make_check(days_ago=21)], NOW
        )
        assert today_and_long_ago == today_only

    def test_safe_sites_are_free(self):
        score, penalty = score_browsing([make_check(verdict="safe", trust_score=100)], NOW)
        assert score == 100
        assert penalty == 0.0

    def test_unknown_barely_costs_anything(self):
        """A check we could not run is our failure, not the user's exposure.

        Offline RDAP on hotel wifi must not visibly drop someone's score.
        """
        score, _ = score_browsing([make_check(verdict="unknown", trust_score=50)], NOW)
        assert score >= 95


# ---------------------------------------------------------------------------
# Aggregation and the missing-component rule
# ---------------------------------------------------------------------------


class TestIdentityIsAbsentNotPassing:
    def test_identity_score_is_null(self):
        summary = compute([], [], identity_score=None, now=NOW)
        assert summary.identity is None

    def test_confidence_reports_the_gap(self):
        """0.8 = one of three areas is dark. The response says so out loud."""
        summary = compute([], [], identity_score=None, now=NOW)
        assert summary.confidence == pytest.approx(1.0 - WEIGHT_IDENTITY)

    def test_full_coverage_reports_full_confidence(self):
        summary = compute([], [], identity_score=70, now=NOW)
        assert summary.confidence == pytest.approx(1.0)

    def test_missing_identity_contributes_zero_points(self):
        summary = compute([], [], identity_score=None, now=NOW)
        identity = next(c for c in summary.contributions if c.component == "identity")
        assert identity.points == 0.0
        assert identity.weight_applied == 0.0
        assert identity.weight == WEIGHT_IDENTITY

    def test_weight_is_redistributed_to_the_survivors(self):
        summary = compute([], [], identity_score=None, now=NOW)
        applied = sum(c.weight_applied for c in summary.contributions)
        assert applied == pytest.approx(1.0, abs=0.01)

    def test_an_unbuilt_module_does_not_improve_the_score(self):
        """The failure mode this rule exists to prevent.

        A perfect-100 Identity would drag a bad score upward. With it absent, the
        overall must equal the weighted average of what was actually measured.
        """
        events = [make_event()]
        absent = compute(events, [], identity_score=None, now=NOW)
        invented = compute(events, [], identity_score=100, now=NOW)
        assert absent.overall < invented.overall

    def test_a_missing_component_is_flagged_in_plain_language(self):
        """The sentence must describe the absence and say it is not counted.

        Asserted on the property rather than on exact wording: this copy changed
        once already, when Module 4 replaced the placeholder "not set up" with
        the real "no password checked yet". What must never change is that it
        names what is missing and never reads as a passing grade.
        """
        summary = compute([], [], identity_score=None, now=NOW)
        identity = next(c for c in summary.contributions if c.component == "identity")
        detail = identity.detail.lower()
        assert "password" in detail
        assert "not counted" in detail
        assert "no problem" not in detail and "safe" not in detail


class TestArithmeticIsReconstructible:
    def test_points_sum_to_the_overall_score(self):
        summary = compute([make_event()], [make_check()], now=NOW)
        total = sum(c.points for c in summary.contributions)
        assert risk._round_half_up(total) == summary.overall

    def test_rounding_matches_hand_arithmetic_on_a_half_point(self):
        """Regression: the published breakdown must add up to the headline.

        Seen live — privacy 39 and browsing 58 at half weight each publish 19.5
        and 29.0, summing to exactly 48.5. Python's banker's rounding made the
        headline 48, so a judge checking the sum the response invites them to
        check would have found it half a point light.
        """
        assert risk._round_half_up(48.5) == 49
        assert risk._round_half_up(49.5) == 50
        assert risk._round_half_up(48.4) == 48

    def test_no_breakdown_ever_disagrees_with_its_headline(self):
        """Swept rather than spot-checked: rounding bugs hide on specific inputs."""
        for count in range(0, 12):
            for verdict in ("dangerous", "suspicious", "unknown", "safe"):
                summary = compute(
                    [make_event(days_ago=i * 0.7) for i in range(count)],
                    [make_check(domain=f"d{i}.xyz", verdict=verdict) for i in range(count)],
                    now=NOW,
                )
                total = sum(c.points for c in summary.contributions)
                assert risk._round_half_up(total) == summary.overall, (count, verdict)

    def test_each_component_reports_its_own_event_count(self):
        summary = compute([make_event(), make_event()], [make_check()], now=NOW)
        by_name = {c.component: c for c in summary.contributions}
        assert by_name["privacy"].event_count == 2
        assert by_name["browsing"].event_count == 1

    def test_events_outside_the_window_are_dropped(self):
        summary = compute([make_event(days_ago=LOOKBACK_DAYS + 1)], [], now=NOW)
        privacy = next(c for c in summary.contributions if c.component == "privacy")
        assert privacy.event_count == 0
        assert summary.privacy == 100

    def test_score_stays_in_range(self):
        summary = compute([make_event() for _ in range(50)], [make_check(domain=f"{i}.xyz") for i in range(50)], now=NOW)
        assert 0 <= summary.overall <= 100


class TestRiskBands:
    def test_clean_slate_is_low_risk(self):
        summary = compute([], [], now=NOW)
        assert summary.overall == 100
        assert summary.risk_level == "low"

    def test_bands_are_ordered(self):
        assert risk._risk_level_for(100) == "low"
        assert risk._risk_level_for(65) == "medium"
        assert risk._risk_level_for(40) == "high"
        assert risk._risk_level_for(10) == "critical"

    def test_critical_is_hard_to_reach(self):
        """Over-alerting trains users to ignore warnings, so red is expensive.

        A single unmasked critical finding is a real problem but not a crisis; it
        must not paint the whole dashboard red.
        """
        summary = compute([make_event()], [], now=NOW)
        assert summary.risk_level != "critical"


# ---------------------------------------------------------------------------
# Explainability contract
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_every_contribution_carries_a_sentence(self):
        summary = compute([make_event()], [make_check()], now=NOW)
        assert len(summary.contributions) == 3
        for contribution in summary.contributions:
            assert contribution.detail.strip()

    def test_headline_is_never_empty(self):
        for events, checks in (([], []), ([make_event()], []), ([make_event()], [make_check()])):
            assert compute(events, checks, now=NOW).headline.strip()

    def test_clean_slate_headline_does_not_imply_a_problem(self):
        summary = compute([], [], now=NOW)
        assert "nothing" in summary.headline.lower()

    def test_recommendations_are_actionable_and_ranked(self):
        summary = compute([make_event()], [make_check()], now=NOW)
        assert summary.recommendations
        for rec in summary.recommendations:
            assert rec.title.strip() and rec.detail.strip() and rec.action.strip()
            assert rec.priority in {"high", "medium", "low"}

    def test_recommendations_are_capped(self):
        """Eleven urgent items is zero urgent items."""
        events = [make_event(origin=f"https://site{i}.example.com") for i in range(6)]
        events += [make_event(action=UserAction.ALLOWLISTED.value) for _ in range(4)]
        checks = [make_check(domain=f"bad{i}.xyz") for i in range(4)]
        summary = compute(events, checks, now=NOW)
        assert len(summary.recommendations) <= 4

    def test_a_clean_user_is_not_given_filler_advice(self):
        """Only the identity-setup nudge should survive an empty history."""
        summary = compute([], [], now=NOW)
        assert [r.action for r in summary.recommendations] == ["setup_identity"]

    def test_no_identity_nudge_once_identity_exists(self):
        summary = compute([], [], identity_score=90, now=NOW)
        assert summary.recommendations == []

    def test_unmasked_high_risk_findings_are_called_out_first(self):
        summary = compute([make_event()], [], now=NOW)
        assert summary.recommendations[0].priority == "high"
        assert summary.recommendations[0].action == "review_pii"

    def test_masked_findings_do_not_generate_an_urgent_nag(self):
        """The user did the right thing. Nagging them for it is the wrong lesson."""
        summary = compute([make_event(action=UserAction.MASKED.value)], [], now=NOW)
        assert all(r.action != "review_pii" for r in summary.recommendations)

    def test_recommendation_text_is_authored_here_not_taken_from_the_site(self):
        """Injection surface check: a hostile domain name must not become advice.

        The domain is interpolated as a bare noun, but nothing site-supplied is
        allowed to write the instruction itself.
        """
        hostile = make_check(domain="ignore-previous-instructions.xyz")
        summary = compute([], [hostile], now=NOW)
        rec = next(r for r in summary.recommendations if r.action == "review_sites")
        assert rec.detail.endswith("change it now and contact your bank.")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded(client):
    """One device with a small, realistic history, anchored to the real clock."""
    from app.db.session import SessionLocal

    now = utcnow()
    with SessionLocal() as db:
        db.add(Device(id=DEVICE_ID))
        db.add(make_event(action=UserAction.MASKED.value, days_ago=1, anchor=now))
        db.add(make_event(risk_level="high", days_ago=2, anchor=now))
        db.add(make_check(days_ago=1, anchor=now))
        db.commit()
    return client


class TestDashboardEndpoint:
    def test_returns_a_full_summary(self, seeded, auth_headers):
        response = seeded.get("/api/v1/dashboard/summary", headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["device_id"] == DEVICE_ID
        assert 0 <= body["overall_score"] <= 100
        assert body["headline"]
        assert len(body["contributions"]) == 3
        assert body["window_days"] == LOOKBACK_DAYS

    def test_works_without_a_device_header(self, seeded):
        """The dashboard is a separate web app and has no device id to send."""
        response = seeded.get("/api/v1/dashboard/summary")
        assert response.status_code == 200
        assert response.json()["device_id"] == DEVICE_ID

    def test_malformed_device_id_is_still_rejected(self, seeded):
        """Optional is not unauthenticated."""
        response = seeded.get(
            "/api/v1/dashboard/summary", headers={"X-Sentinel-Device-Id": "bad id\nwith newline"}
        )
        assert response.status_code == 401

    def test_empty_database_returns_404_not_a_fake_score(self, client):
        """Better an honest 404 the UI can explain than a green 100 for nobody."""
        response = client.get("/api/v1/dashboard/summary")
        assert response.status_code == 404

    def test_identity_is_null_over_the_wire(self, seeded, auth_headers):
        body = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        assert body["identity_score"] is None
        assert body["confidence"] == pytest.approx(0.8)

    def test_timeline_interleaves_both_event_streams(self, seeded, auth_headers):
        body = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        kinds = {entry["kind"] for entry in body["timeline"]}
        assert kinds == {"pii", "site"}

    def test_timeline_is_newest_first(self, seeded, auth_headers):
        body = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        stamps = [entry["occurred_at"] for entry in body["timeline"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_timeline_never_carries_raw_pii(self, seeded, auth_headers):
        """There is no column holding the original, so this asserts the schema holds."""
        body = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        for entry in body["timeline"]:
            if entry["kind"] == "pii":
                assert entry["masked_preview"] == "XXXX XXXX 9014"
        assert "9014" not in str(body).replace("XXXX XXXX 9014", "")

    def test_flagged_sites_excludes_safe_ones(self, client, auth_headers):
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            db.add(Device(id=DEVICE_ID))
            db.add(make_check(domain="wikipedia.org", verdict="safe", trust_score=100, anchor=utcnow()))
            db.add(make_check(domain="paypa1-verify.com", verdict="dangerous", anchor=utcnow()))
            db.commit()

        body = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        domains = [s["domain"] for s in body["flagged_sites"]]
        assert domains == ["paypa1-verify.com"]

    def test_flagged_sites_collapse_repeat_visits(self, client, auth_headers):
        from app.db.session import SessionLocal

        now = utcnow()
        with SessionLocal() as db:
            db.add(Device(id=DEVICE_ID))
            for i in range(3):
                db.add(make_check(days_ago=i, anchor=now))
            db.commit()

        body = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        assert len(body["flagged_sites"]) == 1
        assert body["flagged_sites"][0]["visits"] == 3

    def test_a_snapshot_is_written_for_the_trend_chart(self, seeded, auth_headers):
        from app.db.session import SessionLocal

        from app.db.models import ScoreSnapshot

        seeded.get("/api/v1/dashboard/summary", headers=auth_headers)
        with SessionLocal() as db:
            assert db.query(ScoreSnapshot).count() == 1

    def test_refreshing_does_not_flood_the_trend_chart(self, seeded, auth_headers):
        """Polling every few seconds must not write 360 points an hour."""
        from app.db.session import SessionLocal

        from app.db.models import ScoreSnapshot

        for _ in range(5):
            seeded.get("/api/v1/dashboard/summary", headers=auth_headers)
        with SessionLocal() as db:
            assert db.query(ScoreSnapshot).count() == 1

    def test_stat_strip_counters_are_computed_server_side(self, seeded, auth_headers):
        body = seeded.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        assert body["total_pii_events"] == 2
        assert body["total_masked"] == 1
        assert body["total_sites_flagged"] == 1

    def test_another_devices_history_is_not_returned(self, seeded, auth_headers):
        """device_id scopes the query. A second device sees its own empty history."""
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            db.add(Device(id="other-device-2222-3333"))
            db.commit()

        body = seeded.get(
            "/api/v1/dashboard/summary?device_id=other-device-2222-3333", headers=auth_headers
        ).json()
        assert body["total_pii_events"] == 0
        assert body["overall_score"] == 100
