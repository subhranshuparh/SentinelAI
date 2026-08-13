"""Module 4 tests — breached-password checks.

Two clusters carry the weight.

**The privacy promise.** The whole feature rests on one claim: the password
never leaves the device. That claim is architectural — the endpoint that talks
to Have I Been Pwned accepts *five characters* and physically cannot receive
more, and the endpoint that scores a result never sees a hash at all. Both are
asserted here, because a regression that widened the prefix field would silently
turn a privacy-preserving feature into a password-harvesting one while every
other test still passed.

**Supersession.** A score you cannot move is a score nobody acts on. Checking
"Gmail", changing it, and checking it again must recover the score — the second
check for a label replaces the first rather than accumulating alongside it.

No network calls: the range client is monkeypatched throughout.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.db.models import IdentityCheck, utcnow
from app.services.identity import pwned
from app.services.identity.engine import (
    breached_labels,
    current_checks,
    evaluate_password,
    identity_detail,
    score_identity,
)


@pytest.fixture(autouse=True)
def _clean_range_cache():
    pwned.clear_cache()
    yield
    pwned.clear_cache()


def _check(label: str | None, count: int, *, minutes_ago: int = 0, prefix: str = "5BAA6") -> IdentityCheck:
    verdict = evaluate_password(count)
    return IdentityCheck(
        device_id="test-device-0000-1111",
        occurred_at=utcnow() - timedelta(minutes=minutes_ago),
        hash_prefix=prefix,
        label=label,
        breach_count=count,
        risk_level=verdict.risk_level,
        confidence=verdict.confidence,
        reason=verdict.reason,
    )


# ---------------------------------------------------------------------------
# The k-anonymity transport
# ---------------------------------------------------------------------------


class TestPrefixHandling:
    def test_normalises_case(self):
        assert pwned.normalise_prefix("5baa6") == "5BAA6"

    @pytest.mark.parametrize("bad", ["5BAA", "5BAA61", "5BAAZ", "", "   ", "../../etc"])
    def test_rejects_anything_that_is_not_five_hex_chars(self, bad: str):
        """The guard that makes the privacy claim true rather than aspirational.

        A full SHA-1 is 40 characters. If this accepted 40, the endpoint would
        happily forward a complete password hash to a third party, and nothing
        else in the system would notice.
        """
        assert pwned.normalise_prefix(bad) is None

    def test_parse_drops_padding_entries(self):
        """``Add-Padding: true`` returns decoy suffixes with a count of zero.

        Keeping them would make every password look breached, because the
        matching happens client-side against whatever this returns.
        """
        # Both suffixes are a real 35 hex chars — the parser requires it, which
        # is itself the check that a truncated response cannot be half-read.
        body = "0018A45C4D1DEF81644B54AB7F969B88D65AB:0\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:12"
        parsed = pwned._parse_range(body)
        assert parsed == {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 12}

    def test_parse_ignores_malformed_lines(self):
        body = "not-a-line\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:12\nSHORT:3\n"
        assert list(pwned._parse_range(body)) == ["1E4C9B93F3F0682250B6CF8331B7EE68FD8"]


class TestRangeEndpoint:
    def test_returns_503_when_upstream_is_unavailable(self, client, auth_headers, monkeypatch):
        """A failed lookup is an error, not an empty list.

        Returning ``{"suffixes": {}}`` would be read client-side as "your
        password is in no breach" — a confident all-clear produced by a network
        failure. This is the single most important assertion in the file.
        """
        monkeypatch.setattr("app.routers.identity.fetch_range", lambda _p: None)
        response = client.get("/api/v1/identity/pwned-range/5BAA6", headers=auth_headers)
        assert response.status_code == 503

    def test_rejects_a_full_hash(self, client, auth_headers):
        full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        response = client.get(f"/api/v1/identity/pwned-range/{full_sha1}", headers=auth_headers)
        assert response.status_code == 422

    def test_returns_the_range(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr(
            "app.routers.identity.fetch_range",
            lambda _p: {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 12_345},
        )
        response = client.get("/api/v1/identity/pwned-range/5BAA6", headers=auth_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["prefix"] == "5BAA6"
        assert body["count"] == 1
        assert body["suffixes"]["1E4C9B93F3F0682250B6CF8331B7EE68FD8"] == 12_345


# ---------------------------------------------------------------------------
# Scoring one password
# ---------------------------------------------------------------------------


class TestEvaluatePassword:
    def test_clean_password_is_not_breached(self):
        verdict = evaluate_password(0)
        assert verdict.breached is False
        assert verdict.penalty == 0.0
        assert verdict.reason and verdict.recommendation

    @pytest.mark.parametrize(
        "count,expected",
        [(1, "high"), (9, "high"), (10, "high"), (1_000, "critical"), (3_000_000, "critical")],
    )
    def test_severity_bands(self, count: int, expected: str):
        assert evaluate_password(count).risk_level == expected

    def test_every_verdict_carries_its_reasoning(self):
        """The project-wide rule, asserted rather than assumed.

        No code path may return a bare verdict. If one ever does, this fails
        before it reaches a user.
        """
        for count in (0, 1, 42, 5_000, 25_000_000):
            verdict = evaluate_password(count)
            assert verdict.reason
            assert verdict.explanation
            assert verdict.recommendation
            assert 0.0 < verdict.confidence <= 1.0

    def test_unverified_count_lowers_confidence(self):
        """The client reports the count; the backend re-checks it can be true.

        A count that could not be corroborated is still acted on — it is the
        user's own password on the user's own device — but the number shown
        beside the verdict says the corroboration did not happen.
        """
        assert evaluate_password(500, verified=False).confidence < evaluate_password(
            500, verified=True
        ).confidence


# ---------------------------------------------------------------------------
# Supersession and the identity score
# ---------------------------------------------------------------------------


class TestSupersession:
    def test_rechecking_a_label_replaces_the_old_result(self):
        """Check Gmail, find it breached, change it, check again → recovered.

        Without this the score is a ratchet: the user does exactly what the
        tool told them to and the number never moves, which teaches them the
        number is decoration.
        """
        checks = [_check("Gmail", 50_000, minutes_ago=60), _check("Gmail", 0, minutes_ago=1)]
        assert breached_labels(checks) == []
        score, counted = score_identity(checks)
        assert counted == 1
        assert score == 100

    def test_different_labels_are_scored_independently(self):
        checks = [_check("Gmail", 0, minutes_ago=60), _check("Bank", 50_000, minutes_ago=1)]
        assert breached_labels(checks) == ["Bank"]
        _, counted = score_identity(checks)
        assert counted == 2

    def test_unlabelled_checks_collapse_by_prefix(self):
        """Two unlabelled checks of the same password are one password.

        Without a label there is nothing else to key on, and counting the same
        password twice would double its weight in the score.
        """
        checks = [_check(None, 900, minutes_ago=30), _check(None, 900, minutes_ago=1)]
        assert len(current_checks(checks)) == 1

    def test_label_matching_ignores_case(self):
        checks = [_check("Gmail", 900, minutes_ago=30), _check("gmail", 0, minutes_ago=1)]
        assert breached_labels(checks) == []


class TestIdentityScore:
    def test_no_checks_means_none_not_a_hundred(self):
        """The invariant, in its Module 4 form.

        A user who has never checked a password has an *unmeasured* identity
        score. Returning 100 would award full marks for doing nothing, and the
        risk engine would fold that fabricated confidence into the headline.
        """
        score, counted = score_identity([])
        assert score is None
        assert counted == 0

    def test_a_breached_password_lowers_the_score(self):
        clean, _ = score_identity([_check("Gmail", 0)])
        breached, _ = score_identity([_check("Gmail", 500_000)])
        assert breached < clean

    def test_detail_never_claims_a_check_that_did_not_happen(self):
        """The sentence for an unmeasured score must describe the *absence*.

        Anything reading like "no problems found" here would tell a user who has
        checked nothing that nothing is wrong.
        """
        detail = identity_detail(None, 0, 0).lower()
        assert "no password" in detail
        assert "safe" not in detail and "no problem" not in detail


# ---------------------------------------------------------------------------
# The scoring endpoint
# ---------------------------------------------------------------------------


class TestPasswordCheckEndpoint:
    def test_records_and_returns_an_explained_verdict(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr("app.routers.identity.count_is_plausible", lambda _p, _c: True)
        response = client.post(
            "/api/v1/identity/password-check",
            headers=auth_headers,
            json={"hash_prefix": "5baa6", "breach_count": 24_230_577, "label": "Old email"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["breached"] is True
        assert body["risk_level"] == "critical"
        # Required by the schema, not by convention.
        assert body["reason"] and body["explanation"] and body["recommendation"]
        assert body["identity_score"] is not None
        assert body["checks_counted"] == 1

    def test_never_accepts_a_hash_longer_than_a_prefix(self, client, auth_headers):
        response = client.post(
            "/api/v1/identity/password-check",
            headers=auth_headers,
            json={"hash_prefix": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "breach_count": 1},
        )
        assert response.status_code == 422

    def test_rejects_a_negative_count(self, client, auth_headers):
        response = client.post(
            "/api/v1/identity/password-check",
            headers=auth_headers,
            json={"hash_prefix": "5BAA6", "breach_count": -1},
        )
        assert response.status_code == 422

    def test_result_reaches_the_dashboard(self, client, auth_headers, monkeypatch):
        """End to end: a check in the popup changes the number on the dashboard."""
        monkeypatch.setattr("app.routers.identity.count_is_plausible", lambda _p, _c: True)
        client.post(
            "/api/v1/identity/password-check",
            headers=auth_headers,
            json={"hash_prefix": "5BAA6", "breach_count": 3_000_000, "label": "Gmail"},
        )
        summary = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()

        assert summary["identity_score"] is not None
        assert any(row["kind"] == "identity" for row in summary["timeline"])
        # And the fix is offered, ranked first.
        assert summary["recommendations"][0]["action"] == "change_password"
