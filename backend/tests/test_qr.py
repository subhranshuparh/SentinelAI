"""Module 9 tests — QR payloads.

Three clusters carry the weight.

**The fraud itself.** A UPI code with a large pre-filled amount and no shop
details is the "scan this to receive ₹50,000" scam, and it must come out
``dangerous`` with the direction of the money stated in words. If only one test
in this file survives, it should be that one.

**False positives.** The counter QR at a chai stall also has a pre-filled
amount. If this module flags every shop in India, it gets muted, and a muted
detector protects nobody. ``TestLegitimatePaymentsStaySilent`` is the counterweight
to the class above it.

**Missing signals, again.** A payload we could not classify, a lookup that could
not run, a code with no payee at all — every one of them must produce
``unknown``, never ``safe``. That rule already has seven enforcement points in
this codebase; these are the next few.

Nothing here makes a network call: the site engine's two network signals are
monkeypatched exactly as ``test_site.py`` does it.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.services.qr.engine import (
    LARGE_AMOUNT,
    THRESHOLD_DANGEROUS,
    THRESHOLD_SUSPICIOUS,
    analyse,
)
from app.services.qr.parse import MAX_PAYLOAD_CHARS, parse
from app.services.qr.psp import is_known_handle
from app.services.site.engine import clear_cache


@pytest.fixture(autouse=True)
def _clean_cache():
    """The site engine caches for six hours; that would leak between tests."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch):
    """Both of the site engine's network signals unavailable by default.

    Deliberately the *pessimistic* default: any test that gets a URL verdict
    without opting in is seeing what a user on hotel wifi sees.
    """
    monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: None)
    monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: None)


@pytest.fixture
def site_signals(monkeypatch: pytest.MonkeyPatch):
    """Factory: pin the site engine's two network signals to chosen values."""

    def _apply(sb: tuple[bool, list[str]] | None, age: int | None):
        monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: sb)
        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: age)

    return _apply


def signal_names(result) -> set[str]:
    return {signal.signal for signal in result.signals}


def upi(**params: str) -> str:
    """Build a ``upi://pay`` payload from keyword parameters."""
    query = "&".join(f"{key}={value}" for key, value in params.items())
    return f"upi://pay?{query}"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestClassification:
    @pytest.mark.parametrize(
        "payload,kind",
        [
            ("https://example.com/x", "url"),
            ("http://example.com", "url"),
            ("upi://pay?pa=a@ybl", "upi"),
            ("WIFI:T:WPA;S:MyNet;P:secret;;", "wifi"),
            ("BEGIN:VCARD\nFN:Bob\nEND:VCARD", "vcard"),
            ("MECARD:N:Bob;;", "vcard"),
            ("tel:+911234567890", "tel"),
            ("smsto:+911234567890:hello", "sms"),
            ("mailto:a@b.com", "mailto"),
            ("geo:12.9,77.6", "geo"),
            ("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "crypto"),
            ("just some words", "text"),
            ("", "text"),
        ],
    )
    def test_kinds(self, payload: str, kind: str) -> None:
        assert parse(payload).kind == kind

    def test_ftp_is_not_a_url(self) -> None:
        """Only http(s) counts as a link.

        An allowlist, not a denylist: handing an unfamiliar scheme to the site
        engine would send it to Safe Browsing and get back a meaningless
        "not listed", which reads on screen as reassurance.
        """
        assert parse("ftp://files.example.com/x").kind == "text"

    def test_upi_parameters_are_read(self) -> None:
        parsed = parse(upi(pa="shop@okhdfcbank", pn="Chai%20Point", am="45.50", tn="tea", mc="5812"))
        assert parsed.upi is not None
        assert parsed.upi.payee_vpa == "shop@okhdfcbank"
        assert parsed.upi.handle == "okhdfcbank"
        assert parsed.upi.payee_name == "Chai Point"
        assert parsed.upi.amount == Decimal("45.50")
        assert parsed.upi.merchant_code == "5812"

    def test_a_vpa_with_two_at_signs_splits_on_the_last(self) -> None:
        """``a@ybl@evil`` must not read its handle as ``ybl``.

        Splitting on the first ``@`` would let an attacker park a recognised
        handle where a human eye stops reading and put the real one after it.
        """
        parsed = parse(upi(pa="a@ybl@evil"))
        assert parsed.upi is not None
        assert parsed.upi.handle == "evil"


class TestAmountParsing:
    def test_absent_and_unreadable_are_different_answers(self) -> None:
        """The missing-signal rule, applied to a single field.

        No ``am`` means the payer types the amount. An ``am`` we could not read
        means the code specified one and we failed — which is a reason to
        distrust the code, not to describe it as open-ended.
        """
        absent = parse(upi(pa="a@ybl")).upi
        broken = parse(upi(pa="a@ybl", am="fifty%20thousand")).upi
        assert absent is not None and broken is not None

        assert absent.amount is None and absent.amount_unreadable is False
        assert broken.amount is None and broken.amount_unreadable is True

    @pytest.mark.parametrize("raw", ["-5", "NaN", "Infinity", "1e999999"])
    def test_hostile_amounts_are_rejected_not_believed(self, raw: str) -> None:
        parsed = parse(upi(pa="a@ybl", am=raw)).upi
        assert parsed is not None
        assert parsed.amount is None


# ---------------------------------------------------------------------------
# The scam this module exists for
# ---------------------------------------------------------------------------


class TestReceiveMoneyScam:
    def test_large_prefilled_amount_is_dangerous(self) -> None:
        result = analyse(upi(pa="rahul@ybl", pn="Refund", am="50000"))

        assert result.verdict == "dangerous"
        assert result.risk_score >= THRESHOLD_DANGEROUS
        assert "amount_on_receive_qr" in signal_names(result)

    def test_the_direction_of_the_money_is_stated_in_words(self) -> None:
        """The one fact the victim has backwards, said explicitly.

        A score does not correct a misunderstanding. The sentence has to.
        """
        result = analyse(upi(pa="rahul@ybl", am="50000"))
        finding = next(s for s in result.signals if s.signal == "amount_on_receive_qr")

        assert "out of your account" in finding.detail
        assert "can only send money, never receive it" in finding.detail

    def test_the_destination_names_the_amount_and_the_account(self) -> None:
        """The most important field in the response.

        A QR code is unreadable to a human. Showing where it actually goes is
        most of the protection, and the verdict is the rest.
        """
        result = analyse(upi(pa="rahul@ybl", am="50000"))
        assert result.destination == "Pays INR 50,000 to rahul@ybl"

    def test_recommendation_corrects_the_belief_not_just_the_action(self) -> None:
        result = analyse(upi(pa="rahul@ybl", am="50000"))
        assert "No QR code can put money into your account" in result.recommendation

    def test_the_full_scam_payload(self) -> None:
        """Name, amount, and note together — the code a victim is actually sent."""
        result = analyse(
            upi(
                pa="rahul-refund@ybl",
                pn="Amazon%20Refund",
                am="50000",
                tn="Urgent%20refund%20claim%20within%2024%20hours",
            )
        )

        assert result.verdict == "dangerous"
        names = signal_names(result)
        assert "amount_on_receive_qr" in names
        assert "payee_name_brand_mismatch" in names
        assert "urgent_note" in names


class TestBrandImpersonation:
    def test_brand_in_the_vpa_is_flagged(self) -> None:
        result = analyse(upi(pa="sbi-kyc@fakebank", am="1"))
        assert "payee_brand_mismatch" in signal_names(result)

    def test_brand_in_the_displayed_name_is_flagged(self) -> None:
        """The field the victim actually reads."""
        result = analyse(upi(pa="rahul123@ybl", pn="Amazon%20Refund"))
        assert "payee_name_brand_mismatch" in signal_names(result)

    def test_a_brands_own_handle_is_silent(self) -> None:
        """``amazon@apl`` is Amazon Pay. Flagging it would be the false positive
        that gets the whole check switched off."""
        result = analyse(upi(pa="amazon@apl", pn="Amazon"))
        names = signal_names(result)
        assert "payee_brand_mismatch" not in names
        assert "payee_name_brand_mismatch" not in names

    def test_the_same_impersonation_is_never_counted_twice(self) -> None:
        """One fake VPA is one finding.

        Reporting the VPA and the display name separately would let the breadth
        bump treat a single fact as two agreeing signals — precisely what the
        max-plus-breadth rule exists to prevent.
        """
        result = analyse(upi(pa="sbi-refund@fakebank", pn="SBI"))
        names = signal_names(result)
        assert "payee_brand_mismatch" in names
        assert "payee_name_brand_mismatch" not in names

    def test_token_matching_not_substring_matching(self) -> None:
        """``amazonaws`` is one token and is not ``amazon`` — same rule as sites."""
        result = analyse(upi(pa="amazonaws@ybl"))
        assert "payee_brand_mismatch" not in signal_names(result)


class TestUnknownHandles:
    def test_unrecognised_handle_is_flagged_but_not_called_fake(self) -> None:
        """New PSPs launch. An incomplete list must not speak as an authority."""
        result = analyse(upi(pa="someone@brandnewpsp"))
        finding = next(s for s in result.signals if s.signal == "unknown_psp_handle")

        assert "does not prove it is fake" in finding.detail
        assert result.verdict != "dangerous"

    @pytest.mark.parametrize("handle", ["ybl", "okhdfcbank", "paytm", "upi", "apl", "oksbi"])
    def test_real_handles_are_recognised(self, handle: str) -> None:
        assert is_known_handle(handle)

    def test_handle_matching_ignores_case(self) -> None:
        assert "unknown_psp_handle" not in signal_names(analyse(upi(pa="a@YBL")))


# ---------------------------------------------------------------------------
# The counterweight
# ---------------------------------------------------------------------------


class TestLegitimatePaymentsStaySilent:
    def test_a_shop_counter_qr_is_not_dangerous(self) -> None:
        """A merchant code plus a small amount is a chai stall, not a scam.

        This module flagging every shop in India would get it muted, and a muted
        detector protects nobody.
        """
        result = analyse(upi(pa="q12345678@okhdfcbank", pn="Chai%20Point", am="45", mc="5812"))
        assert result.verdict == "safe"
        assert result.risk_score < THRESHOLD_SUSPICIOUS

    def test_a_plain_person_to_person_qr_is_safe(self) -> None:
        result = analyse(upi(pa="friend@okaxis", pn="Friend"))
        assert result.verdict == "safe"
        assert result.risk_score == 0

    def test_a_clean_verdict_never_claims_certainty(self) -> None:
        """"We found nothing" and "this is definitely safe" are different claims."""
        result = analyse(upi(pa="friend@okaxis"))
        assert result.verdict == "safe"
        assert result.confidence <= 0.80

    def test_amount_alone_below_the_large_threshold_is_not_dangerous(self) -> None:
        result = analyse(upi(pa="friend@okaxis", am=str(int(LARGE_AMOUNT) - 1)))
        assert result.verdict == "suspicious"
        assert result.risk_score < THRESHOLD_DANGEROUS


# ---------------------------------------------------------------------------
# URLs — delegation to Module 2
# ---------------------------------------------------------------------------


class TestUrlPayloads:
    def test_a_url_payload_delegates_to_the_site_engine(self, site_signals) -> None:
        site_signals((True, ["SOCIAL_ENGINEERING"]), 4_000)
        result = analyse("https://phishy.example/login")

        assert result.kind == "url"
        assert result.verdict == "dangerous"
        assert result.site is not None
        assert result.site.domain == "phishy.example"

    def test_trust_and_risk_run_in_opposite_directions(self, site_signals) -> None:
        """The one subtraction in the module, asserted rather than assumed."""
        site_signals((False, []), 4_000)
        result = analyse("https://example.com/")
        assert result.site is not None
        assert result.risk_score == 100 - result.site.trust_score

    def test_a_shortener_is_flagged_on_a_qr_even_when_the_site_is_clean(
        self, site_signals
    ) -> None:
        """Ordinary on the web, abnormal on a printed code.

        A shortener defeats the only inspection the user could have performed
        before scanning, which is a QR-specific problem and gets a QR-specific
        signal.
        """
        site_signals((False, []), 4_000)
        result = analyse("https://bit.ly/3xYz")
        assert "shortened_link" in signal_names(result)
        assert result.verdict != "safe"

    def test_a_bare_ip_is_flagged(self, site_signals) -> None:
        site_signals((False, []), 4_000)
        assert "raw_ip_link" in signal_names(analyse("http://203.0.113.5/pay"))

    def test_a_qr_that_resolves_to_a_site_carries_the_site_result(self, site_signals) -> None:
        """So the router can write a ``SiteCheck`` and feed the Browsing score."""
        site_signals((True, ["MALWARE"]), 10)
        assert analyse("https://bad.example/x").site is not None

    def test_a_upi_qr_carries_no_site_result(self) -> None:
        """No domain means no row, rather than a fabricated one.

        Storing ``upi`` or a VPA in a column called ``domain`` to avoid an empty
        space would put an invented fact in front of the risk engine.
        """
        assert analyse(upi(pa="a@ybl")).site is None


# ---------------------------------------------------------------------------
# Unknown is not safe
# ---------------------------------------------------------------------------


class TestUnknownIsNotSafe:
    def test_an_unreachable_lookup_gives_unknown_not_safe(self) -> None:
        """Both network signals are down via the autouse fixture."""
        result = analyse("https://never-heard-of-it.example/")
        assert result.verdict == "unknown"
        assert result.risk_score < THRESHOLD_SUSPICIOUS

    def test_an_unreachable_lookup_does_not_suppress_an_offline_finding(self) -> None:
        """Thin evidence blocks a clean bill of health; it never mutes a warning.

        The site lookup could not answer, but a bare-IP destination is a fact we
        established without it, and it stands.
        """
        result = analyse("http://203.0.113.5/pay")
        assert result.verdict == "dangerous"
        assert "raw_ip_link" in signal_names(result)

    def test_a_upi_code_with_no_payee_is_unknown(self) -> None:
        """There is no destination to judge, whatever else the code contains."""
        result = analyse(upi(am="999"))
        assert result.verdict == "unknown"
        assert "missing_vpa" in signal_names(result)

    def test_a_missing_payee_is_reported_as_an_absence_not_a_finding(self) -> None:
        result = analyse(upi(am="999"))
        row = next(s for s in result.signals if s.signal == "missing_vpa")
        assert row.weight == "unknown"

    def test_a_malformed_payee_is_a_finding_not_an_absence(self) -> None:
        """"No UPI ID" and "not a valid UPI ID" are different statements.

        The second one is evidence: no legitimate app emits it.
        """
        result = analyse(upi(pa="notavpa", am="999"))
        assert result.verdict == "dangerous"
        assert "malformed_vpa" in signal_names(result)

    def test_plain_text_is_unknown_and_says_why(self) -> None:
        result = analyse("Please call me back")
        assert result.verdict == "unknown"
        assert "not_a_destination" in signal_names(result)

    def test_a_contact_card_with_a_clean_link_is_still_unknown(self, site_signals) -> None:
        """One clean string inside a payload is not a clean payload."""
        site_signals((False, []), 4_000)
        result = analyse("BEGIN:VCARD\nFN:Bob\nURL:https://example.com/\nEND:VCARD")
        assert result.verdict == "unknown"

    def test_a_wifi_code_is_never_called_safe(self) -> None:
        """Encryption was checked. Who runs the network was not."""
        result = analyse("WIFI:T:WPA;S:Cafe;P:secret;;")
        assert result.verdict == "unknown"
        assert "wifi_name_unverified" in signal_names(result)


# ---------------------------------------------------------------------------
# Hostile payloads
# ---------------------------------------------------------------------------


class TestHostilePayloads:
    @pytest.mark.parametrize(
        "payload",
        [
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "intent://scan#Intent;scheme=zxing;end",
            "file:///etc/passwd",
        ],
    )
    def test_executable_schemes_are_dangerous_and_never_looked_up(self, payload: str) -> None:
        result = analyse(payload)
        assert result.verdict == "dangerous"
        assert "dangerous_scheme" in signal_names(result)
        # Never handed to the site engine: a "not listed" answer about a
        # `javascript:` string reads on screen as reassurance.
        assert result.site is None

    def test_a_newline_cannot_push_the_destination_out_of_view(self) -> None:
        """Whitespace is collapsed, so a payload cannot pad itself off a toast."""
        result = analyse(upi(pa="a@ybl", pn="Amazon" + "%0A" * 200 + "Refund"))
        assert "\n" not in result.destination
        for signal in result.signals:
            assert "\n" not in signal.detail
            assert "\n" not in (signal.evidence or "")

    def test_evidence_is_bounded(self) -> None:
        result = analyse(upi(pa="a" * 3_000 + "@ybl"))
        for signal in result.signals:
            assert len(signal.evidence or "") <= 300

    def test_a_maximum_length_payload_does_not_raise(self) -> None:
        assert analyse("x" * MAX_PAYLOAD_CHARS).verdict == "unknown"

    @pytest.mark.parametrize(
        "payload",
        ["", "   ", "upi://", "upi://pay?", "WIFI:", "BEGIN:VCARD", "%%%", "upi://pay?pa=&am="],
    )
    def test_degenerate_payloads_never_raise(self, payload: str) -> None:
        result = analyse(payload)
        assert result.verdict in {"dangerous", "suspicious", "safe", "unknown"}
        assert result.summary
        assert result.recommendation
        assert result.destination


# ---------------------------------------------------------------------------
# The explainability contract
# ---------------------------------------------------------------------------


class TestExplainability:
    @pytest.mark.parametrize(
        "payload",
        [
            "upi://pay?pa=a@ybl&am=50000",
            "upi://pay?pa=friend@okaxis",
            "https://example.com/",
            "WIFI:T:nopass;S:Free;;",
            "tel:+911234567890",
            "javascript:void(0)",
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ],
    )
    def test_every_verdict_carries_reasons_and_an_action(self, payload: str) -> None:
        result = analyse(payload)

        assert result.summary.strip()
        assert result.recommendation.strip()
        assert result.destination.strip()
        assert result.signals
        for signal in result.signals:
            assert signal.detail.strip()
            assert signal.weight in {"bad", "good", "unknown"}

    def test_findings_are_listed_before_passing_checks(self) -> None:
        """A user reads the top of a list."""
        result = analyse(upi(pa="sbi-kyc@fakebank", am="50000"))
        weights = [s.weight for s in result.signals]
        order = {"bad": 0, "unknown": 1, "good": 2}
        assert weights == sorted(weights, key=lambda w: order[w])

    def test_checks_that_passed_are_shown_not_hidden(self) -> None:
        """Evidence includes what was examined and came back clean."""
        result = analyse(upi(pa="friend@okaxis"))
        assert any(s.weight == "good" for s in result.signals)

    def test_the_unverifiable_payee_name_is_always_stated(self) -> None:
        """Not a finding — a permanent property of the format users do not know."""
        result = analyse(upi(pa="friend@okaxis"))
        row = next(s for s in result.signals if s.signal == "payee_name_unverified")
        assert row.weight == "unknown"


# ---------------------------------------------------------------------------
# Advice has to fit the thing on screen
# ---------------------------------------------------------------------------


class TestAdviceMatchesThePayload:
    """Regression cover for a real defect found in live output.

    The recommendation table was originally keyed on the verdict alone and
    written UPI-first, so an open Wi-Fi network came back with *"Never approve
    an amount you did not enter."* Nothing crashed and no score was wrong — but
    advice that plainly does not fit what is on screen is the fastest way to
    teach a user that this panel is not worth reading, and once they have
    learned that, the correct warnings go unread too.

    These tests assert the seam rather than the wording: payment vocabulary must
    not appear on non-payment codes, and each family must say something about
    its own risk.
    """

    #: Words that only make sense when money is moving through a UPI app.
    PAYMENT_WORDS = ("approve", "amount", "upi app", "your bank")

    @pytest.mark.parametrize(
        "payload",
        [
            "WIFI:T:nopass;S:Free Airport WiFi;;",
            "WIFI:T:WPA;S:Cafe;P:secret;;",
            "https://example.com/",
            "tel:+911234567890",
            "mailto:someone@example.com",
            "BEGIN:VCARD\nFN:Priya\nEND:VCARD",
            "just some plain text",
        ],
    )
    def test_non_payment_codes_are_not_given_payment_advice(self, payload: str) -> None:
        advice = analyse(payload).recommendation.lower()
        for word in self.PAYMENT_WORDS:
            assert word not in advice, f"payment wording {word!r} leaked into: {advice}"

    def test_a_upi_code_still_gets_payment_advice(self) -> None:
        """The counterweight: the fix must not have made the primary case vague."""
        advice = analyse(upi(pa="a@ybl", am="50000")).recommendation.lower()
        assert "upi" in advice
        assert any(word in advice for word in ("scan", "approve"))

    def test_a_link_is_told_what_not_to_type(self) -> None:
        """The realistic harm from a QR link is a credential typed into it."""
        advice = analyse("https://example.com/").recommendation.lower()
        assert "otp" in advice or "password" in advice

    def test_wifi_advice_talks_about_the_network(self) -> None:
        advice = analyse("WIFI:T:nopass;S:Free Airport WiFi;;").recommendation.lower()
        assert "network" in advice or "mobile data" in advice

    def test_crypto_advice_does_not_borrow_bank_reassurance(self) -> None:
        """There is no bank to call and no amount to re-check. Saying otherwise
        would undercut the one finding that matters — it is irreversible."""
        advice = analyse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").recommendation.lower()
        assert "reversed" in advice
        assert "your bank" not in advice

    def test_an_unrecognised_kind_still_gets_cautious_advice(self) -> None:
        """A payload nobody anticipated must not raise. A KeyError here would
        surface as a 500, which reads as a broken tool rather than a careful one."""
        result = analyse("SOMETHINGNEW:v=1;data=xyz")
        assert result.recommendation.strip()
        assert result.verdict != "safe"


# ---------------------------------------------------------------------------
# Combination arithmetic
# ---------------------------------------------------------------------------


class TestCombination:
    def test_findings_combine_as_max_plus_breadth_never_as_a_sum(self) -> None:
        """Three findings worth 80, 85, and 50 must not add up to 215."""
        result = analyse(
            upi(pa="sbi-kyc@fakebank", am="50000", tn="urgent%20act%20now%20or%20account%20blocked")
        )
        assert result.risk_score <= 100
        # max(80, 85, 50, 50) + 6 * (n - 1) — well short of any sum.
        assert result.risk_score < 80 + 85

    def test_more_findings_score_higher_than_fewer(self) -> None:
        one = analyse(upi(pa="a@ybl", am="50000"))
        two = analyse(upi(pa="sbi-kyc@fakebank", am="50000"))
        assert two.risk_score > one.risk_score


# ---------------------------------------------------------------------------
# Endpoint contract
# ---------------------------------------------------------------------------


class TestEndpoint:
    def test_a_scam_qr_returns_a_dangerous_verdict(self, client, auth_headers) -> None:
        response = client.post(
            "/api/v1/qr/check",
            json={"payload": "upi://pay?pa=rahul@ybl&pn=Amazon&am=50000"},
            headers=auth_headers,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["verdict"] == "dangerous"
        assert body["kind"] == "upi"
        assert body["destination"]
        assert body["signals"]
        # No domain, no trust score — a payment has neither, and null says so.
        assert body["domain"] is None
        assert body["trust_score"] is None

    def test_an_uncheckable_payload_is_200_not_an_error(self, client, auth_headers) -> None:
        """"We could not check" must not be indistinguishable from a broken backend."""
        response = client.post(
            "/api/v1/qr/check", json={"payload": "hello there"}, headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "unknown"

    def test_an_oversized_payload_is_rejected_at_the_edge(self, client, auth_headers) -> None:
        response = client.post(
            "/api/v1/qr/check",
            json={"payload": "x" * (MAX_PAYLOAD_CHARS + 1)},
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_a_blank_payload_is_rejected(self, client, auth_headers) -> None:
        response = client.post("/api/v1/qr/check", json={"payload": "   "}, headers=auth_headers)
        assert response.status_code == 422

    def test_a_qr_link_feeds_the_browsing_score(
        self, client, auth_headers, site_signals
    ) -> None:
        """A scanned link is a site visit about to happen, so it lands in the
        same table with the same rules rather than in a parallel one."""
        from app.db.models import SiteCheck
        from app.db.session import SessionLocal

        site_signals((True, ["SOCIAL_ENGINEERING"]), 5)
        response = client.post(
            "/api/v1/qr/check",
            json={"payload": "https://qr-scam.example/pay"},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert response.json()["domain"] == "qr-scam.example"
        with SessionLocal() as db:
            rows = db.query(SiteCheck).filter(SiteCheck.domain == "qr-scam.example").all()
        assert len(rows) == 1

    def test_a_upi_qr_writes_nothing(self, client, auth_headers) -> None:
        from app.db.models import SiteCheck
        from app.db.session import SessionLocal

        client.post(
            "/api/v1/qr/check",
            json={"payload": "upi://pay?pa=rahul@ybl&am=50000"},
            headers=auth_headers,
        )

        with SessionLocal() as db:
            assert db.query(SiteCheck).count() == 0

    def test_the_response_requires_an_explanation(self) -> None:
        """Enforced by the schema, not by convention."""
        from app.schemas.qr import QrCheckResponse

        for field in ("summary", "recommendation", "destination", "signals"):
            assert QrCheckResponse.model_fields[field].is_required()
