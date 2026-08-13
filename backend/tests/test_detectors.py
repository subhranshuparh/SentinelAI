"""Detector tests, weighted toward false positives.

True positives are easy and mostly self-evident from the patterns. The tests that
earn their keep are the negative ones: an order ID that is not a card, a
reference number that is not a bank account, a meeting date that is not a
birthday. Those are what decide whether the extension gets kept or uninstalled,
so they are asserted explicitly and named after the scenario they protect.
"""

from __future__ import annotations

import pytest

from app.services.pii.checksums import verhoeff_checksum_digit
from app.services.pii.detectors import scan_text


def make_aadhaar(prefix: str = "22345678901", spaced: bool = True) -> str:
    """Generate a checksum-valid Aadhaar. Never hardcode a real one."""
    number = prefix + str(verhoeff_checksum_digit(prefix))
    return f"{number[:4]} {number[4:8]} {number[8:]}" if spaced else number


def types_in(text: str) -> set[str]:
    return {f.pii_type for f in scan_text(text)}


class TestTruePositives:
    def test_aadhaar_spaced_and_unspaced(self) -> None:
        assert "aadhaar" in types_in(f"My Aadhaar is {make_aadhaar()}")
        assert "aadhaar" in types_in(f"aadhaar {make_aadhaar(spaced=False)}")

    def test_card_with_luhn(self) -> None:
        assert "credit_card" in types_in("Card 4539 5787 6362 1486")

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Reach me at priya.sharma@example.com", "email"),
            ("call 9876543210", "phone"),
            ("PAN ABCDE1234F", "pan"),
            ("IFSC SBIN0001234", "ifsc"),
            ("pay me at priya@ybl", "upi_id"),
            ("password: hunter2secret", "password"),
            ("AKIA1234567890ABCDEF", "api_key"),
            ("we are at 19.076012, 72.877655", "coordinates"),
            ("DOB 15/08/1998", "dob"),
            ("passport P1234567 issued", "passport"),
        ],
    )
    def test_each_detector_fires(self, text: str, expected: str) -> None:
        assert expected in types_in(text)

    @pytest.mark.parametrize(
        "text",
        [
            "reach me at +91 98765 43210",
            "call 98765-43210 anytime",
            "my number is 9876543210",
        ],
    )
    def test_phone_in_every_common_written_form(self, text: str) -> None:
        """Indians write mobile numbers split 5+5 more often than unbroken."""
        assert "phone" in types_in(text)

    @pytest.mark.parametrize(
        "text",
        [
            "OPENAI_API_KEY=sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf01",
            "key sk-AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789",
        ],
    )
    def test_openai_key_shapes(self, text: str) -> None:
        """Legacy `sk-` and current `sk-proj-` are hyphenated, unlike Stripe's."""
        assert "api_key" in types_in(text)

    def test_jwt(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert "jwt" in types_in(f"here is my token {token}")


class TestFalsePositives:
    """The tests that decide whether a user keeps the extension installed."""

    def test_order_id_is_not_a_card(self) -> None:
        """A 16-digit order number fails Luhn, so it must not be flagged."""
        assert "credit_card" not in types_in("My order id is 1234567890123456 please check")

    def test_tracking_number_without_context_is_not_a_bank_account(self) -> None:
        """Same digits, no account wording -> silence. This is the context gate."""
        assert types_in("ref number 123456789012 for the parcel") == set()

    def test_same_digits_with_account_context_do_fire(self) -> None:
        """Control for the test above: the gate opens when context is present."""
        assert "bank_account" in types_in("my account number is 123456789012 at HDFC")

    def test_meeting_date_is_not_a_birthday(self) -> None:
        assert "dob" not in types_in("The meeting is on 15/08/1998 agenda attached")

    def test_sequential_digits_are_not_aadhaar(self) -> None:
        """The number every demo reaches for. Verhoeff rejects it."""
        assert "aadhaar" not in types_in("test value 1234 5678 9012")

    def test_five_digit_groups_without_a_mobile_prefix_stay_silent(self) -> None:
        """"45000 12345" is an invoice line, not a number to call."""
        assert "phone" not in types_in("invoice 45000 12345 total")

    def test_landline_is_not_a_mobile(self) -> None:
        """Indian mobiles start 6-9; a 2-prefixed number must not fire."""
        assert "phone" not in types_in("dial 2234567890 for support")

    def test_grouped_phone_does_not_match_inside_card_or_aadhaar(self) -> None:
        """Allowing a 5+5 split must not let `phone` chew into other groupings.

        This is the risk the phone pattern trades against: any looser separator
        rule starts finding ten-digit "numbers" spanning the gaps in a card or
        Aadhaar, and the user gets two warnings for one value.
        """
        assert "phone" not in types_in("card 4111 1111 1111 1111 exp 12/28")
        assert "phone" not in types_in(f"My Aadhaar is {make_aadhaar()}")
        assert "phone" not in types_in("order id 1234567890123456 shipped")

    def test_short_sk_prefix_is_not_a_key(self) -> None:
        """`sk-` alone is a common abbreviation; only real key length fires."""
        assert "api_key" not in types_in("the sk-abc branch is merged")

    def test_plain_prose_is_silent(self) -> None:
        assert scan_text("Hi, hope you are doing well. Let's meet on Friday.") == []

    def test_empty_and_whitespace(self) -> None:
        assert scan_text("") == []
        assert scan_text("   \n  ") == []


class TestOverlapResolution:
    def test_upi_id_is_not_also_reported_as_email(self) -> None:
        """Both patterns match `priya@ybl`; only the specific one survives."""
        assert types_in("send to priya@ybl") == {"upi_id"}

    def test_card_is_not_also_reported_as_bank_account(self) -> None:
        found = types_in("my bank account card 4539 5787 6362 1486 details")
        assert "credit_card" in found
        assert "bank_account" not in found

    def test_spans_do_not_overlap(self) -> None:
        text = f"Aadhaar {make_aadhaar()} card 4539 5787 6362 1486 mail a@b.com"
        findings = scan_text(text)
        for earlier, later in zip(findings, findings[1:]):
            assert earlier.end <= later.start, "overlapping spans would double-warn"


class TestSuppression:
    def test_suppressed_type_is_never_returned(self) -> None:
        text = "call 9876543210 or mail a@b.com"
        assert types_in(text) == {"phone", "email"}
        remaining = {f.pii_type for f in scan_text(text, suppressed_types=frozenset({"phone"}))}
        assert remaining == {"email"}

    def test_suppressing_everything_yields_nothing(self) -> None:
        text = "call 9876543210 or mail a@b.com"
        assert scan_text(text, suppressed_types=frozenset({"phone", "email"})) == []


class TestFindingContract:
    """Every finding must be explainable and safe to persist."""

    def test_reason_and_confidence_always_present(self) -> None:
        text = f"Aadhaar {make_aadhaar()}, card 4539 5787 6362 1486, mail a@b.com"
        findings = scan_text(text)
        assert findings
        for finding in findings:
            assert finding.reason, "a bare verdict is not allowed"
            assert 0.0 < finding.confidence <= 0.99, "never claim certainty"
            assert finding.explanation and finding.recommendation

    def test_masked_preview_never_contains_the_full_value(self) -> None:
        aadhaar = make_aadhaar()
        finding = next(f for f in scan_text(f"Aadhaar {aadhaar}") if f.pii_type == "aadhaar")
        assert finding.masked_preview != aadhaar
        assert finding.masked_preview.endswith(aadhaar[-4:])
        assert "X" in finding.masked_preview

    def test_secrets_are_masked_harder_than_pii(self) -> None:
        """No tail is revealed for credentials — a key fragment is still material."""
        finding = next(f for f in scan_text("AKIA1234567890ABCDEF") if f.pii_type == "api_key")
        assert finding.masked_preview.startswith("AKIA")
        assert "ABCDEF" not in finding.masked_preview

    def test_spans_index_the_original_text(self) -> None:
        """start/end must slice the exact substring, or masking writes back wrong."""
        text = f"My Aadhaar is {make_aadhaar()} ok"
        finding = next(f for f in scan_text(text) if f.pii_type == "aadhaar")
        assert text[finding.start : finding.end] == make_aadhaar()
