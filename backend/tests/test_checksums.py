"""Checksum tests. No network, no server, no fixtures — runs in well under a second.

Deliberately runnable at any point in the build, including while the extension is
broken and nothing else works.

Note on test data: every Aadhaar number here is *generated* from an arbitrary
11-digit prefix via ``verhoeff_checksum_digit``. No real government ID appears in
this repository, and none should.
"""

from __future__ import annotations

import pytest

from app.services.pii.checksums import (
    card_brand,
    ifsc_structurally_valid,
    luhn_valid,
    verhoeff_checksum_digit,
    verhoeff_valid,
)


class TestLuhn:
    @pytest.mark.parametrize(
        "number",
        [
            "4539578763621486",  # Visa, test range
            "4539 5787 6362 1486",  # Spaces must not matter
            "4539-5787-6362-1486",  # Nor hyphens
            "5555555555554444",  # Mastercard test number
            "378282246310005",  # Amex, 15 digits
        ],
    )
    def test_accepts_valid_cards(self, number: str) -> None:
        assert luhn_valid(number) is True

    def test_rejects_single_digit_error(self) -> None:
        """The core value of Luhn: one wrong digit fails."""
        assert luhn_valid("4539578763621486") is True
        assert luhn_valid("4539578763621487") is False

    def test_rejects_transposition(self) -> None:
        """Adjacent transposition — the second most common typing error."""
        assert luhn_valid("4539578763621846") is False

    @pytest.mark.parametrize(
        "number,reason",
        [
            ("123456789012", "12 digits is too short for a card"),
            ("12345678901234567890", "20 digits is too long"),
            ("", "empty"),
            ("abcdefghijklmnop", "no digits"),
        ],
    )
    def test_rejects_wrong_length(self, number: str, reason: str) -> None:
        assert luhn_valid(number) is False, reason

    def test_order_id_is_not_a_card(self) -> None:
        """The false-positive case that motivates the whole module.

        A 16-digit order number will almost never satisfy Luhn (1-in-10 chance),
        so the checksum is what stops the tool from nagging about order IDs.
        """
        assert luhn_valid("1234567890123456") is False

    @pytest.mark.parametrize(
        "number,expected",
        [
            ("4539578763621486", "Visa"),
            ("5555555555554444", "Mastercard"),
            ("378282246310005", "American Express"),
            ("6011111111111117", "Discover"),
            ("9999999999999999", None),  # Unknown prefix must not raise.
        ],
    )
    def test_brand_detection(self, number: str, expected: str | None) -> None:
        assert card_brand(number) == expected


class TestVerhoeff:
    @staticmethod
    def _make_aadhaar(prefix_11: str) -> str:
        """Build a checksum-valid 12-digit number from an 11-digit prefix."""
        return prefix_11 + str(verhoeff_checksum_digit(prefix_11))

    @pytest.mark.parametrize(
        "prefix", ["22345678901", "99887766554", "34567890123", "78901234567"]
    )
    def test_generated_numbers_validate(self, prefix: str) -> None:
        """Round-trip: generator and validator must agree."""
        assert verhoeff_valid(self._make_aadhaar(prefix)) is True

    def test_formatting_is_ignored(self) -> None:
        number = self._make_aadhaar("22345678901")
        spaced = f"{number[:4]} {number[4:8]} {number[8:]}"
        hyphenated = f"{number[:4]}-{number[4:8]}-{number[8:]}"
        assert verhoeff_valid(spaced) is True
        assert verhoeff_valid(hyphenated) is True

    def test_rejects_single_digit_error(self) -> None:
        number = self._make_aadhaar("22345678901")
        broken = number[:5] + str((int(number[5]) + 1) % 10) + number[6:]
        assert verhoeff_valid(broken) is False

    def test_rejects_adjacent_transposition(self) -> None:
        """This is why Verhoeff, not Luhn: Luhn misses the 0<->9 transposition."""
        number = self._make_aadhaar("22345678901")
        swapped = number[:3] + number[4] + number[3] + number[5:]
        if number[3] != number[4]:  # A swap of identical digits is a no-op.
            assert verhoeff_valid(swapped) is False

    @pytest.mark.parametrize(
        "number,reason",
        [
            ("012345678901", "UIDAI never issues a leading 0"),
            ("112345678901", "nor a leading 1"),
            ("22345678901", "11 digits, too short"),
            ("223456789012345", "15 digits, too long"),
            ("", "empty"),
        ],
    )
    def test_rejects_invalid_shapes(self, number: str, reason: str) -> None:
        assert verhoeff_valid(number) is False, reason

    def test_sequential_number_is_rejected(self) -> None:
        """'123456789012' is the number every demo accidentally uses.

        It fails Verhoeff, which is the correct outcome and worth asserting so
        nobody 'fixes' the validator to make their demo text work.
        """
        assert verhoeff_valid("123456789012") is False

    def test_random_12_digits_rarely_pass(self) -> None:
        """Quantifies the false-positive claim rather than asserting it.

        Roughly 1 in 10 arbitrary 12-digit strings satisfies Verhoeff, so a plain
        regex would over-report by ~10x. Deterministic sample, no RNG.
        """
        candidates = [f"2{i:011d}" for i in range(1000)]
        passing = sum(1 for c in candidates if verhoeff_valid(c))
        assert 50 <= passing <= 150, f"expected ~10% to pass, got {passing}/1000"


class TestIfsc:
    @pytest.mark.parametrize("code", ["SBIN0001234", "HDFC0000123", "icic0abcd12"])
    def test_accepts_valid_shapes(self, code: str) -> None:
        assert ifsc_structurally_valid(code) is True

    @pytest.mark.parametrize(
        "code,reason",
        [
            ("SBIN1001234", "position 5 must be '0'"),
            ("SB1N0001234", "first four must be alphabetic"),
            ("SBIN000123", "too short"),
            ("SBIN00012345", "too long"),
            ("", "empty"),
        ],
    )
    def test_rejects_invalid_shapes(self, code: str, reason: str) -> None:
        assert ifsc_structurally_valid(code) is False, reason
