"""Module 12 — checksum-backed recovery of OCR'd identifiers.

The tests are split by what they protect. The first group proves the feature
works at all. Every group after it proves the feature cannot be turned into a
machine for inventing government IDs, which is the failure mode that matters:
a missed Aadhaar is a gap, and a fabricated Aadhaar is a tool nobody should run.

No image, no OCR engine, no server. ``recover`` takes a string, so the whole
module is testable with the strings a real OCR pass produces.
"""

from __future__ import annotations

import pytest

from app.services.pii.checksums import verhoeff_checksum_digit
from app.services.pii.detectors import scan_text
from app.services.pii.engine import scan
from app.services.pii.ocr_normalise import (
    CONFUSABLES,
    MAX_OCR_CONFIDENCE,
    MAX_SUBSTITUTIONS,
    OCR_TIER,
    normalise,
    recover,
)


def aadhaar(first_eleven: str) -> str:
    """A synthetic Verhoeff-valid Aadhaar number.

    Generated rather than hardcoded for the reason ``checksums.py`` gives: a real
    government ID in a public test fixture is precisely the leak this product
    exists to prevent.
    """
    return first_eleven + str(verhoeff_checksum_digit(first_eleven))


#: Verhoeff-valid, issued to nobody.
VALID_AADHAAR = aadhaar("23456789901")
#: The standard Luhn-valid test Visa. Never issued.
VALID_CARD = "4111111111111111"


def mangle(digits: str, swaps: dict[int, str]) -> str:
    """Replace digits at the given indices with the letters OCR mistakes them for.

    The assertion is a fixture guard, not a test: a swap that is not in
    ``CONFUSABLES`` would make the case below prove nothing, because ``normalise``
    would refuse it for the wrong reason.
    """
    chars = list(digits)
    for index, letter in swaps.items():
        assert CONFUSABLES[letter] == chars[index], "fixture must be a real confusion"
        chars[index] = letter
    return "".join(chars)


#: ``234567899014`` — index 9 is the '0', index 3 is the '5'. Named so a change to
#: the synthetic number above fails in one place instead of eight.
ONE_SWAP = {9: "O"}
TWO_SWAPS = {9: "O", 3: "S"}


# ---------------------------------------------------------------------------


class TestItRecoversWhatTheDirectScanCannot:
    def test_an_aadhaar_with_a_misread_zero_is_found(self):
        # Index 9 of 23456789901X is a '0'. Tesseract reads it as 'O'.
        text = f"Aadhaar {mangle(VALID_AADHAAR, ONE_SWAP)}"

        assert scan_text(text) == [], "precondition: the direct scan must miss this"

        found = recover(text)
        assert [f.pii_type for f in found] == ["aadhaar"]

    def test_the_spaced_layout_printed_on_the_card_is_handled(self):
        # An Aadhaar card prints 4-4-4. OCR keeps the spacing.
        spaced = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}"
        text = spaced.replace("5", "S", 1)

        found = recover(text)
        assert [f.pii_type for f in found] == ["aadhaar"]

    def test_a_card_number_with_a_misread_one_is_found(self):
        text = f"card {VALID_CARD.replace('1', 'I', 1)} exp 09/28"

        assert scan_text(text) == []

        found = recover(text)
        assert [f.pii_type for f in found] == ["credit_card"]

    def test_two_corrections_in_one_number_still_work(self):
        text = mangle(VALID_AADHAAR, TWO_SWAPS)
        assert [f.pii_type for f in recover(text)] == ["aadhaar"]


class TestOnlyChecksumsMayAuthoriseACorrection:
    """The single property that keeps this module honest."""

    def test_a_failing_checksum_is_not_reported(self):
        # Same shape, same length, one digit changed so Verhoeff fails.
        broken = VALID_AADHAAR[:-1] + str((int(VALID_AADHAAR[-1]) + 1) % 10)
        text = mangle(broken, ONE_SWAP) if broken[9] == "0" else broken.replace("5", "S", 1)

        assert recover(text) == []

    def test_pan_is_never_recovered_because_it_has_no_checksum(self):
        # A PAN is 5 letters, 4 digits, 1 letter. Nothing here may turn a word
        # into one, because there is no arithmetic that could confirm it.
        assert [f.pii_type for f in recover("ABCDE1234F")] == []
        assert [f.pii_type for f in recover("A8CDE1234F")] == []

    def test_only_aadhaar_and_card_are_recoverable(self):
        """A registry-wide guard: adding a checksum-free detector here must fail.

        The lists in this module are the security boundary. If a future change
        makes ``recover`` able to emit an IFSC code or a bank account — neither
        of which has a checksum — this test is the thing that says so.
        """
        from app.services.pii.ocr_normalise import _RECOVERABLE

        assert {name for name, _, _ in _RECOVERABLE} == {"aadhaar", "credit_card"}

    def test_an_ifsc_code_is_not_recovered(self):
        # HDFC0001234: the 'O'-for-'0' confusion runs the other way here, and an
        # IFSC has no checksum, so there is nothing to validate against.
        assert recover("IFSC HDFCOOO1234") == []


class TestItDoesNotDuplicateTheDirectScan:
    def test_a_clean_aadhaar_is_left_to_scan_text(self):
        text = f"Aadhaar {VALID_AADHAAR}"

        assert [f.pii_type for f in scan_text(text)] == ["aadhaar"]
        assert recover(text) == [], "nothing needed correcting, so this is not our finding"

    def test_the_engine_reports_one_finding_not_two(self):
        result = scan(f"Aadhaar {VALID_AADHAAR}", from_ocr=True)
        assert [f.pii_type for f in result.findings] == ["aadhaar"]

    def test_a_direct_match_wins_over_a_corrected_one_for_the_same_span(self):
        """Overlap resolution must prefer the read that needed no invention."""
        result = scan(f"Aadhaar {VALID_AADHAAR}", from_ocr=True)
        (finding,) = result.findings
        assert finding.detection_tier == "regex"


class TestCorrectionsAreBounded:
    def test_more_than_the_cap_is_refused(self):
        raw = "O" * (MAX_SUBSTITUTIONS + 1) + "1" * 8
        assert normalise(raw) is None

    def test_a_number_needing_four_corrections_is_not_recovered(self):
        # Deliberately built from a valid Aadhaar so the *checksum still passes*.
        # The refusal has to come from the substitution cap, not from arithmetic.
        swaps = {}
        for index, digit in enumerate(VALID_AADHAAR):
            letter = next((k for k, v in CONFUSABLES.items() if v == digit), None)
            if letter is not None:
                swaps[index] = letter
            if len(swaps) > MAX_SUBSTITUTIONS:
                break
        assert len(swaps) > MAX_SUBSTITUTIONS, "fixture needs enough confusable digits"

        text = mangle(VALID_AADHAAR, swaps)
        assert recover(text) == []

    def test_normalise_refuses_a_token_containing_an_unmapped_letter(self):
        assert normalise("2345X789901" + "4") is None

    def test_normalise_refuses_pure_digits(self):
        assert normalise(VALID_AADHAAR) is None


class TestOneCandidatePerSpan:
    """No search. Every confusable has exactly one digit reading.

    This is what keeps the false-positive rate at the checksum's own one-in-ten
    instead of multiplying it by the number of variants tried.
    """

    def test_the_map_is_a_function(self):
        for char, digit in CONFUSABLES.items():
            assert len(digit) == 1 and digit.isdigit()

    def test_normalise_is_deterministic(self):
        raw = mangle(VALID_AADHAAR, ONE_SWAP)
        first = normalise(raw)
        assert first is not None
        assert normalise(raw) == first

    def test_digits_are_never_rewritten(self):
        """Only letters become digits. A digit read as a digit is not doubted."""
        assert not any(char.isdigit() for char in CONFUSABLES)


class TestTokensAreNotMisSegmented:
    def test_a_run_inside_a_longer_word_is_not_a_candidate(self):
        # If the pattern trimmed to whatever was numeric, this would produce a
        # candidate from a bank branch code.
        assert recover(f"REF{VALID_AADHAAR.replace('5', 'S', 1)}X") == []

    def test_a_newline_does_not_splice_two_fields_together(self):
        """OCR emits one line per printed field. Joining them invents a number."""
        head, tail = VALID_AADHAAR[:6], VALID_AADHAAR[6:]
        text = f"{head.replace('5', 'S', 1)}\n{tail}"
        assert recover(text) == []

    def test_an_ordinary_word_is_not_read_as_a_number(self):
        # Twelve letters, all confusable, and the checksum is what refuses it.
        # Belt and braces with the substitution cap, which refuses it first.
        for word in ("Bibliography", "Sociological", "Astrologists"):
            assert recover(word) == []


class TestRecoveredFindingsSayTheyWereGuessed:
    def test_confidence_is_capped_below_the_typed_detector(self):
        (finding,) = recover(mangle(VALID_AADHAAR, ONE_SWAP))
        assert finding.confidence <= MAX_OCR_CONFIDENCE
        assert finding.confidence < 0.96, "the typed Aadhaar confidence"

    def test_confidence_falls_as_more_characters_are_corrected(self):
        (one,) = recover(mangle(VALID_AADHAAR, ONE_SWAP))
        (two,) = recover(mangle(VALID_AADHAAR, TWO_SWAPS))
        assert two.confidence < one.confidence

    def test_the_reason_names_the_checksum_and_every_substitution(self):
        (finding,) = recover(mangle(VALID_AADHAAR, TWO_SWAPS))
        assert "Verhoeff" in finding.reason
        assert "image" in finding.reason.lower()
        assert "O → 0" in finding.reason
        assert "S → 5" in finding.reason

    def test_the_tier_is_marked_ocr(self):
        (finding,) = recover(mangle(VALID_AADHAAR, ONE_SWAP))
        assert finding.detection_tier == OCR_TIER

    @pytest.mark.parametrize("attribute", ["reason", "explanation", "recommendation"])
    def test_the_explainability_contract_holds(self, attribute):
        (finding,) = recover(mangle(VALID_AADHAAR, ONE_SWAP))
        assert getattr(finding, attribute).strip(), "no bare verdicts, ever"

    def test_the_mask_shows_the_corrected_digits(self):
        """The user checks the warning against their own card. 'X9O14' reads as a bug."""
        (finding,) = recover(mangle(VALID_AADHAAR, ONE_SWAP))
        assert VALID_AADHAAR[-4:] in finding.masked_preview
        assert "O" not in finding.masked_preview


class TestTheFlagIsOffByDefault:
    def test_typed_text_is_never_corrected(self):
        """A typed 'S' is an 'S'. There was no camera in the path."""
        text = f"Aadhaar {mangle(VALID_AADHAAR, ONE_SWAP)}"
        assert scan(text).findings == []

    def test_the_same_text_is_found_when_the_flag_is_set(self):
        text = f"Aadhaar {mangle(VALID_AADHAAR, ONE_SWAP)}"
        result = scan(text, from_ocr=True)
        assert [f.pii_type for f in result.findings] == ["aadhaar"]
        assert result.risk_score > 0

    def test_suppression_is_honoured_on_the_ocr_path_too(self):
        """'Always allow Aadhaar here' is a promise about a category, not a path."""
        text = f"Aadhaar {mangle(VALID_AADHAAR, ONE_SWAP)}"
        result = scan(text, suppressed_types=frozenset({"aadhaar"}), from_ocr=True)
        assert result.findings == []


class TestEmptyAndDegenerateInput:
    @pytest.mark.parametrize("text", ["", "   ", "\n\n"])
    def test_nothing_from_nothing(self, text):
        assert recover(text) == []

    def test_a_page_of_prose_produces_nothing(self):
        prose = (
            "Dear Sir, please find attached the documents you requested for the "
            "loan application. I have signed page 3 and page 7. Let me know if "
            "anything else is needed before Friday."
        )
        assert recover(prose) == []
