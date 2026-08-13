"""Checksum validators — what turns "12 digits" into "an Aadhaar number".

This module is the highest-value code in the PII tier and it is ~60 lines.

A bare 12-digit regex flags order IDs, tracking numbers, and timestamps. Adding
the Verhoeff checksum collapses false positives by roughly three orders of
magnitude: only 1 in 10 random 12-digit strings satisfies it, and the check runs
in microseconds with no network and no model.

The same argument applies to Luhn for payment cards. This is why the roadmap
puts checksums in Phase 1 rather than treating them as polish — they are the
difference between a tool the user trusts and one they disable on day one.

Every function here is pure: no I/O, no state, no config. Directly unit-testable.
"""

from __future__ import annotations


def digits_only(value: str) -> str:
    """Strip formatting so ``2234 5678 9013`` and ``2234-5678-9013`` both work."""
    return "".join(ch for ch in value if ch.isdigit())


# ---------------------------------------------------------------------------
# Luhn — payment cards (ISO/IEC 7812)
# ---------------------------------------------------------------------------


def luhn_valid(number: str) -> bool:
    """Validate a payment card number using the Luhn mod-10 algorithm.

    Double every second digit from the right; subtract 9 from any result over 9;
    a valid number's total is divisible by 10.

    Catches every single-digit error and almost every adjacent transposition,
    which is exactly the noise a regex alone would surface.
    """
    digits = digits_only(number)
    # Real card PANs are 13-19 digits. Anything outside that is not a card,
    # regardless of what the checksum says.
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    # Process right-to-left; `index` counts position from the right, 0-based.
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:  # Every second digit from the right.
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_brand(number: str) -> str | None:
    """Best-effort issuer identification from the IIN prefix.

    Used only to enrich the ``reason`` string ("Visa card number detected"),
    never to decide whether something *is* a card — that stays with Luhn. An
    unrecognised prefix must not suppress a valid finding, so this returns None
    rather than raising or vetoing.
    """
    digits = digits_only(number)
    if not digits:
        return None
    if digits.startswith("4"):
        return "Visa"
    if digits[:2] in {"51", "52", "53", "54", "55"}:
        return "Mastercard"
    if digits[:2] in {"34", "37"}:
        return "American Express"
    if digits[:4] == "6011" or digits[:2] == "65":
        return "Discover"
    # RuPay: relevant for the Indian PII set this project targets.
    if digits[:2] in {"60", "81", "82"}:
        return "RuPay"
    return None


# ---------------------------------------------------------------------------
# Verhoeff — Aadhaar (UIDAI)
# ---------------------------------------------------------------------------
#
# Verhoeff is used instead of Luhn because it detects ALL single-digit errors
# and ALL adjacent transpositions — including the 09<->90 pair that Luhn misses.
# It works over the dihedral group D5 via three lookup tables.

# Multiplication table for the dihedral group D5.
_D_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Permutation table, applied cyclically by digit position.
_P_TABLE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(number: str) -> bool:
    """Validate a 12-digit Aadhaar number using the Verhoeff checksum.

    Returns True only when the number is exactly 12 digits, does not start with
    0 or 1 (UIDAI never issues those), and the Verhoeff sum resolves to 0.
    """
    digits = digits_only(number)
    if len(digits) != 12:
        return False
    # UIDAI reserves leading 0 and 1. Cheap structural check before the maths,
    # and it removes a large class of ordinary numbers (phone-like, ID-like).
    if digits[0] in "01":
        return False

    checksum = 0
    for index, char in enumerate(reversed(digits)):
        checksum = _D_TABLE[checksum][_P_TABLE[index % 8][int(char)]]
    return checksum == 0


def verhoeff_checksum_digit(first_eleven: str) -> int:
    """Compute the 12th (check) digit for an 11-digit Aadhaar prefix.

    Not used in detection — this exists so tests can generate *valid* synthetic
    Aadhaar numbers instead of hardcoding a real one. Never put a real
    government ID in a test fixture; it ends up in a public repo.
    """
    digits = digits_only(first_eleven)
    if len(digits) != 11:
        raise ValueError("expected exactly 11 digits")

    checksum = 0
    # The check digit sits at position 0 from the right, which shifts every
    # other digit's position by one relative to validation.
    for index, char in enumerate(reversed(digits)):
        checksum = _D_TABLE[checksum][_P_TABLE[(index + 1) % 8][int(char)]]

    # Invert through D5: find the digit d where D[checksum][d] == 0.
    return next(d for d in range(10) if _D_TABLE[checksum][d] == 0)


# ---------------------------------------------------------------------------
# IFSC — Indian bank branch codes
# ---------------------------------------------------------------------------


def ifsc_structurally_valid(code: str) -> bool:
    """Validate IFSC shape: 4 alphabetic + '0' + 6 alphanumeric.

    There is no checksum in IFSC, so this is structure only. The fixed '0' at
    position 5 is reserved by RBI and is what makes the format distinctive
    enough to detect with acceptable precision.
    """
    code = code.strip().upper()
    if len(code) != 11:
        return False
    return code[:4].isalpha() and code[4] == "0" and code[5:].isalnum()
