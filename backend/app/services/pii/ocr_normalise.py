"""Recover checksum-backed identifiers from OCR'd text — Module 12.

Optical recognition does not fail randomly. It fails in a small, well-known set
of pairs, because the failures are shape collisions: ``0``/``O``, ``1``/``I``,
``5``/``S``, ``8``/``B``. A photographed Aadhaar card whose number reads
``234S 6789 9O14`` is not a partially-recognised number — every digit was read,
two of them into the wrong alphabet. The regex in ``detectors.py`` requires
twelve digits and sees ten, so it reports nothing, and the user uploads their
Aadhaar with a green tick beside it.

This module exists to close exactly that gap, and its whole design is about not
opening a much worse one while doing it.

**Only checksums may authorise a correction.** Rewriting a character is inventing
data. The only thing that makes an invented read trustworthy is an independent
arithmetic property the corrected string either satisfies or does not: Verhoeff
for Aadhaar, Luhn for cards. PAN, passport numbers, IFSC codes and bank accounts
are deliberately absent from this file. They have no checksum, so a "correction"
on one of them would be a bare assertion that a word is a government ID — and
this module would become a machine for hallucinating identity documents out of
low-resolution photographs.

**One candidate per span, not a search.** The obvious implementation tries every
combination of confusable substitutions and keeps whichever passes. That
implementation is broken, and the reason is worth stating plainly: Verhoeff and
Luhn each admit about one in ten random strings of the right length. Testing one
candidate inherits that one-in-ten. Testing thirty candidates finds a "valid"
Aadhaar in almost any twelve-character blob on the page. So the substitution map
below is a *function* — each character has exactly one digit reading — and every
span yields exactly one candidate. The checksum's own error rate is then the
whole error rate, which is the same rate ``detectors.py`` already accepts for
typed text.

**A correction is bounded, and its size is visible.** Past three corrected
characters the result is no longer a reading of the image; it is a guess that
happened to survive arithmetic. ``MAX_SUBSTITUTIONS`` refuses those. Below it,
confidence drops with every character corrected and the ``reason`` names each
substitution, so the user is told exactly how much of what they are being shown
was inferred rather than read.

Pure functions only — no I/O, no config, no model. ``tests/test_ocr_normalise.py``
exercises all of it with no server and no image.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.pii.checksums import luhn_valid, verhoeff_valid
from app.services.pii.detectors import DETECTORS, Finding
from app.services.pii.masking import mask_for

#: Character read by the OCR engine → the digit it was probably meant to be.
#:
#: A function, not a relation: see the module docstring on why every span must
#: produce exactly one candidate. Direction is one-way — letters become digits
#: and never the reverse, because a digit that was read *as a digit* is the one
#: part of the string there is no reason to doubt.
#:
#: The set is kept deliberately short. Every entry added here widens the class of
#: ordinary words that can be read as a number, and the only defence against
#: that is a checksum that is already only one-in-ten. These are the collisions
#: Tesseract actually produces on Indian ID cards and payment cards, which are
#: printed in the tall sans-serif faces where these particular shapes collide.
CONFUSABLES: dict[str, str] = {
    "O": "0", "o": "0", "Q": "0", "D": "0",
    "I": "1", "i": "1", "l": "1", "L": "1", "|": "1", "!": "1",
    "Z": "2", "z": "2",
    "A": "4",
    "S": "5", "s": "5",
    "G": "6",
    "T": "7",
    "B": "8",
    "g": "9", "q": "9",
}

#: Formatting that appears *inside* a printed identifier and carries no meaning.
#: Newlines are excluded on purpose: a line break between two digit groups means
#: OCR found them on different lines of the card, and joining them would splice
#: an Aadhaar number out of two unrelated fields.
SEPARATORS = " -"

#: Past this many corrected characters, stop. A twelve-digit number with four
#: characters rewritten is three-quarters read and one-quarter authored, and no
#: checksum can tell the difference between the two.
MAX_SUBSTITUTIONS = 3

#: Ceiling on the confidence of anything recovered here, regardless of how strong
#: the underlying detector is. Aadhaar's typed confidence is 0.96 and that number
#: means "the checksum validated on characters we actually received". Here some
#: of the characters were chosen by this file, and the displayed number has to
#: say so.
MAX_OCR_CONFIDENCE = 0.80

#: Subtracted per corrected character beyond the first, so the number itself
#: reports how much inference went into it: 0.80, 0.75, 0.70.
CONFIDENCE_PENALTY_PER_SUBSTITUTION = 0.05

#: Recorded in ``PiiEvent.detection_tier`` and on the finding. A third value
#: beside ``regex`` and ``llm``, and unranked in ``detectors._TIER_RANK`` on
#: purpose — the ``.get(tier, 9)`` default puts it last, so where an OCR-
#: recovered finding overlaps a directly-matched one, the one that needed no
#: correction wins. That is the correct precedence and it falls out for free.
#:
#: Written as a literal rather than imported from ``db.models.DetectionTier``
#: for the same reason ``detectors.Finding`` defaults to the string ``"regex"``:
#: nothing under ``services/pii/`` imports the ORM, so the detection engine is
#: testable with no database in the process at all. The enum mirrors this value
#: and carries the comment explaining why the two must agree.
OCR_TIER = "ocr"

#: Detector names this module may resurrect, and the checksum that authorises
#: each. Keyed by the exact digit length the identifier has, which also keeps the
#: two from ever competing for one span: Aadhaar is 12, a card PAN is 13-19.
#:
#: Adding an entry here without a checksum is the one change that would break
#: the module's guarantee, which is why the value is the validator itself rather
#: than a boolean flag beside it.
_RECOVERABLE = (
    ("aadhaar", verhoeff_valid, lambda n: n == 12),
    ("credit_card", luhn_valid, lambda n: 13 <= n <= 19),
)

_BY_NAME = {detector.name: detector for detector in DETECTORS}

# Built from the map rather than written out, so adding a confusable cannot
# leave the scanner unable to see it.
_CORE = "".join(re.escape(ch) for ch in sorted(set("0123456789") | set(CONFUSABLES)))

#: A standalone token made only of digits and confusables, with separators
#: allowed between them.
#:
#: The surrounding lookarounds reject any letter or digit on either side, so a
#: run embedded in a longer word is not a candidate at all. ``HDFC0001234`` does
#: not yield ``0001234``: the ``C`` before it is not in the map, the token is
#: therefore mis-segmented, and a mis-segmented token is thrown away rather than
#: trimmed to whatever happened to be numeric.
_CANDIDATE = re.compile(
    rf"(?<![A-Za-z0-9])[{_CORE}](?:[{_CORE}]|[{re.escape(SEPARATORS)}](?=[{_CORE}]))*(?![A-Za-z0-9])"
)


@dataclass(frozen=True)
class Correction:
    """One span of OCR output, read as digits.

    ``substitutions`` is carried separately from ``digits`` because it is what
    the user is shown. A correction the user cannot see is a correction they
    cannot disagree with.
    """

    digits: str
    substitutions: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.substitutions)


def normalise(raw: str) -> Correction | None:
    """Read ``raw`` as a digit string, or return ``None`` if it should not be.

    Returns ``None`` in three cases, each a deliberate refusal rather than a
    limitation:

    * a character is neither a digit, a separator, nor a known confusable — the
      token is not a mangled number, it is text;
    * **nothing needed correcting** — a run of pure digits was already visible to
      ``scan_text``, and re-reporting it here would show the user two warnings
      for one number and make the tool look broken;
    * more than ``MAX_SUBSTITUTIONS`` characters needed correcting.
    """
    digits: list[str] = []
    substitutions: list[str] = []

    for char in raw:
        if char in SEPARATORS:
            continue
        if char.isdigit():
            digits.append(char)
            continue
        replacement = CONFUSABLES.get(char)
        if replacement is None:
            return None
        digits.append(replacement)
        substitutions.append(f"{char} → {replacement}")

    if not substitutions or len(substitutions) > MAX_SUBSTITUTIONS:
        return None
    return Correction("".join(digits), tuple(substitutions))


def _confidence(count: int) -> float:
    """Confidence for a finding recovered from ``count`` corrected characters."""
    value = MAX_OCR_CONFIDENCE - CONFIDENCE_PENALTY_PER_SUBSTITUTION * (count - 1)
    return round(max(0.05, value), 2)


def _reason(label: str, checksum_name: str, correction: Correction) -> str:
    """The sentence that makes the correction auditable.

    Names the checksum, the number of characters changed, and each change. A
    user who reads "S → 5" can look at their own card and settle the question
    themselves, which is the only real check on a module that rewrites input.
    """
    changes = ", ".join(correction.substitutions)
    noun = "character" if correction.count == 1 else "characters"
    return (
        f"Read from an image: the {checksum_name} checksum for {label} validated after "
        f"correcting {correction.count} {noun} that optical recognition commonly "
        f"misreads ({changes})"
    )


_CHECKSUM_NAMES = {"aadhaar": "Verhoeff", "credit_card": "Luhn"}


def recover(text: str, suppressed_types: frozenset[str] | None = None) -> list[Finding]:
    """Findings that only a checksum-backed OCR correction could have produced.

    Returns findings for spans ``scan_text`` could not match because letters sat
    where digits belonged. Never returns a finding for a span that was already
    valid digits — those are ``scan_text``'s, and duplicating them would double
    the warning count for one value.

    ``suppressed_types`` is honoured here for the same reason it is honoured in
    ``scan_text``: "always allow Aadhaar on this site" is a promise about a
    category, not about which code path happened to notice it.
    """
    if not text or not text.strip():
        return []

    suppressed = suppressed_types or frozenset()
    findings: list[Finding] = []

    for match in _CANDIDATE.finditer(text):
        raw = match.group(0)
        correction = normalise(raw)
        if correction is None:
            continue

        for name, checksum, length_ok in _RECOVERABLE:
            if name in suppressed:
                continue
            if not length_ok(len(correction.digits)):
                continue
            if not checksum(correction.digits):
                continue

            detector = _BY_NAME[name]
            # The mask is built from the corrected digits, not the raw span: the
            # last four digits of an Aadhaar are what the user checks the warning
            # against, and showing them "9O14" would make a correct finding look
            # like a bug.
            masked = mask_for(name, correction.digits)
            findings.append(
                Finding(
                    pii_type=name,
                    label=detector.label,
                    risk_level=detector.risk_level,
                    confidence=_confidence(correction.count),
                    reason=_reason(detector.label, _CHECKSUM_NAMES[name], correction),
                    explanation=detector.explanation,
                    recommendation=detector.recommendation,
                    # Offsets into the *extracted text*, not into the image.
                    # There is nothing to highlight in a PNG, but the span is
                    # what ``resolve_overlaps`` needs to keep this finding from
                    # being reported twice alongside a direct match.
                    start=match.start(),
                    end=match.end(),
                    masked_preview=masked,
                    suggested_replacement=masked,
                    detection_tier=OCR_TIER,
                )
            )
            # One identifier per span. The length rules above are disjoint, so
            # this break is belt-and-braces rather than a tie-break.
            break

    return findings
