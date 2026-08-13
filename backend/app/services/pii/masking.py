"""Format-preserving redaction.

Two rules drive every function here:

1. **Keep the shape.** ``XXXX XXXX 9013`` still reads as an Aadhaar number, so
   the user can see *what* was masked and confirm the tool understood them. A
   flat ``[REDACTED]`` destroys that and makes people distrust the suggestion.
2. **Keep the tail, never the head.** The last 4 digits let a human confirm
   "yes, that's my card" without the value being reusable. The leading digits
   are the identifying ones — an Aadhaar prefix encodes issuing details, and a
   card IIN identifies the issuer.

These outputs are also what gets persisted to ``pii_events.masked_preview``, so
anything this module leaks, the database keeps. Reveal counts stay small.
"""

from __future__ import annotations

import re

# Characters preserved verbatim so the mask keeps the original's visual shape.
_SEPARATORS = frozenset(" -.")


def mask_keep_last(value: str, reveal: int = 4, mask_char: str = "X") -> str:
    """Mask all alphanumerics except the final ``reveal`` of them.

    Separators are preserved in place, which is what keeps ``2234 5678 9013``
    looking like ``XXXX XXXX 9013`` rather than ``XXXXXXXX9013``.

    >>> mask_keep_last("2234 5678 9013")
    'XXXX XXXX 9013'
    """
    alnum_positions = [i for i, ch in enumerate(value) if ch.isalnum()]
    # Never reveal more than half: on a short value, "keep the last 4" would
    # expose most of it. Better to over-mask than to under-mask.
    reveal = min(reveal, len(alnum_positions) // 2)
    keep_from = len(alnum_positions) - reveal

    chars = list(value)
    for order, position in enumerate(alnum_positions):
        if order < keep_from:
            chars[position] = mask_char
    return "".join(chars)


def mask_email(value: str) -> str:
    """Mask the local part, keep the domain.

    The domain is rarely the sensitive half and keeping it makes the warning
    legible ("that's my work address"), while the local part is the identifier.

    >>> mask_email("priya.sharma@example.com")
    'p•••••••••••@example.com'
    """
    match = re.match(r"^([^@]+)@(.+)$", value)
    if not match:
        return mask_keep_last(value, reveal=0)
    local, domain = match.groups()
    if len(local) <= 1:
        return f"{'•' * len(local)}@{domain}"
    return f"{local[0]}{'•' * (len(local) - 1)}@{domain}"


def mask_secret(value: str) -> str:
    """Mask a credential end-to-end, keeping only a short identifying prefix.

    API keys, JWTs and passwords are masked far more aggressively than PII:
    there is no "confirm it's mine" benefit that justifies revealing a tail, and
    a trailing fragment of a signing key is still material. Prefix only, and only
    because ``AKIA…`` tells the user *which kind* of secret leaked.
    """
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}{'•' * 12}"


def mask_generic(value: str) -> str:
    """Fallback for free-text spans (addresses, names) where shape carries no meaning."""
    return "•" * min(len(value), 12)


# Dispatch table. Keys match ``Detector.name`` in detectors.py.
_STRATEGIES = {
    "email": mask_email,
    "api_key": mask_secret,
    "jwt": mask_secret,
    "password": mask_secret,
    "upi_id": mask_email,  # Same shape: handle@provider.
}


def mask_for(pii_type: str, value: str) -> str:
    """Return the masked form appropriate to ``pii_type``.

    Unknown types fall through to ``mask_keep_last``, which is the conservative
    choice — a new detector added at hour 18 gets sane masking without touching
    this file.
    """
    strategy = _STRATEGIES.get(pii_type)
    if strategy is not None:
        return strategy(value)
    if value.isalpha():
        return mask_generic(value)
    return mask_keep_last(value)
