"""What a QR code actually says — parsing only, no judgement.

A QR code is a string. Everything a human cannot see about it — that it is a
payment request rather than a link, that the payment has an amount already
filled in, that the "link" is a ``javascript:`` URL — is plainly readable in
that string. This module reads it. ``engine`` decides what it means.

The split matters for one reason beyond tidiness: **the parse is the security
boundary**. A QR payload is attacker-authored and arrives verbatim from a photo
on a web page. Everything downstream — the sentence in the toast, the URL handed
to Safe Browsing, the row written to ``site_checks`` — depends on this file
having correctly decided what kind of thing it is holding. So the classifier is
allowlist-shaped: a payload is a URL only if it starts with ``http://`` or
``https://``, and any other scheme is called out by name rather than quietly
treated as text.

The formats handled are the ones QR codes are actually used for in India:

* ``upi://pay?pa=…&pn=…&am=…&tn=…`` — the NPCI UPI deep link. This is the one
  the whole module exists for.
* ``http(s)://…`` — a plain link.
* ``WIFI:T:WPA;S:ssid;P:pass;;`` — network join.
* ``BEGIN:VCARD…`` / ``MECARD:…`` — contact cards.
* ``tel:`` / ``smsto:`` / ``mailto:`` / ``geo:`` — the small schemes.
* anything else — ``text``.

Nothing here raises. A payload that cannot be understood becomes
``kind="text"``, which the engine reports as *unknown* — never as safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qsl, unquote, urlsplit

#: QR's own alphanumeric capacity ceiling at version 40. A payload longer than
#: this did not come out of a scannable code, so the API rejects it rather than
#: spending work on it. Defined here because it is a fact about QR, not about
#: our schema.
MAX_PAYLOAD_CHARS = 4_500

#: Displayed strings are cut here. A VPA is at most 255 characters by NPCI's
#: spec, but a *hostile* one is whatever fits in the QR, and the toast has one
#: line to work with.
MAX_FIELD_CHARS = 120

#: ₹1 crore — comfortably above every published UPI per-transaction limit, which
#: top out at ₹5 lakh for the highest categories. An ``am`` beyond this did not
#: come from a payment app.
#:
#: This is a bound, not a nicety. ``Decimal`` will happily construct
#: ``1E+999999`` from a QR payload, and formatting that as an integer raises
#: before it ever reaches a screen. An amount this module cannot state is an
#: amount it reports as unreadable, which is already a distinct, honest answer.
MAX_UPI_AMOUNT = Decimal("10000000")

# ---------------------------------------------------------------------------
# Schemes
# ---------------------------------------------------------------------------

#: Schemes a QR code has no legitimate reason to carry and that do something
#: dangerous when a scanner app hands them to the OS or a webview. Listed
#: explicitly so ``engine`` can name the scheme in the warning instead of saying
#: "unsupported".
DANGEROUS_SCHEMES = frozenset(
    {
        "javascript",  # executes in whatever context opens it
        "data",        # inline payload, commonly a base64 HTML phishing page
        "file",        # local filesystem
        "blob",
        "vbscript",
        "intent",      # Android: launches an arbitrary app with arbitrary extras
        "market",      # jumps straight to a Play Store install page
        "content",
    }
)

#: Recognised, benign-by-shape schemes that are not links and not payments.
_SIMPLE_SCHEMES = {
    "tel": "tel",
    "sms": "sms",
    "smsto": "sms",
    "mailto": "mailto",
    "geo": "geo",
    "bitcoin": "crypto",
    "ethereum": "crypto",
    "litecoin": "crypto",
}

#: UPI deep links. ``pay`` is the ordinary one; the others exist in the spec and
#: are treated identically, because the direction of money is the same for all
#: of them and that is the only thing this module cares about.
_UPI_SCHEMES = frozenset({"upi", "upiqr"})

_SCHEME = re.compile(r"^([a-z][a-z0-9+.\-]*):", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpiRequest:
    """A parsed ``upi://`` deep link.

    Field names follow the NPCI parameter names so the mapping stays checkable
    against the spec, with the English meaning in the comment.
    """

    #: ``pa`` — the Virtual Payment Address money would go *to*.
    payee_vpa: str
    #: The part of the VPA after ``@`` — the payment service provider handle.
    #: Empty when the VPA is malformed, which is itself a finding.
    handle: str
    #: The part before ``@``.
    local_part: str
    #: ``pn`` — the payee name the QR *claims*. Attacker-controlled; it is a
    #: label typed by whoever made the code, verified by nobody.
    payee_name: str | None = None
    #: ``am`` — the amount, already filled in. ``None`` when the QR leaves it to
    #: the payer. Parsed as ``Decimal`` because this is money.
    amount: Decimal | None = None
    #: ``cu`` — currency code, ``INR`` in practice.
    currency: str = "INR"
    #: ``tn`` — the transaction note. Free text, and the field scammers use to
    #: explain why you are "receiving" ₹50,000.
    note: str | None = None
    #: ``mc`` — merchant category code. Present on genuine merchant QRs.
    merchant_code: str | None = None
    #: ``tr`` — transaction reference.
    txn_ref: str | None = None
    #: ``url`` — an optional link the spec allows alongside the payment. A place
    #: to smuggle a destination past someone who is only looking at the amount.
    embedded_url: str | None = None
    #: True when ``am`` was present but could not be read as a number.
    amount_unreadable: bool = False


@dataclass(frozen=True)
class ParsedPayload:
    """One decoded QR payload, classified.

    ``destination`` is the single line the toast shows above the verdict. It is
    the whole user-facing point of the feature: a QR code is unreadable to a
    human, and showing where it actually goes is most of the protection.
    """

    kind: str
    #: The payload as decoded, truncated for display only. Never re-emitted as
    #: HTML anywhere; the extension sets it with ``textContent``.
    raw: str
    #: One line: the host, or the VPA and amount, or the SSID.
    destination: str
    #: Set for ``kind == "url"``. Always ``http``/``https``.
    url: str | None = None
    #: Set for ``kind == "upi"``.
    upi: UpiRequest | None = None
    #: The URI scheme when the payload had one, lowercased. ``None`` for bare
    #: text. Kept even for text so the engine can name a rejected scheme.
    scheme: str | None = None
    #: True when ``scheme`` is in :data:`DANGEROUS_SCHEMES`.
    dangerous_scheme: bool = False
    #: ``http(s)`` links found *inside* a text/vcard/sms payload. A message that
    #: reads "you have won" and carries a link is still a link to check.
    embedded_urls: tuple[str, ...] = field(default_factory=tuple)
    #: For ``kind == "wifi"``: the network name and whether it is unencrypted.
    wifi_ssid: str | None = None
    wifi_open: bool | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clip(value: str | None, limit: int = MAX_FIELD_CHARS) -> str | None:
    """Trim, bound, and collapse whitespace. ``None`` and blank both give ``None``.

    Newlines are collapsed rather than preserved: every consumer of these
    strings renders them on one line, and a payload containing ``\\n`` is a
    cheap way to push the real destination out of a toast.
    """
    if value is None:
        return None
    cleaned = " ".join(value.split())
    if not cleaned:
        return None
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


#: Bare ``http(s)`` URLs inside a longer string. Same shape as the phishing
#: module's, kept local rather than imported so a change there for email prose
#: cannot silently retune QR parsing.
_EMBEDDED_URL = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)


def _embedded(text: str) -> tuple[str, ...]:
    """Links inside a non-link payload, de-duplicated, order preserved."""
    seen: list[str] = []
    for match in _EMBEDDED_URL.findall(text):
        if match not in seen:
            seen.append(match)
    return tuple(seen[:5])


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# UPI
# ---------------------------------------------------------------------------


def _parse_amount(raw: str | None) -> tuple[Decimal | None, bool]:
    """Read ``am``. Returns ``(amount, unreadable)``.

    The two failure modes are kept apart on purpose. ``(None, False)`` means the
    QR genuinely left the amount open — the payer types it. ``(None, True)``
    means the QR *did* specify one and we could not read it, which is a reason
    to distrust the code, not a reason to describe it as open-ended. That is the
    project's missing-signal rule applied to a single field.
    """
    if raw is None:
        return None, False
    text = raw.strip().replace(",", "")
    if not text:
        return None, False
    try:
        amount = Decimal(text)
    except InvalidOperation:
        return None, True
    if amount.is_nan() or amount.is_infinite() or amount < 0 or amount > MAX_UPI_AMOUNT:
        return None, True
    return amount, False


def _split_vpa(vpa: str) -> tuple[str, str]:
    """``name@bank`` -> ``("name", "bank")``. Missing ``@`` gives an empty handle.

    Split on the *last* ``@``: ``a@b@ybl`` is a malformed VPA, and reading its
    handle as ``b@ybl`` would let an attacker put a legitimate-looking handle in
    the middle where a human eye stops reading.
    """
    if "@" not in vpa:
        return vpa, ""
    local, _, handle = vpa.rpartition("@")
    return local, handle.lower()


def format_amount(amount: Decimal) -> str:
    """Money as a person writes it: ``50000`` -> ``50,000``, ``99.5`` -> ``99.50``.

    Whole amounts lose the decimals entirely. "₹50,000.00" and "₹50,000" carry
    the same information, and the shorter one is the one a hurried reader
    actually takes in.
    """
    if amount == amount.to_integral_value():
        return f"{int(amount):,}"
    return f"{amount.quantize(Decimal('0.01')):,f}"


def _upi_destination(upi: UpiRequest) -> str:
    """The one line shown above the verdict.

    Always leads with the direction of money, because that is the fact the
    victim of this scam has wrong. A QR code can only ever *send*.
    """
    who = upi.payee_vpa or "an unnamed account"
    if upi.amount is not None:
        return f"Pays {upi.currency} {format_amount(upi.amount)} to {who}"
    if upi.amount_unreadable:
        return f"Pays an unreadable amount to {who}"
    return f"Pays {who} — the amount is not filled in"


def _parse_upi(payload: str, scheme: str) -> ParsedPayload:
    """Parse a ``upi://`` deep link into a payment request."""
    # ``upi://pay?…`` parses with an empty netloc on some inputs and ``pay`` as
    # the host on others depending on slashes, so the query is taken from the
    # first ``?`` rather than from urlsplit's opinion about authority.
    _, _, after = payload.partition("?")
    params = {key.lower(): value for key, value in parse_qsl(after, keep_blank_values=True)}

    vpa = _clip(unquote(params.get("pa", "")), 255) or ""
    local_part, handle = _split_vpa(vpa)
    amount, unreadable = _parse_amount(params.get("am"))

    upi = UpiRequest(
        payee_vpa=vpa,
        handle=handle,
        local_part=local_part,
        payee_name=_clip(unquote(params.get("pn", ""))),
        amount=amount,
        currency=(_clip(params.get("cu"), 8) or "INR").upper(),
        note=_clip(unquote(params.get("tn", "")), 300),
        merchant_code=_clip(params.get("mc"), 16),
        txn_ref=_clip(params.get("tr"), 64),
        embedded_url=_clip(unquote(params.get("url", "")), 300),
        amount_unreadable=unreadable,
    )

    return ParsedPayload(
        kind="upi",
        raw=_clip(payload, 300) or "",
        destination=_upi_destination(upi),
        upi=upi,
        scheme=scheme,
    )


# ---------------------------------------------------------------------------
# Wi-Fi
# ---------------------------------------------------------------------------

_WIFI_FIELD = re.compile(r"(?<!\\)([TSPH]):((?:\\.|[^;])*)", re.IGNORECASE)


def _parse_wifi(payload: str) -> ParsedPayload:
    """``WIFI:T:WPA;S:MyNet;P:secret;;`` -> SSID plus whether it is encrypted."""
    body = payload[5:]
    fields = {key.upper(): value for key, value in _WIFI_FIELD.findall(body)}
    ssid = _clip(fields.get("S", "").replace("\\;", ";").replace("\\\\", "\\"), 64)
    auth = (fields.get("T") or "").strip().lower()
    # Absent ``T`` means the network is open under the spec's default, but an
    # absent field is also just an absent field. Only the explicit "nopass" and
    # the explicit encryption types are treated as answers; anything else is
    # ``None`` and the engine says the encryption could not be determined.
    if auth in {"nopass", ""}:
        open_network: bool | None = auth == "nopass"
    elif auth in {"wpa", "wpa2", "wpa3", "wep", "sae", "wpa2-eap", "wpa/wpa2"}:
        open_network = False
    else:
        open_network = None

    return ParsedPayload(
        kind="wifi",
        raw=_clip(payload, 300) or "",
        destination=f"Joins the Wi-Fi network “{ssid}”" if ssid else "Joins a Wi-Fi network",
        scheme="wifi",
        wifi_ssid=ssid,
        wifi_open=open_network,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse(payload: str) -> ParsedPayload:
    """Classify one decoded QR payload. Never raises.

    ``payload`` is the raw string from the decoder. It is trusted to be a
    string and nothing else.
    """
    text = (payload or "").strip()
    if not text:
        return ParsedPayload(
            kind="text",
            raw="",
            destination="This QR code contained nothing readable.",
        )

    match = _SCHEME.match(text)
    scheme = match.group(1).lower() if match else None

    if scheme in DANGEROUS_SCHEMES:
        # Deliberately not classified as a URL. Handing a ``javascript:`` string
        # to the site engine would send it to Safe Browsing and get back a
        # meaningless "not listed", which reads as reassurance.
        return ParsedPayload(
            kind="text",
            raw=_clip(text, 300) or "",
            destination=f"Runs a “{scheme}:” instruction rather than opening a web page",
            scheme=scheme,
            dangerous_scheme=True,
        )

    if scheme in _UPI_SCHEMES:
        return _parse_upi(text, scheme or "upi")

    if scheme in {"http", "https"}:
        host = _host_of(text)
        return ParsedPayload(
            kind="url",
            raw=_clip(text, 300) or "",
            destination=f"Opens {host}" if host else "Opens a web address that could not be read",
            url=text,
            scheme=scheme,
        )

    if text.upper().startswith("WIFI:"):
        return _parse_wifi(text)

    if text.upper().startswith(("BEGIN:VCARD", "MECARD:")):
        return ParsedPayload(
            kind="vcard",
            raw=_clip(text, 300) or "",
            destination="Adds a contact to your phone",
            scheme="vcard",
            embedded_urls=_embedded(text),
        )

    if scheme in _SIMPLE_SCHEMES:
        kind = _SIMPLE_SCHEMES[scheme]
        target = _clip(text[len(scheme) + 1 :].lstrip("/"), 80) or ""
        labels = {
            "tel": f"Calls {target}",
            "sms": f"Sends a text message to {target}",
            "mailto": f"Writes an email to {target}",
            "geo": "Opens a map location",
            "crypto": f"Sends cryptocurrency to {target}",
        }
        return ParsedPayload(
            kind=kind,
            raw=_clip(text, 300) or "",
            destination=labels[kind],
            scheme=scheme,
            embedded_urls=_embedded(text),
        )

    return ParsedPayload(
        kind="text",
        raw=_clip(text, 300) or "",
        destination="Shows a plain text message",
        scheme=scheme,
        embedded_urls=_embedded(text),
    )
