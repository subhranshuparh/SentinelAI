"""QR verdicts — Module 9.

A QR code is the only thing a user is routinely asked to trust that they
physically cannot read. Every other surface in SentinelAI examines something the
user could in principle check themselves; this one examines something they
cannot. That is the whole justification for the module, and it is also why the
**destination line matters more than the score**: showing "Pays INR 50,000 to
rahul-refund@ybl" is most of the protection, and the verdict is the rest.

**There is no model here, and that is deliberate.** The same argument
``services/identity/`` makes: a QR payload is a machine-readable string, and
deciding whether it is a payment request with a pre-filled amount is parsing,
not judgement. Asking a language model to read a URI would add latency, a key, a
failure mode, and an injection surface, in exchange for a worse answer.

**The one thing users have backwards.** A UPI QR code always *debits* the person
scanning it. There is no such thing as a QR that pays you. "Scan this to receive
your ₹50,000 refund" is a request for ₹50,000 *from* the victim, and it works
because the direction is invisible. Every UPI sentence this module writes leads
with the direction.

Two rules inherited from elsewhere in the project, unchanged:

* **Correlated findings combine as max plus a breadth bump, never a sum.**
  ``combine`` is imported from the phishing heuristics rather than reimplemented
  so the two modules cannot drift apart on what "three findings" is worth.
* **A signal that did not answer never votes "fine".** A URL whose site lookup
  came back ``unknown`` makes the QR verdict ``unknown`` — unless our own
  offline checks already found something, in which case the warning stands.
  Thin evidence blocks a clean bill of health; it never suppresses a warning.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal

from app.services.phishing.heuristics import SHORTENERS, Hit, analyse_content, combine
from app.services.qr.parse import ParsedPayload, format_amount, parse
from app.services.qr.psp import handles_for_brand, is_known_handle
from app.services.site.brand import BRAND_DOMAINS, host_tokens
from app.services.site.engine import SiteResult
from app.services.site.engine import evaluate as evaluate_site

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
#
# Same numbers as the phishing engine, on purpose. A user who has learned what
# "dangerous" means from an email check should not find it means something
# different when they scan a code.

#: Score at or above which the code is called dangerous. Higher = more risk.
THRESHOLD_DANGEROUS = 65
#: Score at or above which it is called suspicious.
THRESHOLD_SUSPICIOUS = 30

#: "We found nothing" is not "this is definitely safe", so a clean verdict is
#: capped below certainty here exactly as it is in Modules 2 and 3.
MAX_CONFIDENCE_WHEN_CLEAN = 0.80

#: Breadth bump for UPI findings. Lower than the phishing content group's 8:
#: UPI signals are fewer and less independent of each other — an unknown handle
#: and a brand mismatch often describe the same fake VPA — so stacking them
#: should move the number less.
UPI_BREADTH_BUMP = 6

#: Above this, a pre-filled amount stops looking like a shop counter and starts
#: looking like the advance-fee script. ₹2,000 is roughly where an unprompted
#: payment request becomes worth stopping for even if it turns out to be real.
LARGE_AMOUNT = Decimal("2000")


@dataclass(frozen=True)
class QrSignal:
    """One row of the explanation.

    Same three-value ``weight`` vocabulary as Modules 2 and 3 — ``bad`` for a
    finding, ``good`` for a check that ran and passed, ``unknown`` for one that
    could not run. The extension renders all three with one component, and a
    check that did not happen stays visibly different from one that passed.
    """

    signal: str
    detail: str
    weight: str = "bad"
    #: A short excerpt of the payload, when the row has one to quote. Always a
    #: literal substring of what was scanned.
    evidence: str | None = None


@dataclass(frozen=True)
class QrResult:
    """Everything the API returns, decided here rather than in the router."""

    kind: str
    verdict: str
    #: 0-100, **higher means more dangerous** — the same direction as the
    #: phishing risk score and the inverse of ``trust_score``. The UI says so.
    risk_score: int
    confidence: float
    summary: str
    recommendation: str
    signals: tuple[QrSignal, ...]
    #: The one line shown above the verdict: where this code actually goes.
    destination: str
    #: The site evaluation, when the payload was a link. The router persists a
    #: ``SiteCheck`` from it so a scanned QR feeds the Browsing sub-score just
    #: like a visited page. ``None`` for every other kind — a UPI QR has no
    #: domain, and inventing one to have something to store would put a
    #: fabricated row in front of the risk engine.
    site: SiteResult | None = None


# ---------------------------------------------------------------------------
# Copy, authored in Python
# ---------------------------------------------------------------------------

_SUMMARIES: dict[str, str] = {
    "dangerous": "Do not scan this QR code.",
    "suspicious": "This QR code does not look right.",
    "safe": "Nothing suspicious found in this QR code.",
    "unknown": "SentinelAI could not check where this QR code goes.",
}

#: Which advice applies depends on what the code *is*, not only on how bad it is.
#:
#: A single table keyed on the verdict alone produced sentences like "never
#: approve an amount you did not enter" underneath a Wi-Fi network, which is not
#: merely untidy — advice that does not fit the thing on screen is the fastest
#: way to teach someone that this panel is not worth reading. So the table is
#: keyed by *family* first.
#:
#: Families rather than kinds, because `tel:`, `mailto:` and a contact card all
#: need the same sentence and would otherwise be three copies of it that drift.
_KIND_FAMILY: dict[str, str] = {
    "upi": "payment",
    "url": "link",
    "wifi": "network",
}

_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "payment": {
        "dangerous": (
            "Do not scan it, and do not approve anything your UPI app shows after scanning. "
            "If someone sent you this code saying you will receive money, that is not how UPI "
            "works — scanning only ever sends money. If you have already approved a payment, "
            "call your bank now."
        ),
        "suspicious": (
            "Treat this as unverified. Ask the person to send money to you instead, or pay "
            "from your bank's own app by typing the details yourself. Never approve an amount "
            "you did not enter."
        ),
        "safe": (
            "Nothing suspicious was found, but that is not a guarantee. Before you approve "
            "anything, read the name and the amount your UPI app shows and stop if either "
            "one surprises you."
        ),
        "unknown": (
            "There was not enough here to judge. Check the payment address shown above and "
            "confirm the amount in your UPI app before approving it."
        ),
    },
    "link": {
        "dangerous": (
            "Do not open it. If the code came with a promise of a refund, a prize, or an "
            "urgent problem with your account, that promise is the scam. Reach the company "
            "through its own app, or by typing its address into your browser yourself."
        ),
        "suspicious": (
            "If you do open it, do not type a password, a card number, or an OTP into the "
            "page. Reach the company through its own app instead — a code you did not print "
            "is not a safe way to arrive at a login screen."
        ),
        "safe": (
            "Nothing suspicious was found, but that is not a guarantee. If the page asks for "
            "a password, a card number, or an OTP, stop and go to the company's own app."
        ),
        "unknown": (
            "There was not enough here to judge. Read the address shown above, and do not "
            "enter a password, a card number, or an OTP on a page you reached this way."
        ),
    },
    "network": {
        "dangerous": (
            "Do not join this network. Use your mobile data instead."
        ),
        "suspicious": (
            "If you join it, do not bank, shop, or sign in to anything while connected — use "
            "your mobile data for those. And only join from a code you got from the venue "
            "itself, not one taped up by a stranger."
        ),
        "safe": (
            "The network is encrypted, but a name proves nothing about who runs it. Only "
            "join from a code you got from the venue itself."
        ),
        "unknown": (
            "SentinelAI can read whether a network is password-protected. It cannot tell you "
            "who runs it. Only join from a code you got from the venue itself, and avoid "
            "banking while connected."
        ),
    },
    "other": {
        "dangerous": (
            "Do not act on it. Close your scanner without opening anything it offers."
        ),
        "suspicious": (
            "Read what it contains before acting on it. Do not follow a link, call a number, "
            "or send a message it suggests without first checking who sent you the code."
        ),
        "safe": (
            "Nothing suspicious was found, but read what the code contains before acting on it."
        ),
        "unknown": (
            "There was not enough here to judge. Read what is shown above before acting on it."
        ),
    },
}

#: One extra instruction for the finding that most deserves its own line. First
#: match wins, so the user gets a single clear action rather than a list.
_SPECIFIC_ACTIONS: tuple[tuple[str, str], ...] = (
    (
        "amount_on_receive_qr",
        "This code takes money from you. No QR code can put money into your account, "
        "whatever the sender told you.",
    ),
    (
        "payee_brand_mismatch",
        "The payment name uses a well-known company's name but does not pay that company. "
        "Pay through the company's own app instead.",
    ),
    (
        "dangerous_scheme",
        "This code is not a link or a payment — it is an instruction for your phone to run "
        "something. Close the scanner without opening it.",
    ),
    (
        "malformed_vpa",
        "The payment address in this code is not a valid UPI ID, so no legitimate app "
        "generated it.",
    ),
)


def _verdict_for(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "dangerous"
    if score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _recommendation_for(kind: str, verdict: str, signals: list[QrSignal]) -> str:
    """The sentence telling the user what to do.

    Unknown kinds fall to ``other`` rather than raising. A payload type nobody
    anticipated should still produce cautious, generic advice — a ``KeyError``
    here would turn a novel QR code into a 500, which reads to the user as the
    tool being broken rather than as the tool being careful.
    """
    base = _RECOMMENDATIONS[_KIND_FAMILY.get(kind, "other")][verdict]
    names = {signal.signal for signal in signals}
    for name, extra in _SPECIFIC_ACTIONS:
        if name in names:
            return f"{extra} {base}"
    return base


def _to_signals(hits: list[Hit]) -> list[QrSignal]:
    return [
        QrSignal(signal=hit.name, detail=hit.detail, weight="bad", evidence=hit.evidence)
        for hit in hits
    ]


# ---------------------------------------------------------------------------
# UPI
# ---------------------------------------------------------------------------


def _brand_in_vpa(local_part: str, handle: str) -> str | None:
    """Which brand a VPA is invoking without being entitled to, if any.

    Reuses ``site.brand``'s token rule for the same reason it exists there:
    ``amazonaws`` is not ``amazon``, and substring matching would make this the
    noisiest check in the module. A brand only counts when it is a whole token
    of the VPA's local part.

    A brand that pays through this handle is silent — ``amazon@apl`` is Amazon
    Pay and must not be flagged. A brand with no UPI presence at all
    (``netflix``, ``uidai``) is a mismatch on sight, because there is no handle
    it could legitimately be paying through.
    """
    for token in host_tokens(local_part):
        if token not in BRAND_DOMAINS:
            continue
        if handle in handles_for_brand(token):
            return None
        return token
    return None


def _brand_in_name(payee_name: str | None, handle: str) -> str | None:
    """The same check against the *displayed* name — ``pn=Amazon Refund``.

    Separate from the VPA check because it is weaker evidence and priced lower.
    A marketplace seller may legitimately trade under a brand's name while being
    paid at their own VPA, so this alone is a reason to look twice rather than a
    verdict. It is also the field the victim actually reads, which is why it
    cannot be skipped: "Amazon Refund" next to ``rahul-refund@ybl`` is the whole
    trick, and the VPA check alone is blind to it.
    """
    if not payee_name:
        return None
    for token in host_tokens(payee_name):
        if token not in BRAND_DOMAINS:
            continue
        if handle in handles_for_brand(token):
            return None
        return token
    return None


def _upi_hits(payload: ParsedPayload) -> list[Hit]:
    """Deterministic findings for a UPI payment request."""
    upi = payload.upi
    assert upi is not None  # guaranteed by kind == "upi"
    hits: list[Hit] = []

    # --- The payment address ------------------------------------------------
    #
    # Three different states, kept apart because they mean different things.
    # No ``pa`` at all is an *absence* — there is no destination to judge, so the
    # verdict becomes "unknown" rather than a score. A ``pa`` that is present but
    # not shaped like a UPI ID is a *finding*: no legitimate app emits one.
    if not upi.payee_vpa:
        hits.append(
            Hit(
                name="missing_vpa",
                penalty=0,
                detail=(
                    "This code claims to be a UPI payment but names no account to pay. "
                    "SentinelAI cannot tell you where the money would go."
                ),
            )
        )
    elif not upi.handle:
        hits.append(
            Hit(
                name="malformed_vpa",
                penalty=70,
                detail=(
                    "The payment address in this code is not a valid UPI ID. Every real "
                    "UPI ID looks like name@bank."
                ),
                evidence=upi.payee_vpa,
            )
        )
    elif not is_known_handle(upi.handle):
        hits.append(
            Hit(
                name="unknown_psp_handle",
                penalty=50,
                detail=(
                    f"SentinelAI does not recognise “@{upi.handle}” as a bank or payment "
                    "app. That does not prove it is fake — new ones do appear — but it is "
                    "worth checking before you pay."
                ),
                evidence=upi.payee_vpa,
            )
        )

    brand = _brand_in_vpa(upi.local_part, upi.handle)
    if brand:
        hits.append(
            Hit(
                name="payee_brand_mismatch",
                penalty=80,
                detail=(
                    f"The payment address uses the name “{brand}” but does not pay "
                    f"{brand}. Anyone can put a company's name in a UPI ID."
                ),
                evidence=upi.payee_vpa,
            )
        )
    else:
        # Only when the VPA itself is clean. Otherwise the same impersonation
        # would be reported twice and the breadth bump would count it as two
        # independent findings, which is exactly what ``combine`` exists to
        # prevent.
        named = _brand_in_name(upi.payee_name, upi.handle)
        if named:
            hits.append(
                Hit(
                    name="payee_name_brand_mismatch",
                    # Below the dangerous threshold on its own: this is a reason
                    # to look twice, and it becomes a verdict when something else
                    # agrees with it.
                    penalty=60,
                    detail=(
                        f"The code displays the name “{named}”, but the account it actually "
                        f"pays is {upi.payee_vpa}, which is not {named}'s. The name in a QR "
                        "code is typed by whoever made it."
                    ),
                    evidence=upi.payee_name,
                )
            )

    # --- The amount ---------------------------------------------------------
    #
    # A pre-filled amount is not fraud by itself: every shop counter QR carries
    # one. What separates the two is context that is readable from the payload —
    # a merchant category code, and the size of the ask. So the penalty is
    # graded rather than binary, and the sentence explains the direction of the
    # money either way.
    if upi.amount is not None and upi.amount > 0:
        if upi.merchant_code:
            penalty, extra = 20, (
                "It carries a shop's merchant code, so this may well be a genuine counter "
                "QR — but read the amount before you approve it."
            )
        elif upi.amount >= LARGE_AMOUNT:
            penalty, extra = 85, (
                "A large amount filled in by someone else, on a code with no shop details, "
                "is the usual shape of the “I'll send you money, just scan this” scam."
            )
        else:
            penalty, extra = 50, (
                "The amount was filled in by whoever made this code, not by you."
            )
        hits.append(
            Hit(
                name="amount_on_receive_qr",
                penalty=penalty,
                detail=(
                    f"Scanning this will take {upi.currency} {format_amount(upi.amount)} "
                    f"out of your account. A QR code can only send money, never receive it. "
                    f"{extra}"
                ),
                evidence=f"am={upi.amount}",
            )
        )
    elif upi.amount_unreadable:
        hits.append(
            Hit(
                name="unreadable_amount",
                penalty=55,
                detail=(
                    "This code specifies an amount that SentinelAI could not read. A real "
                    "payment app writes a plain number here."
                ),
            )
        )

    # --- The note -----------------------------------------------------------
    #
    # Reuses the email content heuristics rather than a second set of patterns.
    # The note is a 50-character free-text field and it is where the story goes:
    # "urgent refund", "prize claim", "KYC update".
    if upi.note:
        content = analyse_content("", upi.note)
        if content.hits:
            worst = max(content.hits, key=lambda hit: hit.penalty)
            hits.append(
                Hit(
                    name="urgent_note",
                    # Capped below the amount signal: pressure wording is a
                    # supporting finding here, not a standalone verdict, because
                    # 50 characters is very little to judge.
                    penalty=min(70, worst.penalty),
                    detail=(
                        "The message attached to this payment uses pressure or reward "
                        "wording — the sort used to stop you checking the amount."
                    ),
                    evidence=upi.note,
                )
            )

    # --- A link smuggled into a payment ------------------------------------
    if upi.embedded_url:
        hits.append(
            Hit(
                name="link_inside_payment",
                penalty=60,
                detail=(
                    "This payment code also carries a web link. A genuine payment does not "
                    "need to send you to a website."
                ),
                evidence=upi.embedded_url,
            )
        )

    return hits


def _upi_result(payload: ParsedPayload) -> QrResult:
    upi = payload.upi
    assert upi is not None
    hits = _upi_hits(payload)
    score = combine(hits, UPI_BREADTH_BUMP)

    signals = _to_signals(hits)
    names = {hit.name for hit in hits}

    # ``missing_vpa`` carries no penalty and is not a finding — it is a stated
    # absence, so it must not be rendered as a red row alongside real ones.
    if "missing_vpa" in names:
        signals = [
            QrSignal(signal=s.signal, detail=s.detail, weight="unknown", evidence=s.evidence)
            if s.signal == "missing_vpa"
            else s
            for s in signals
        ]

    # Rows for the checks that ran and passed. A user who only sees red rows has
    # no way to know how much of the code was actually examined.
    if upi.handle and "unknown_psp_handle" not in names:
        signals.append(
            QrSignal(
                signal="known_psp_handle",
                detail=f"“@{upi.handle}” is a bank or payment app SentinelAI recognises.",
                weight="good",
            )
        )
    if upi.amount is None and not upi.amount_unreadable:
        signals.append(
            QrSignal(
                signal="no_prefilled_amount",
                detail="No amount is filled in, so you will type it yourself.",
                weight="good",
            )
        )
    if not upi.note:
        signals.append(
            QrSignal(
                signal="no_note",
                detail="The code carries no message, so there was no wording to check.",
                weight="good",
            )
        )

    # The payee name is attacker-controlled and verified by nobody. Saying so is
    # not a finding — it is a permanent property of the format that users do not
    # know, and it is why "Verified Merchant" in a scanner app means nothing.
    signals.append(
        QrSignal(
            signal="payee_name_unverified",
            detail=(
                "The name shown by your UPI app comes from your bank, not from this code — "
                "but the name written *inside* the code is chosen by whoever made it. "
                "Trust the amount and the UPI ID, not the name."
            ),
            weight="unknown",
        )
    )

    # A code that names no payee has no destination to judge, so the honest
    # answer is "unknown" no matter what else was found in it. A code that names
    # a *malformed* payee is judged normally — that is a finding, not a gap.
    verdict = "unknown" if "missing_vpa" in names else _verdict_for(score)

    confidence = 0.90 if score else 0.75
    if verdict == "safe":
        confidence = min(MAX_CONFIDENCE_WHEN_CLEAN, confidence)
    if verdict == "unknown":
        confidence = 0.40

    return QrResult(
        kind="upi",
        verdict=verdict,
        risk_score=score,
        confidence=confidence,
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for("upi", verdict, signals),
        signals=tuple(signals),
        destination=payload.destination,
    )


# ---------------------------------------------------------------------------
# URL
# ---------------------------------------------------------------------------

#: Link shapes worth flagging on a QR specifically. Both are ordinary on the
#: web and abnormal on a printed code: a shortener defeats the only inspection
#: the user could have done, and a bare IP has no registration to check.
_SHORTENER_PENALTY = 55
_RAW_IP_PENALTY = 70


def _url_hits(url: str, site: SiteResult) -> list[Hit]:
    from ipaddress import ip_address
    from urllib.parse import urlsplit

    hits: list[Hit] = []
    host = (urlsplit(url).hostname or "").lower()

    if site.domain in SHORTENERS:
        hits.append(
            Hit(
                name="shortened_link",
                penalty=_SHORTENER_PENALTY,
                detail=(
                    f"The code hides its real destination behind the shortener "
                    f"“{site.domain}”. A printed code that will not show you where it goes "
                    "is worth refusing on that alone."
                ),
                evidence=url[:120],
            )
        )

    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        hits.append(
            Hit(
                name="raw_ip_link",
                penalty=_RAW_IP_PENALTY,
                detail=(
                    "The code points at a bare numeric address rather than a website name. "
                    "There is no registration behind it to check."
                ),
                evidence=host,
            )
        )

    return hits


def _url_result(payload: ParsedPayload) -> QrResult:
    """Delegate to the site engine, then apply the QR-specific checks on top."""
    url = payload.url or ""
    site = evaluate_site(url)

    # The site engine scores trust (100 = healthy); this module scores risk
    # (100 = dangerous). One subtraction, stated here rather than assumed.
    site_risk = 100 - site.trust_score
    local = _url_hits(url, site)
    local_score = combine(local, 5)

    signals = _to_signals(local)
    signals += [
        QrSignal(signal=reason.signal, detail=reason.detail, weight=reason.weight)
        for reason in site.reasons
    ]

    if site.verdict == "unknown":
        # The lookup could not answer. Our own offline checks still can, and a
        # warning they justify is not withdrawn because a second opinion was
        # unavailable — but the reverse does not hold: an unanswered lookup can
        # never be upgraded to "safe".
        score = local_score
        verdict = "unknown" if local_score < THRESHOLD_DANGEROUS else "dangerous"
        confidence = max(0.35, site.confidence)
    else:
        score = max(site_risk, local_score)
        verdict = _verdict_for(score)
        confidence = site.confidence
        if verdict == "safe":
            confidence = min(MAX_CONFIDENCE_WHEN_CLEAN, confidence)

    return QrResult(
        kind="url",
        verdict=verdict,
        risk_score=score,
        confidence=round(confidence, 2),
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for("url", verdict, signals),
        signals=tuple(signals),
        destination=payload.destination,
        site=site,
    )


# ---------------------------------------------------------------------------
# Everything else
# ---------------------------------------------------------------------------


def _dangerous_scheme_result(payload: ParsedPayload) -> QrResult:
    """A payload whose scheme is an instruction rather than a destination."""
    scheme = payload.scheme or "unknown"
    return QrResult(
        kind=payload.kind,
        verdict="dangerous",
        risk_score=90,
        confidence=0.95,
        summary=_SUMMARIES["dangerous"],
        recommendation=_recommendation_for(
            payload.kind, "dangerous", [QrSignal(signal="dangerous_scheme", detail="")]
        ),
        signals=(
            QrSignal(
                signal="dangerous_scheme",
                detail=(
                    f"This code contains a “{scheme}:” instruction rather than a web "
                    "address or a payment. Legitimate QR codes do not use it, and opening "
                    "one can run code on your phone."
                ),
                evidence=payload.raw[:120],
            ),
        ),
        destination=payload.destination,
    )


def _wifi_result(payload: ParsedPayload) -> QrResult:
    signals: list[QrSignal] = []
    score = 0

    if payload.wifi_open is True:
        score = 45
        signals.append(
            QrSignal(
                signal="open_wifi",
                detail=(
                    "This network has no password, so anything you send on it can be read "
                    "by anyone nearby. Do not use it for banking or shopping."
                ),
                evidence=payload.wifi_ssid,
            )
        )
    elif payload.wifi_open is False:
        signals.append(
            QrSignal(
                signal="encrypted_wifi",
                detail="The network is password-protected.",
                weight="good",
            )
        )
    else:
        signals.append(
            QrSignal(
                signal="wifi_encryption_unknown",
                detail="SentinelAI could not tell whether this network is password-protected.",
                weight="unknown",
            )
        )

    # The name is not the network. Anyone can broadcast "Airport_Free_WiFi".
    signals.append(
        QrSignal(
            signal="wifi_name_unverified",
            detail=(
                "A network name proves nothing about who runs it. Only join networks from a "
                "code you got from the venue itself."
            ),
            weight="unknown",
        )
    )

    verdict = _verdict_for(score) if payload.wifi_open is not None else "unknown"
    if verdict == "safe":
        verdict = "unknown"  # We checked encryption, not the operator. Say so.
    return QrResult(
        kind="wifi",
        verdict=verdict,
        risk_score=score,
        confidence=0.70 if payload.wifi_open is not None else 0.40,
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for("wifi", verdict, signals),
        signals=tuple(signals),
        destination=payload.destination,
    )


def _crypto_result(payload: ParsedPayload) -> QrResult:
    """A cryptocurrency address. Irreversible by design, so always flagged."""
    return QrResult(
        kind="crypto",
        verdict="suspicious",
        risk_score=55,
        confidence=0.75,
        summary=_SUMMARIES["suspicious"],
        # Written out in full rather than assembled from the payment family.
        # That family's advice — "ask them to send money to you instead", "check
        # the amount in your UPI app" — assumes a rail with a counterparty and a
        # bank behind it. Crypto has neither, which is the entire finding, so
        # borrowing sentences that imply otherwise would undercut it.
        recommendation=(
            "Cryptocurrency transfers cannot be reversed and cannot be traced back to a "
            "person. No refund, tax office, delivery company, or support desk is ever paid "
            "this way. If someone has told you to pay like this, that instruction is the "
            "scam. Do not scan it."
        ),
        signals=(
            QrSignal(
                signal="crypto_payment",
                detail=(
                    "This code sends cryptocurrency. Once sent, it cannot be reversed and no "
                    "bank can help you recover it."
                ),
                evidence=payload.raw[:120],
            ),
        ),
        destination=payload.destination,
    )


def _plain_result(payload: ParsedPayload) -> QrResult:
    """Contacts, phone numbers, messages, plain text.

    None of these is judgeable on its own, so the verdict is ``unknown`` and the
    sentence says which question was not answered. The exception is an embedded
    link: a "contact card" carrying a URL is still a URL, and it gets the full
    site check.
    """
    signals: list[QrSignal] = []
    site: SiteResult | None = None
    score = 0
    confidence = 0.40

    if payload.embedded_urls:
        first = payload.embedded_urls[0]
        site = evaluate_site(first)
        local = _url_hits(first, site)
        # Same one-sided rule as the URL path: the offline checks may raise the
        # score when the lookup could not answer, and never lower it when it did.
        score = combine(local, 5)
        if site.verdict != "unknown":
            score = max(score, 100 - site.trust_score)
            confidence = site.confidence
        signals += _to_signals(local)
        signals += [
            QrSignal(signal=reason.signal, detail=reason.detail, weight=reason.weight)
            for reason in site.reasons
        ]
        signals.insert(
            0,
            QrSignal(
                signal="link_in_payload",
                detail=(
                    f"This code is not a plain link, but it contains one: {site.domain or first}."
                ),
                weight="bad" if score >= THRESHOLD_SUSPICIOUS else "unknown",
                evidence=first[:120],
            ),
        )

    signals.append(
        QrSignal(
            signal="not_a_destination",
            detail=(
                "This code does not open a website or make a payment, so there is nothing "
                "for SentinelAI to look up. Read what it contains before acting on it."
            ),
            weight="unknown",
        )
    )

    verdict = _verdict_for(score) if score else "unknown"
    if verdict == "safe":
        # A contact card with a clean link is still a contact card. Nothing was
        # checked about what the code *is*, only about one string inside it, and
        # calling that "safe" would claim more than was measured.
        verdict = "unknown"
    # Capped below the site engine's own figure even when that engine was fully
    # confident. It answered a question about one string inside the payload, not
    # about the payload — so its certainty is not this module's certainty.
    confidence = min(confidence, 0.45 if verdict == "unknown" else 0.85)
    return QrResult(
        kind=payload.kind,
        verdict=verdict,
        risk_score=score,
        confidence=round(confidence, 2),
        summary=_SUMMARIES[verdict],
        recommendation=_recommendation_for(payload.kind, verdict, signals),
        signals=tuple(signals),
        destination=payload.destination,
        site=site,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

#: Findings first, then what could not be checked, then what passed. A user
#: reads the top of a list, and the top of this one must be what is wrong.
_WEIGHT_ORDER = {"bad": 0, "unknown": 1, "good": 2}


def analyse(payload: str) -> QrResult:
    """Judge one decoded QR payload. Never raises.

    Deterministic and offline apart from the site lookup, which itself never
    raises and degrades to ``unknown``. Callers get a result in every case,
    including the ones where the honest answer is "we do not know".
    """
    parsed = parse(payload)

    if parsed.dangerous_scheme:
        result = _dangerous_scheme_result(parsed)
    elif parsed.kind == "upi":
        result = _upi_result(parsed)
    elif parsed.kind == "url":
        result = _url_result(parsed)
    elif parsed.kind == "wifi":
        result = _wifi_result(parsed)
    elif parsed.kind == "crypto":
        result = _crypto_result(parsed)
    else:
        result = _plain_result(parsed)

    # Sorted here rather than in each branch so no future kind can forget to.
    # ``sorted`` is stable, so the order findings were discovered in survives.
    return replace(
        result,
        signals=tuple(sorted(result.signals, key=lambda s: _WEIGHT_ORDER[s.weight])),
    )
