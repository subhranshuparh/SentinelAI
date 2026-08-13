"""Brand-impersonation detection. Offline, instant, no key, no quota.

The most valuable of the three site signals, for an unglamorous reason: it is
the only one that cannot be unavailable. Safe Browsing needs a key and a
network; RDAP throttles and 404s on half the world's ccTLDs. This is string
comparison, so it works on hotel wifi and it works after the free tier runs out.

It also catches the newest attacks first. A domain registered an hour ago is not
on any blocklist yet, but it still has to *look* like the brand it is
impersonating — that is the whole point of the attack, and it is exactly what
this module reads.

**The false-positive rule that shapes everything here:** ``amazonaws.com``
contains the string "amazon". So does ``amazonia-travel.com``. Matching
substrings would make this the noisiest detector in the project, so matching is
done on *tokens* — the hostname split on dots and hyphens — and a brand only
counts when it is a whole token. ``amazonaws`` is one token and is not
``amazon``, so it is silent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Registrable domain
# ---------------------------------------------------------------------------
#
# A trimmed public-suffix list rather than the real one. The full PSL is ~9,000
# lines and a dependency; this covers the suffixes an Indian user's browsing
# actually touches. The failure mode of a miss is graceful — "co.uk" treated as
# the registrable domain makes the check stricter, never wrong-in-the-dangerous-
# direction, because it can only cause a legitimate domain to look unfamiliar,
# and legitimacy is decided by the explicit allowlist below.

_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in", "firm.in",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "co.kr", "co.nz", "co.za", "co.th", "co.id",
        "com.br", "com.mx", "com.sg", "com.tr", "com.cn", "com.my", "com.ph", "com.hk",
    }
)


def registrable_domain(hostname: str) -> str:
    """Reduce a hostname to the part someone actually registered.

    ``login.secure.amazon-verify.co.in`` -> ``amazon-verify.co.in``. This is the
    unit that matters: subdomains are free to whoever owns the registration, so
    ``amazon.attacker.com`` is an *attacker* domain and must be judged as one.
    """
    host = hostname.strip().lower().rstrip(".").split(":")[0]
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# The brand table
# ---------------------------------------------------------------------------
#
# Weighted toward what this product's users actually get phished for: Indian
# banking, government identity portals, payments, delivery, and the global
# accounts everyone has. Each brand maps to *every* domain it legitimately
# operates, because a missing entry here is a false positive on a real site.

BRAND_DOMAINS: dict[str, frozenset[str]] = {
    # --- Indian banking & government ---------------------------------------
    "sbi": frozenset({"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "statebank.in", "sbicard.com"}),
    "hdfc": frozenset({"hdfcbank.com", "hdfc.com", "hdfcsec.com"}),
    "icici": frozenset({"icicibank.com", "icicidirect.com", "icicilombard.com"}),
    "axisbank": frozenset({"axisbank.com", "axisbank.co.in"}),
    "kotak": frozenset({"kotak.com", "kotaksecurities.com"}),
    "pnb": frozenset({"pnbindia.in", "pnbibanking.in"}),
    "uidai": frozenset({"uidai.gov.in"}),
    "incometax": frozenset({"incometax.gov.in", "incometaxindia.gov.in"}),
    "irctc": frozenset({"irctc.co.in", "irctc.com"}),
    "epfindia": frozenset({"epfindia.gov.in"}),
    # --- Payments -----------------------------------------------------------
    "paytm": frozenset({"paytm.com", "paytmbank.com", "paytmmall.com"}),
    "phonepe": frozenset({"phonepe.com"}),
    "razorpay": frozenset({"razorpay.com"}),
    "paypal": frozenset({"paypal.com", "paypal.me", "paypalobjects.com"}),
    # --- Shopping & delivery ------------------------------------------------
    "amazon": frozenset({"amazon.com", "amazon.in", "amazon.co.uk", "amazon.jobs", "amazon.de"}),
    "flipkart": frozenset({"flipkart.com"}),
    "myntra": frozenset({"myntra.com"}),
    "swiggy": frozenset({"swiggy.com", "swiggy.in"}),
    "zomato": frozenset({"zomato.com"}),
    "bluedart": frozenset({"bluedart.com"}),
    "indiapost": frozenset({"indiapost.gov.in"}),
    "fedex": frozenset({"fedex.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
    # --- Global accounts ----------------------------------------------------
    "google": frozenset({"google.com", "google.co.in", "googleapis.com", "gstatic.com", "goo.gl"}),
    "gmail": frozenset({"gmail.com", "google.com"}),
    "youtube": frozenset({"youtube.com", "youtu.be"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "office.com", "microsoftonline.com"}),
    "outlook": frozenset({"outlook.com", "live.com", "microsoft.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "fb.com", "fbcdn.net"}),
    "instagram": frozenset({"instagram.com", "cdninstagram.com"}),
    "whatsapp": frozenset({"whatsapp.com", "whatsapp.net", "wa.me"}),
    "linkedin": frozenset({"linkedin.com", "licdn.com"}),
    "telegram": frozenset({"telegram.org", "t.me"}),
}

#: Words that turn "unfamiliar" into "actively pretending". No legitimate brand
#: registers `<brand>-verify-account.xyz`; the presence of one of these next to a
#: brand token is close to a confession.
LURE_TOKENS = frozenset(
    {
        "login", "signin", "log", "verify", "verification", "secure", "security",
        "update", "confirm", "account", "auth", "recovery", "recover", "unlock",
        "support", "help", "alert", "suspended", "billing", "payment", "refund",
        "kyc", "otp", "reward", "prize", "offer", "win", "gift", "claim", "bonus",
    }
)

#: Brand names that are also ordinary English words. Token matching is not
#: enough for these: ``smart-apple-orchard.com`` is a whole token "apple" on a
#: domain Apple does not own, and flagging it would be the same class of mistake
#: as matching "amazon" inside "amazonaws".
#:
#: The fix is the project's standard third technique — require corroboration.
#: An ambiguous brand only counts when something else in the hostname agrees: a
#: lure word, or a lookalike spelling. ``apple-id-verify.xyz`` still fires;
#: an orchard does not. This is why the table says ``axisbank`` and not ``axis``.
_AMBIGUOUS_BRANDS = frozenset({"apple"})

#: Digit- and letter-shape substitutions used to build lookalike domains.
#: Applied only when comparing against the brand table, never to real text.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def host_tokens(hostname: str) -> list[str]:
    """Split a hostname into whole tokens on dots, hyphens, and underscores.

    Public because Module 9 runs the same token rule over the local part of a
    UPI address: ``amazon-refund@ybl`` has to be read the same way
    ``amazon-refund.xyz`` is, or the two checks disagree about what counts as a
    brand name.
    """
    return [token for token in _TOKEN_SPLIT.split(hostname.lower()) if token]


def _deglyph(token: str) -> str:
    """Fold a token toward what it is trying to look like.

    ``paypa1`` -> ``paypal``, ``arnazon`` -> ``amazon``, ``g00gle`` -> ``google``.

    The ``rn``/``vv`` rules only ever *create* a match against the brand table,
    and no brand in that table is a common English word that ``rn``->``m`` would
    manufacture ("modern" folds to "modem", which is not a brand), so this
    cannot fire on ordinary domains.
    """
    folded = token.translate(_HOMOGLYPHS)
    return folded.replace("rn", "m").replace("vv", "w")


@dataclass(frozen=True)
class BrandResult:
    """Outcome of the offline impersonation check."""

    #: A brand token appears in the hostname but the registration is not theirs.
    mismatch: bool
    #: Which brand is being imitated. None when nothing matched.
    brand: str | None
    #: True when the brand token was spelled to *look* like the brand rather
    #: than spelled correctly (paypa1, arnazon). Strictly worse than a mismatch:
    #: a correct spelling can be coincidence, a lookalike cannot.
    lookalike: bool
    #: Lure words found alongside the brand. Escalates severity.
    lures: tuple[str, ...]
    #: Plain-language sentences for the popup. Written for someone who has never
    #: heard the word "domain" — hence "web address" in the user-facing text.
    reasons: tuple[str, ...]


def check_brand(hostname: str) -> BrandResult:
    """Look for brand impersonation in ``hostname``. Never raises, never blocks."""
    host = hostname.strip().lower().split(":")[0]
    domain = registrable_domain(host)
    tokens = host_tokens(host)
    token_set = set(tokens)

    matched_brand: str | None = None
    lookalike = False
    lures = tuple(sorted(token_set & LURE_TOKENS))

    for token in tokens:
        if token in BRAND_DOMAINS:
            if domain not in BRAND_DOMAINS[token]:
                if token in _AMBIGUOUS_BRANDS and not lures:
                    # An everyday word on an unrelated domain. Keep scanning —
                    # a later token may still be an unambiguous brand.
                    continue
                matched_brand, lookalike = token, False
                break
            # Correct brand on a legitimate domain — stop looking. An official
            # domain must never be reported because some *other* token in it
            # resembled a second brand.
            return BrandResult(False, token, False, (), ())

        folded = _deglyph(token)
        if folded != token and folded in BRAND_DOMAINS and domain not in BRAND_DOMAINS[folded]:
            # A deliberately misspelled brand is its own corroboration, so the
            # ambiguity rule above does not apply here: nobody types "app1e".
            matched_brand, lookalike = folded, True
            break

    if matched_brand is None:
        return BrandResult(False, None, False, (), ())

    reasons: list[str] = []
    if lookalike:
        reasons.append(
            f"The web address is spelled to look like “{matched_brand}” "
            f"without being it — read it letter by letter."
        )
    else:
        reasons.append(
            f"This address uses the name “{matched_brand}” but it is not an "
            f"official {matched_brand} website."
        )
    if lures:
        reasons.append(
            f"It also contains the word “{lures[0]}”, which scam sites use to "
            f"make you feel you must act now."
        )

    return BrandResult(
        mismatch=True,
        brand=matched_brand,
        lookalike=lookalike,
        lures=lures,
        reasons=tuple(reasons),
    )
