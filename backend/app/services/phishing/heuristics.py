"""Tier 1 phishing heuristics — deterministic, offline, zero cost.

Every signal in this file is something a phishing email *has to do* in order to
work. That is the selection criterion, and it is why these hold up against
emails written by an LLM: the prose can be flawless and the grammar native, but
the attacker still has to point a link somewhere they control, still has to ask
for the credential, and still has to create a reason to act before thinking.
Those are structural requirements of the crime, not stylistic tells.

Three groups, scored independently:

* **Links** — where the email actually sends you. The strongest group, because
  it is the hardest thing for an attacker to disguise and the easiest thing for
  a program to read precisely.
* **Sender** — who it claims to be versus what domain it came from. Only
  *available* when a sender line was pasted, which is the normal reason a check
  here goes missing rather than clean.
* **Content** — the ask, the deadline, the threat, the reward.

Within a group the sub-signals are correlated (a punycode host *and* a brand
mismatch is one attack seen twice, not two attacks), so a group scores as its
worst hit plus a small breadth bump — never a sum. Summing correlated evidence
is how a scanner ends up rating a mildly odd newsletter as critical.

References for the signal families: APWG *Phishing Activity Trends* reports,
which track credential-request and brand-impersonation rates per quarter, and
the feature families used across the PhishTank and Nazario phishing corpora
(URL/host structure, sender-vs-brand disagreement, urgency and reward lexicons).
No corpus is redistributed here — the patterns are reimplemented, which is what
keeps this dependency-free and inspectable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.services.site.brand import BRAND_DOMAINS, check_brand, registrable_domain

#: Hard cap on what any regex runs over. A pasted email is a paste, not a
#: keystroke, but unbounded backtracking on a megabyte of quoted-reply history
#: is a denial of service against your own backend.
MAX_BODY_CHARS = 20_000

#: Below this, no verdict is offered. "Your account is locked" is nine words and
#: could be a real bank SMS, a scam, or a note from a colleague — and a tool
#: that rates it either way is guessing with a confident face.
MIN_BODY_CHARS = 40

#: Evidence excerpts are shown to the user, so they are trimmed to something
#: readable rather than dumped whole.
MAX_EVIDENCE_CHARS = 120

#: How far apart two words can be and still count as one phrase. Roughly a
#: clause: "enter your password" is 3 words, "confirm the details, including
#: your net banking password" is 8 — both are one ask.
_WINDOW = 80


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hit:
    """One triggered sub-signal within a group."""

    #: Machine key. Stable across releases; the UI never shows it raw.
    name: str
    #: 0-100, how bad this alone is.
    penalty: int
    #: Plain-language sentence. Written for someone who has never heard the
    #: word "domain" — hence "web address" throughout.
    detail: str
    #: A literal excerpt from the email, so the user can see what was matched.
    #: Always a substring of the input, never paraphrased.
    evidence: str | None = None


@dataclass(frozen=True)
class GroupResult:
    """The outcome of one heuristic group."""

    #: False means the group could not run at all — not that it found nothing.
    #: The engine redistributes the weight of an unavailable group; it never
    #: counts it as a passing score.
    available: bool
    penalty: int
    hits: tuple[Hit, ...]
    #: Shown when the group ran and found nothing, or when it could not run.
    detail: str


def _excerpt(text: str) -> str:
    """Collapse whitespace and trim, keeping the result a recognisable quote."""
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= MAX_EVIDENCE_CHARS:
        return collapsed
    return collapsed[: MAX_EVIDENCE_CHARS - 1].rstrip() + "…"


def combine(hits: list[Hit], bump: int) -> int:
    """Worst hit, plus a little for breadth. Never a sum — see module docstring.

    Public because Module 9 scores QR payloads with the same rule. Two modules
    that both claim "max plus breadth" must not be two implementations of it, or
    a change here silently makes them disagree about what three findings are
    worth.
    """
    if not hits:
        return 0
    return min(100, max(hit.penalty for hit in hits) + bump * (len(hits) - 1))


# ---------------------------------------------------------------------------
# Link extraction
# ---------------------------------------------------------------------------

#: Anchor tags, for the case where the user pasted rich text and the clipboard
#: carried the markup. This is where display-vs-destination mismatch lives, and
#: it is the single most diagnostic signal in the whole module.
_ANCHOR = re.compile(
    r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)

#: Bare URLs in plain text. The trailing character class stops the match before
#: the punctuation that ends an English sentence.
_URL = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)

#: A domain-shaped token inside anchor text — "click here to visit sbi.co.in".
_DOMAINISH = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|in|co|io|gov|edu|info|biz|me|us|uk|xyz|top|tk|ml|ga|cf|online|site|live|app))\b",
    re.IGNORECASE,
)

_TAG = re.compile(r"<[^>]+>")

#: URL shorteners. Not malicious in themselves — they are also how a newsletter
#: fits a tracking link into a tweet — which is why the penalty is moderate and
#: never enough on its own to reach "dangerous".
SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink",
        "s.id", "gg.gg", "shorte.st", "adf.ly",
    }
)

#: Free mailbox providers. A bank does not email from one.
_FREEMAIL = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "yahoo.co.in",
        "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com",
        "rediffmail.com", "protonmail.com", "proton.me", "mail.com",
        "yandex.com", "zoho.com", "gmx.com", "inbox.com",
    }
)


@dataclass(frozen=True)
class LinkRef:
    """One link found in the email."""

    url: str
    host: str
    #: The text the reader actually sees. Equal to the URL for a bare link.
    display: str


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        # urlsplit raises on malformed IPv6 brackets. A URL this broken is not
        # something a mail client would render as a link either.
        return ""


def extract_links(body: str) -> list[LinkRef]:
    """Pull every link out of the email, anchors first, then bare URLs.

    Anchors are extracted first and their hrefs recorded, so a URL that appears
    both as an ``href`` and again in the stripped text is not counted twice —
    double-counting links is how a single suspicious destination turns into
    three "separate" findings.
    """
    links: list[LinkRef] = []
    seen: set[str] = set()

    for href, inner in _ANCHOR.findall(body):
        host = _host_of(href)
        if not host:
            continue
        display = _excerpt(_TAG.sub(" ", inner))
        links.append(LinkRef(url=href, host=host.lower(), display=display))
        seen.add(href)

    for url in _URL.findall(_ANCHOR.sub(" ", body)):
        if url in seen:
            continue
        host = _host_of(url)
        if not host:
            continue
        seen.add(url)
        links.append(LinkRef(url=url, host=host.lower(), display=url))

    return links


def _is_raw_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def analyse_links(body: str) -> GroupResult:
    """Score where this email actually sends the reader.

    Always available, including when there are no links at all: "this email
    contains no links" is a real answer to the question, not a missing one.
    """
    links = extract_links(body)
    hits: list[Hit] = []
    flagged_hosts: set[str] = set()

    for link in links:
        host = link.host
        domain = registrable_domain(host)

        # -- display text disagrees with destination --------------------------
        # The reader sees one address and the click goes to another. There is
        # no honest reason to build a link this way.
        #
        # Two sources for "what the reader sees", because they fail differently:
        # a full URL in the anchor text is unambiguous and needs no TLD table,
        # while a bare "visit sbi.co.in" does. Checking only the second missed
        # the commonest form of this attack — an anchor whose text is a
        # perfectly-spelled https:// link to the real bank.
        shown_candidates = [
            _host_of(found) for found in _URL.findall(link.display)
        ] + _DOMAINISH.findall(link.display)

        for candidate in shown_candidates:
            if not candidate:
                continue
            shown = registrable_domain(candidate.lower())
            if shown and shown != domain and not host.endswith("." + shown):
                hits.append(
                    Hit(
                        name="link_display_mismatch",
                        penalty=100,
                        detail=(
                            f"A link shows “{shown}” but actually goes to "
                            f"“{domain or host}”. Clicking it does not take you where it says."
                        ),
                        evidence=_excerpt(link.display),
                    )
                )
                break

        if host in flagged_hosts:
            continue

        # -- the destination is pretending to be a brand ----------------------
        brand = check_brand(host)
        if brand.mismatch and brand.brand:
            flagged_hosts.add(host)
            hits.append(
                Hit(
                    name="link_brand_mismatch",
                    penalty=95 if brand.lookalike else 85,
                    detail=(
                        f"A link points to “{domain or host}”, which is not an official "
                        f"{brand.brand} address"
                        + (" and is spelled to look like one." if brand.lookalike else ".")
                    ),
                    evidence=_excerpt(link.url),
                )
            )
            continue

        # -- non-Latin characters used to fake a Latin name -------------------
        if "xn--" in host:
            flagged_hosts.add(host)
            hits.append(
                Hit(
                    name="link_punycode",
                    penalty=85,
                    detail=(
                        "A link uses characters from another alphabet that look identical "
                        "to English letters. This is used to fake a familiar web address."
                    ),
                    evidence=_excerpt(link.url),
                )
            )
            continue

        # -- a number instead of a name ---------------------------------------
        if _is_raw_ip(host):
            flagged_hosts.add(host)
            hits.append(
                Hit(
                    name="link_raw_ip",
                    penalty=80,
                    detail=(
                        "A link goes to a bare numeric address instead of a website name. "
                        "Real companies do not send links like this."
                    ),
                    evidence=_excerpt(link.url),
                )
            )
            continue

        # -- the destination is hidden behind a shortener ----------------------
        if domain in SHORTENERS:
            flagged_hosts.add(host)
            hits.append(
                Hit(
                    name="link_shortener",
                    penalty=45,
                    detail=(
                        f"A link is hidden behind the shortener “{domain}”, so you cannot see "
                        "where it leads before you click."
                    ),
                    evidence=_excerpt(link.url),
                )
            )

    if hits:
        # Breadth bump of 5: two independently bad destinations is worse than
        # one, but not additively — they are usually the same campaign.
        return GroupResult(True, combine(hits, 5), tuple(hits), "")

    if not links:
        return GroupResult(True, 0, (), "This email contains no web links.")
    return GroupResult(True, 0, (), f"All {len(links)} link(s) point where they say they do.")


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

_ADDRESS = re.compile(
    r"^\s*(?:\"?(?P<display>[^\"<]*?)\"?\s*)?<?(?P<addr>[^<>\s@]+@[^<>\s@]+?)>?\s*$"
)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class SenderRef:
    display: str
    address: str
    domain: str


def parse_sender(raw: str | None) -> SenderRef | None:
    """Split ``Name <user@host>`` into its parts, or give up cleanly.

    ``None`` here propagates all the way to an *unavailable* sender group. That
    is the honest outcome: a user who pasted only the message body has told us
    nothing about the sender, and inventing a passing grade for the check would
    be the exact fallacy this codebase is built to avoid.
    """
    if not raw or not raw.strip():
        return None
    match = _ADDRESS.match(raw.strip())
    if not match:
        return None
    address = match.group("addr").lower()
    domain = registrable_domain(address.split("@", 1)[1])
    if not domain or "." not in domain:
        return None
    return SenderRef(display=(match.group("display") or "").strip(), address=address, domain=domain)


def _brand_tokens(text: str) -> list[str]:
    """Brand names appearing as whole tokens in ``text``."""
    return [t for t in _TOKEN_SPLIT.split(text.lower()) if t in BRAND_DOMAINS]


def analyse_sender(sender: str | None, reply_to: str | None, subject: str) -> GroupResult:
    """Score who this email claims to be against where it came from."""
    parsed = parse_sender(sender)
    if parsed is None:
        return GroupResult(
            available=False,
            penalty=0,
            hits=(),
            detail="No sender line was included, so who sent this could not be checked.",
        )

    hits: list[Hit] = []
    local_part = parsed.address.split("@", 1)[0]

    # -- the sender domain is itself impersonating a brand ---------------------
    brand = check_brand(parsed.address.split("@", 1)[1])
    if brand.mismatch and brand.brand:
        hits.append(
            Hit(
                name="sender_lookalike_domain",
                penalty=95 if brand.lookalike else 85,
                detail=(
                    f"The address it came from, “{parsed.domain}”, is not an official "
                    f"{brand.brand} address"
                    + (" and is spelled to look like one." if brand.lookalike else ".")
                ),
                evidence=parsed.address,
            )
        )
    else:
        # -- it names a brand it does not own ---------------------------------
        # Checked only when the domain is not already flagged, so one
        # impersonation is not reported twice in different words.
        claimed = _brand_tokens(f"{parsed.display} {local_part}")
        for token in claimed:
            if parsed.domain not in BRAND_DOMAINS[token]:
                hits.append(
                    Hit(
                        name="sender_brand_mismatch",
                        penalty=90,
                        detail=(
                            f"It signs itself “{token}” but was sent from “{parsed.domain}”, "
                            f"which {token} does not own."
                        ),
                        evidence=_excerpt(sender or parsed.address),
                    )
                )
                break

    # -- a bank writing from a free mailbox ------------------------------------
    if parsed.domain in _FREEMAIL:
        authority = _brand_tokens(f"{parsed.display} {subject}")
        if authority:
            hits.append(
                Hit(
                    name="sender_freemail_authority",
                    penalty=75,
                    detail=(
                        f"It claims to be from {authority[0]} but was sent from a free "
                        f"{parsed.domain} account. Companies email from their own address."
                    ),
                    evidence=parsed.address,
                )
            )

    # -- your reply would go somewhere else ------------------------------------
    reply = parse_sender(reply_to)
    if reply and reply.domain != parsed.domain:
        hits.append(
            Hit(
                name="sender_reply_to_mismatch",
                penalty=70,
                detail=(
                    f"If you reply, your answer goes to “{reply.domain}”, not to "
                    f"“{parsed.domain}” where this appears to be from."
                ),
                evidence=reply.address,
            )
        )

    if hits:
        return GroupResult(True, combine(hits, 6), tuple(hits), "")
    return GroupResult(True, 0, (), f"The sender address “{parsed.domain}” matches who it claims to be.")


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------
#
# The two-sided patterns below are deliberate. A single keyword list produces a
# scanner that flags the word "password" in a password-reset email the user
# asked for. Requiring a *request verb* near a *credential noun*, within one
# clause, is the difference between "we will never ask for your password" (no
# hit — no request verb governs it) and "confirm your password below" (a hit).

_CREDENTIAL_NOUNS = re.compile(
    r"\b(passwords?|passcodes?|otps?|one[-\s]time\s+(?:password|code|pin)|"
    r"pins?|mpin|upi\s+pin|cvv|card\s+numbers?|debit\s+cards?|credit\s+cards?|"
    r"net\s?banking(?:\s+(?:id|login|details|credentials))?|user\s?names?|user\s?ids?|"
    r"login\s+(?:id|details|credentials)|aadhaar(?:\s+numbers?)?|pan\s+(?:card|numbers?)|"
    r"account\s+numbers?|security\s+(?:question|answer)|cvc)\b",
    re.IGNORECASE,
)
_REQUEST_VERBS = re.compile(
    r"\b(enter|confirm|verify|validate|update|provide|submit|share|send|"
    r"reply\s+with|re-?enter|type|fill\s+in|give\s+us|tell\s+us|input)\b",
    re.IGNORECASE,
)

_URGENCY = re.compile(
    r"\b(immediately|urgent(?:ly)?|right\s+away|without\s+delay|"
    r"within\s+(?:\d{1,3}|twenty[-\s]four|forty[-\s]eight)\s*(?:hours?|hrs?|minutes?|mins?|days?)|"
    r"before\s+(?:midnight|today|tomorrow|the\s+end\s+of\s+(?:the\s+)?day)|"
    r"expir(?:es?|ing|ed)\s+(?:today|soon|in|within)|last\s+(?:chance|warning|reminder)|"
    r"act\s+now|final\s+notice|time[-\s]sensitive|as\s+soon\s+as\s+possible)\b",
    re.IGNORECASE,
)

_ACCOUNT_NOUNS = re.compile(
    r"\b(accounts?|cards?|services?|access|profile|policy|subscriptions?|kyc|wallets?)\b",
    re.IGNORECASE,
)
_CONSEQUENCES = re.compile(
    r"\b(suspend(?:ed|ing|sion)?|deactivat(?:e|ed|ion)|block(?:ed|ing)?|"
    r"clos(?:e|ed|ure)|terminat(?:e|ed|ion)|restrict(?:ed|ion)|frozen|freeze|"
    r"permanently\s+(?:deleted|lost|disabled)|legal\s+action|penalty|prosecut)\w*",
    re.IGNORECASE,
)

_REWARD = re.compile(
    r"\b(you\s+have\s+won|congratulations[,!\s]|winner|lottery|jackpot|lucky\s+draw|"
    r"prize\s+money|cash\s?back\s+of|refund\s+(?:of|amount|is\s+pending|has\s+been\s+approved)|"
    r"gift\s+(?:card|voucher)|claim\s+your|reward\s+points?\s+(?:expiring|will\s+expire))\b",
    re.IGNORECASE,
)

_PAYMENT = re.compile(
    r"\b(gift\s?cards?|google\s+play\s+cards?|itunes\s+cards?|bitcoins?|btc\b|"
    r"crypto(?:currency)?|wire\s+transfer|western\s+union|moneygram|"
    r"scan\s+(?:this|the)\s+qr|pay\s+(?:a\s+)?(?:small\s+)?(?:processing|clearance|customs)\s+fee)\b",
    re.IGNORECASE,
)

_ATTACHMENT_PROSE = re.compile(
    r"\b(?:attached|attachment|enclosed|find\s+the)\b[^.\n]{0,60}?"
    r"\b(invoices?|receipts?|statements?|documents?|forms?|bills?|reports?|awb|challan)\b",
    re.IGNORECASE,
)
_DANGEROUS_FILE = re.compile(
    r"\b[\w.-]{1,60}\.(zip|exe|scr|iso|rar|apk|bat|cmd|jar|vbs|lnk|7z)\b", re.IGNORECASE
)

_GREETING = re.compile(
    r"\b(dear\s+(?:customer|user|sir|madam|sir\s*/\s*madam|valued\s+customer|"
    r"account\s+holder|member|client|subscriber)|attention\s+customer|dear\s+beneficiary)\b",
    re.IGNORECASE,
)


def near(
    text: str,
    left: re.Pattern[str],
    right: re.Pattern[str],
    *,
    window: int = _WINDOW,
) -> re.Match[str] | None:
    """First ``left`` match with a ``right`` match inside ``window`` characters.

    Returns the *left* match so the evidence excerpt is anchored on the thing
    being asked for, which is what a reader needs to see.

    Public for the same reason ``combine`` is: Module 11 scores chat messages
    with the identical proximity rule, and two implementations of "these two
    words are in the same clause" would drift the day one of them is tuned.

    ``window`` is a parameter rather than a constant because the *rule* is
    shared and the *distance* legitimately is not. An email is one document, so
    two facts that belong together sit in one clause. A conversation splits the
    same pair across separate messages — the offer in one, the ask in the next —
    and Module 11 passes its own wider value for exactly that reason. The
    default keeps every existing caller on the clause window.
    """
    for match in left.finditer(text):
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        if right.search(text, start, end):
            return match
    return None


def strip_markup(body: str) -> str:
    """Remove tags so tag names and URLs cannot trigger a content pattern.

    Without this, ``<a href="…/verify-account">`` alone would fire the urgency
    and credential patterns on every legitimate password-reset email.
    """
    text = _ANCHOR.sub(lambda m: " " + _TAG.sub(" ", m.group(2)) + " ", body)
    text = _TAG.sub(" ", text)
    return _URL.sub(" ", text)


def analyse_content(subject: str, body: str) -> GroupResult:
    """Score the ask, the deadline, the threat, and the bait."""
    text = strip_markup(f"{subject}\n{body}")
    hits: list[Hit] = []

    def add(name: str, penalty: int, detail: str, match: re.Match[str] | None) -> None:
        window = None
        if match is not None:
            start = max(0, match.start() - 40)
            window = _excerpt(text[start : match.end() + 40])
        hits.append(Hit(name=name, penalty=penalty, detail=detail, evidence=window))

    credential = near(text, _CREDENTIAL_NOUNS, _REQUEST_VERBS)
    if credential:
        add(
            "credential_request",
            90,
            "It asks you to enter or confirm a password, OTP, PIN, or card details. "
            "No bank or government office ever asks for these by email.",
            credential,
        )

    threat = near(text, _CONSEQUENCES, _ACCOUNT_NOUNS)
    if threat:
        add(
            "threatened_consequence",
            60,
            "It threatens that your account will be suspended, blocked, or closed. "
            "Fear is the standard tool for stopping you from checking.",
            threat,
        )

    urgency = _URGENCY.search(text)
    if urgency:
        add(
            "urgency",
            55,
            "It pushes you to act within a deadline. Real notices give you time; "
            "scams cannot afford to let you verify.",
            urgency,
        )

    payment = _PAYMENT.search(text)
    if payment:
        add(
            "unusual_payment",
            75,
            "It asks for payment by a method that cannot be reversed — gift cards, "
            "crypto, or a wire transfer. No genuine refund or fee works this way.",
            payment,
        )

    reward = _REWARD.search(text)
    if reward:
        add(
            "reward_lure",
            55,
            "It offers a prize, refund, or reward you did not apply for.",
            reward,
        )

    attachment = _DANGEROUS_FILE.search(text) or _ATTACHMENT_PROSE.search(text)
    if attachment:
        add(
            "attachment_lure",
            50,
            "It refers to an attachment you are expected to open. Attachments in "
            "unexpected emails are the most common way computers get infected.",
            attachment,
        )

    greeting = _GREETING.search(text)
    if greeting:
        add(
            "generic_greeting",
            25,
            "It greets you generically rather than by name. A company you have an "
            "account with knows your name.",
            greeting,
        )

    if hits:
        # Breadth bump of 8, higher than the link group's: content signals are
        # weak alone and strong together. Urgency by itself is a delivery
        # notification; urgency plus a credential request plus a threat is a
        # phishing email, and the arithmetic should say so.
        return GroupResult(True, combine(hits, 8), tuple(hits), "")
    return GroupResult(True, 0, (), "The wording contains no pressure tactics or requests for secrets.")
