"""Module 10 — where the data was about to go.

Every other detector in this codebase answers *what* a string is. This file
answers *where it is being put*, which is the other half of whether it matters.
An ``AKIA…`` key pasted into the AWS console is a person doing their job. The
same key pasted into Discord is an incident. Identical text, opposite meaning,
and no amount of pattern work on the string itself can separate them.

Three properties are deliberate:

1. **It is a table, not a heuristic.** Origins are hand-entered from the sites
   themselves. A wrong entry produces a wrong sentence and can never become an
   execution path, which is the right failure mode for something that decides
   whether to interrupt a user.
2. **An unrecognised origin is ``UNKNOWN``, never ``EXPECTED``.** The house rule
   applies here exactly as it does to a Safe Browsing timeout: a lookup that did
   not answer is not a lookup that said "fine". The table covers roughly ninety
   sites out of the entire web, so ``UNKNOWN`` is the *common* case and had
   better be worded honestly.
3. **It never suppresses a warning.** ``appropriateness`` grades a fit and
   supplies a sentence. It has no path that removes a finding, lowers a risk
   score, or turns a red panel green. Thin evidence blocks a clean bill of
   health; it does not buy one.

All functions are pure and have no imports from FastAPI or SQLAlchemy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DestinationClass(str, Enum):
    """What kind of place the text is being pasted into."""

    CHAT = "chat"
    SOCIAL = "social"
    PASTE_SITE = "paste_site"
    AI_CHAT = "ai_chat"
    EMAIL = "email"
    CODE_HOST = "code_host"
    TRUSTED_FINANCE = "trusted_finance"
    #: Added beyond the original five-module sketch, and the reason is the
    #: flagship case: without it, ``console.aws.amazon.com`` falls to UNKNOWN and
    #: the product cannot express the one place an AWS key legitimately goes.
    #: A table that has no word for "correct" can only ever nag.
    CLOUD_CONSOLE = "cloud_console"
    UNKNOWN = "unknown"


class Appropriateness(str, Enum):
    """How well a kind of secret fits a kind of place.

    ``UNKNOWN`` is a first-class answer, not an error. It is what an
    unrecognised origin produces, and the sentence it generates says so out
    loud rather than shrugging.
    """

    NEVER = "never"
    RARELY = "rarely"
    EXPECTED = "expected"
    UNKNOWN = "unknown"


#: Human-readable name for each class, for the one place the class itself is
#: shown. "paste_site" on screen would be the same mistake as showing a user
#: ``domain_age_days``.
CLASS_LABELS: dict[DestinationClass, str] = {
    DestinationClass.CHAT: "a chat app",
    DestinationClass.SOCIAL: "a social network",
    DestinationClass.PASTE_SITE: "a public paste site",
    DestinationClass.AI_CHAT: "an AI assistant",
    DestinationClass.EMAIL: "an email service",
    DestinationClass.CODE_HOST: "a code hosting site",
    DestinationClass.TRUSTED_FINANCE: "a bank or payment service",
    DestinationClass.CLOUD_CONSOLE: "a cloud or developer console",
    DestinationClass.UNKNOWN: "a site SentinelAI does not recognise",
}


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------
#
# Keyed by host. Lookup is most-specific-first over label boundaries, so
# ``web.whatsapp.com`` finds its own entry, ``canary.discord.com`` falls back to
# ``discord.com``, and ``evil-discord.com`` matches nothing — which is the whole
# reason the walk is by label and not by ``endswith``.
#
# The display name matters: it is interpolated into a sentence a stressed person
# reads in half a second. "Discord" and "WhatsApp Web", not "discord.com".

_TABLE: dict[str, tuple[DestinationClass, str]] = {
    # --- Chat ---------------------------------------------------------------
    "web.whatsapp.com": (DestinationClass.CHAT, "WhatsApp Web"),
    "whatsapp.com": (DestinationClass.CHAT, "WhatsApp"),
    "web.telegram.org": (DestinationClass.CHAT, "Telegram Web"),
    "telegram.org": (DestinationClass.CHAT, "Telegram"),
    "discord.com": (DestinationClass.CHAT, "Discord"),
    "discordapp.com": (DestinationClass.CHAT, "Discord"),
    "slack.com": (DestinationClass.CHAT, "Slack"),
    "teams.microsoft.com": (DestinationClass.CHAT, "Microsoft Teams"),
    "teams.live.com": (DestinationClass.CHAT, "Microsoft Teams"),
    "messenger.com": (DestinationClass.CHAT, "Messenger"),
    "signal.org": (DestinationClass.CHAT, "Signal"),
    "chat.google.com": (DestinationClass.CHAT, "Google Chat"),
    "meet.google.com": (DestinationClass.CHAT, "Google Meet chat"),
    "zoom.us": (DestinationClass.CHAT, "Zoom chat"),
    "element.io": (DestinationClass.CHAT, "Element"),
    "skype.com": (DestinationClass.CHAT, "Skype"),
    # --- Social -------------------------------------------------------------
    "x.com": (DestinationClass.SOCIAL, "X"),
    "twitter.com": (DestinationClass.SOCIAL, "X"),
    "facebook.com": (DestinationClass.SOCIAL, "Facebook"),
    "instagram.com": (DestinationClass.SOCIAL, "Instagram"),
    "reddit.com": (DestinationClass.SOCIAL, "Reddit"),
    "linkedin.com": (DestinationClass.SOCIAL, "LinkedIn"),
    "youtube.com": (DestinationClass.SOCIAL, "YouTube"),
    "quora.com": (DestinationClass.SOCIAL, "Quora"),
    "tumblr.com": (DestinationClass.SOCIAL, "Tumblr"),
    "threads.net": (DestinationClass.SOCIAL, "Threads"),
    "threads.com": (DestinationClass.SOCIAL, "Threads"),
    "pinterest.com": (DestinationClass.SOCIAL, "Pinterest"),
    "snapchat.com": (DestinationClass.SOCIAL, "Snapchat"),
    "sharechat.com": (DestinationClass.SOCIAL, "ShareChat"),
    "koo.com": (DestinationClass.SOCIAL, "Koo"),
    # --- Public paste sites -------------------------------------------------
    #
    # The dangerous property these share is that the default is *public*. A
    # secret pasted here is not merely seen by the recipient; it is indexed.
    "pastebin.com": (DestinationClass.PASTE_SITE, "Pastebin"),
    "paste.ee": (DestinationClass.PASTE_SITE, "Paste.ee"),
    "hastebin.com": (DestinationClass.PASTE_SITE, "Hastebin"),
    "dpaste.org": (DestinationClass.PASTE_SITE, "dpaste"),
    "dpaste.com": (DestinationClass.PASTE_SITE, "dpaste"),
    "controlc.com": (DestinationClass.PASTE_SITE, "ControlC"),
    "rentry.co": (DestinationClass.PASTE_SITE, "Rentry"),
    "justpaste.it": (DestinationClass.PASTE_SITE, "JustPaste.it"),
    "ghostbin.com": (DestinationClass.PASTE_SITE, "Ghostbin"),
    "codepen.io": (DestinationClass.PASTE_SITE, "CodePen"),
    "jsfiddle.net": (DestinationClass.PASTE_SITE, "JSFiddle"),
    "codesandbox.io": (DestinationClass.PASTE_SITE, "CodeSandbox"),
    "replit.com": (DestinationClass.PASTE_SITE, "Replit"),
    "jsonformatter.org": (DestinationClass.PASTE_SITE, "JSONFormatter"),
    "jwt.io": (DestinationClass.PASTE_SITE, "jwt.io"),
    # --- AI assistants ------------------------------------------------------
    #
    # Separated from chat because the risk is different in kind: the text is not
    # merely delivered to a person, it is sent to a third party for processing
    # and may be retained. Users routinely paste whole config files here.
    "chatgpt.com": (DestinationClass.AI_CHAT, "ChatGPT"),
    "chat.openai.com": (DestinationClass.AI_CHAT, "ChatGPT"),
    "claude.ai": (DestinationClass.AI_CHAT, "Claude"),
    "gemini.google.com": (DestinationClass.AI_CHAT, "Gemini"),
    "aistudio.google.com": (DestinationClass.AI_CHAT, "Google AI Studio"),
    "perplexity.ai": (DestinationClass.AI_CHAT, "Perplexity"),
    "copilot.microsoft.com": (DestinationClass.AI_CHAT, "Microsoft Copilot"),
    "poe.com": (DestinationClass.AI_CHAT, "Poe"),
    "chat.deepseek.com": (DestinationClass.AI_CHAT, "DeepSeek"),
    "chat.mistral.ai": (DestinationClass.AI_CHAT, "Le Chat"),
    "grok.com": (DestinationClass.AI_CHAT, "Grok"),
    "huggingface.co": (DestinationClass.AI_CHAT, "Hugging Face"),
    # --- Email --------------------------------------------------------------
    "mail.google.com": (DestinationClass.EMAIL, "Gmail"),
    "outlook.live.com": (DestinationClass.EMAIL, "Outlook"),
    "outlook.office.com": (DestinationClass.EMAIL, "Outlook"),
    "outlook.office365.com": (DestinationClass.EMAIL, "Outlook"),
    "mail.yahoo.com": (DestinationClass.EMAIL, "Yahoo Mail"),
    "mail.proton.me": (DestinationClass.EMAIL, "Proton Mail"),
    "mail.zoho.com": (DestinationClass.EMAIL, "Zoho Mail"),
    "mail.zoho.in": (DestinationClass.EMAIL, "Zoho Mail"),
    "mail.rediff.com": (DestinationClass.EMAIL, "Rediffmail"),
    "roundcube.net": (DestinationClass.EMAIL, "Roundcube"),
    # --- Code hosting -------------------------------------------------------
    "github.com": (DestinationClass.CODE_HOST, "GitHub"),
    "gist.github.com": (DestinationClass.CODE_HOST, "GitHub Gist"),
    "gitlab.com": (DestinationClass.CODE_HOST, "GitLab"),
    "bitbucket.org": (DestinationClass.CODE_HOST, "Bitbucket"),
    "codeberg.org": (DestinationClass.CODE_HOST, "Codeberg"),
    "sourceforge.net": (DestinationClass.CODE_HOST, "SourceForge"),
    "stackoverflow.com": (DestinationClass.CODE_HOST, "Stack Overflow"),
    "stackexchange.com": (DestinationClass.CODE_HOST, "Stack Exchange"),
    "npmjs.com": (DestinationClass.CODE_HOST, "npm"),
    "pypi.org": (DestinationClass.CODE_HOST, "PyPI"),
    # --- Banks and payment --------------------------------------------------
    #
    # The only class where a government ID or a card number is *expected*. Note
    # that a credential is still NEVER appropriate here: a bank asking you to
    # paste an API key is a bank being impersonated.
    "onlinesbi.sbi": (DestinationClass.TRUSTED_FINANCE, "SBI Online"),
    "onlinesbi.com": (DestinationClass.TRUSTED_FINANCE, "SBI Online"),
    "sbi.co.in": (DestinationClass.TRUSTED_FINANCE, "State Bank of India"),
    "hdfcbank.com": (DestinationClass.TRUSTED_FINANCE, "HDFC Bank"),
    "icicibank.com": (DestinationClass.TRUSTED_FINANCE, "ICICI Bank"),
    "axisbank.com": (DestinationClass.TRUSTED_FINANCE, "Axis Bank"),
    "kotak.com": (DestinationClass.TRUSTED_FINANCE, "Kotak Mahindra Bank"),
    "pnbindia.in": (DestinationClass.TRUSTED_FINANCE, "Punjab National Bank"),
    "bankofbaroda.in": (DestinationClass.TRUSTED_FINANCE, "Bank of Baroda"),
    "unionbankofindia.co.in": (DestinationClass.TRUSTED_FINANCE, "Union Bank of India"),
    "idfcfirstbank.com": (DestinationClass.TRUSTED_FINANCE, "IDFC FIRST Bank"),
    "yesbank.in": (DestinationClass.TRUSTED_FINANCE, "YES Bank"),
    "paytm.com": (DestinationClass.TRUSTED_FINANCE, "Paytm"),
    "phonepe.com": (DestinationClass.TRUSTED_FINANCE, "PhonePe"),
    "razorpay.com": (DestinationClass.TRUSTED_FINANCE, "Razorpay"),
    "npci.org.in": (DestinationClass.TRUSTED_FINANCE, "NPCI"),
    "incometax.gov.in": (DestinationClass.TRUSTED_FINANCE, "the Income Tax portal"),
    "uidai.gov.in": (DestinationClass.TRUSTED_FINANCE, "UIDAI"),
    "epfindia.gov.in": (DestinationClass.TRUSTED_FINANCE, "EPFO"),
    "nsdl.com": (DestinationClass.TRUSTED_FINANCE, "NSDL"),
    "zerodha.com": (DestinationClass.TRUSTED_FINANCE, "Zerodha"),
    "groww.in": (DestinationClass.TRUSTED_FINANCE, "Groww"),
    "paypal.com": (DestinationClass.TRUSTED_FINANCE, "PayPal"),
    # --- Cloud and developer consoles ---------------------------------------
    "console.aws.amazon.com": (DestinationClass.CLOUD_CONSOLE, "the AWS Console"),
    "signin.aws.amazon.com": (DestinationClass.CLOUD_CONSOLE, "the AWS Console"),
    "portal.azure.com": (DestinationClass.CLOUD_CONSOLE, "the Azure Portal"),
    "console.cloud.google.com": (DestinationClass.CLOUD_CONSOLE, "the Google Cloud Console"),
    "dashboard.stripe.com": (DestinationClass.CLOUD_CONSOLE, "the Stripe Dashboard"),
    "dashboard.heroku.com": (DestinationClass.CLOUD_CONSOLE, "Heroku"),
    "vercel.com": (DestinationClass.CLOUD_CONSOLE, "Vercel"),
    "app.netlify.com": (DestinationClass.CLOUD_CONSOLE, "Netlify"),
    "dash.cloudflare.com": (DestinationClass.CLOUD_CONSOLE, "the Cloudflare dashboard"),
    "cloud.digitalocean.com": (DestinationClass.CLOUD_CONSOLE, "DigitalOcean"),
    "supabase.com": (DestinationClass.CLOUD_CONSOLE, "Supabase"),
    "railway.app": (DestinationClass.CLOUD_CONSOLE, "Railway"),
    "render.com": (DestinationClass.CLOUD_CONSOLE, "Render"),
    "console.firebase.google.com": (DestinationClass.CLOUD_CONSOLE, "the Firebase Console"),
    "app.datadoghq.com": (DestinationClass.CLOUD_CONSOLE, "Datadog"),
    "sentry.io": (DestinationClass.CLOUD_CONSOLE, "Sentry"),
    "localhost": (DestinationClass.CLOUD_CONSOLE, "a local development server"),
}


@dataclass(frozen=True)
class Destination:
    """A classified paste target.

    ``recognised`` is stored rather than derived so a caller cannot accidentally
    treat "we have no idea" as a class it can reason about. It is the one bit
    the UI branches on.
    """

    origin: str
    name: str
    kind: DestinationClass
    kind_label: str

    @property
    def recognised(self) -> bool:
        return self.kind is not DestinationClass.UNKNOWN


def _host_of(origin: str) -> str:
    """Reduce ``https://Web.WhatsApp.com:443/x`` to ``web.whatsapp.com``.

    Tolerant on purpose. The request schema already normalises ``site_origin``,
    but this function is also called from tests and from a REPL, and a lookup
    table that only works on pre-cleaned input is a table that will one day be
    handed a full URL and quietly return UNKNOWN.
    """
    value = origin.strip().lower()
    if "//" in value:
        value = value.split("//", 1)[1]
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    # Strip credentials and port. IPv6 literals are not in the table and never
    # will be, so bracket handling is deliberately absent.
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip(".")


def classify(origin: str) -> Destination:
    """Look up an origin. Never raises, never guesses.

    The walk drops one leftmost label at a time, so ``canary.discord.com``
    resolves through ``discord.com``. It stops before a bare public suffix,
    which is what stops ``evil-discord.com`` from being read as Discord and
    ``notgithub.com`` from being read as GitHub — a substring match would get
    both wrong in the direction that matters.
    """
    host = _host_of(origin)
    if not host:
        return Destination(origin, "this page", DestinationClass.UNKNOWN,
                           CLASS_LABELS[DestinationClass.UNKNOWN])

    labels = host.split(".")
    # `range(len(labels) - 1)` leaves at least two labels, so a lone TLD is
    # never looked up. `localhost` is a single label and is matched by the
    # exact-host check on the first iteration.
    for index in range(max(1, len(labels) - 1)):
        candidate = ".".join(labels[index:])
        entry = _TABLE.get(candidate)
        if entry is not None:
            kind, name = entry
            return Destination(origin, name, kind, CLASS_LABELS[kind])

    return Destination(origin, host, DestinationClass.UNKNOWN,
                       CLASS_LABELS[DestinationClass.UNKNOWN])


# ---------------------------------------------------------------------------
# Fit
# ---------------------------------------------------------------------------
#
# PII types are grouped into five families rather than enumerated one by one.
# Fourteen detectors times nine classes is 126 cells nobody would keep correct;
# five times nine is a matrix that fits on a screen and can be argued with.

_FAMILIES: dict[str, str] = {
    "api_key": "credential",
    "jwt": "credential",
    "password": "credential",
    "aadhaar": "government_id",
    "pan": "government_id",
    "passport": "government_id",
    "credit_card": "financial",
    "bank_account": "financial",
    "ifsc": "financial",
    "upi_id": "financial",
    "email": "contact",
    "phone": "contact",
    "dob": "personal",
    "coordinates": "personal",
}

_N = Appropriateness.NEVER
_R = Appropriateness.RARELY
_E = Appropriateness.EXPECTED
_U = Appropriateness.UNKNOWN

#: family -> class -> fit.
#:
#: Read the credential row across: a secret key belongs in a console and
#: nowhere else. Read the code_host column down: a credential committed to
#: GitHub is one of the most common breach causes there is, which is why that
#: cell is NEVER and not RARELY even though the site is otherwise reputable.
_MATRIX: dict[str, dict[DestinationClass, Appropriateness]] = {
    "credential": {
        DestinationClass.CHAT: _N,
        DestinationClass.SOCIAL: _N,
        DestinationClass.PASTE_SITE: _N,
        DestinationClass.AI_CHAT: _N,
        DestinationClass.EMAIL: _N,
        DestinationClass.CODE_HOST: _N,
        DestinationClass.TRUSTED_FINANCE: _N,
        DestinationClass.CLOUD_CONSOLE: _E,
    },
    "government_id": {
        DestinationClass.CHAT: _N,
        DestinationClass.SOCIAL: _N,
        DestinationClass.PASTE_SITE: _N,
        DestinationClass.AI_CHAT: _N,
        DestinationClass.EMAIL: _R,
        DestinationClass.CODE_HOST: _N,
        DestinationClass.TRUSTED_FINANCE: _E,
        DestinationClass.CLOUD_CONSOLE: _R,
    },
    "financial": {
        DestinationClass.CHAT: _N,
        DestinationClass.SOCIAL: _N,
        DestinationClass.PASTE_SITE: _N,
        DestinationClass.AI_CHAT: _N,
        DestinationClass.EMAIL: _R,
        DestinationClass.CODE_HOST: _N,
        DestinationClass.TRUSTED_FINANCE: _E,
        DestinationClass.CLOUD_CONSOLE: _R,
    },
    "contact": {
        DestinationClass.CHAT: _E,
        DestinationClass.SOCIAL: _R,
        DestinationClass.PASTE_SITE: _R,
        DestinationClass.AI_CHAT: _R,
        DestinationClass.EMAIL: _E,
        DestinationClass.CODE_HOST: _R,
        DestinationClass.TRUSTED_FINANCE: _E,
        DestinationClass.CLOUD_CONSOLE: _E,
    },
    "personal": {
        DestinationClass.CHAT: _R,
        DestinationClass.SOCIAL: _N,
        DestinationClass.PASTE_SITE: _N,
        DestinationClass.AI_CHAT: _R,
        DestinationClass.EMAIL: _R,
        DestinationClass.CODE_HOST: _N,
        DestinationClass.TRUSTED_FINANCE: _E,
        DestinationClass.CLOUD_CONSOLE: _R,
    },
}


def appropriateness(pii_type: str, kind: DestinationClass) -> Appropriateness:
    """Grade the fit between a kind of secret and a kind of place.

    Returns ``UNKNOWN`` for an unrecognised destination *and* for a PII type
    that has no family — a Tier-2 finding like ``home_address`` arrives with a
    type this table has never seen, and inventing a grade for it would be
    exactly the guess this module exists to avoid.
    """
    if kind is DestinationClass.UNKNOWN:
        return Appropriateness.UNKNOWN
    family = _FAMILIES.get(pii_type)
    if family is None:
        return Appropriateness.UNKNOWN
    return _MATRIX[family].get(kind, Appropriateness.UNKNOWN)


# ---------------------------------------------------------------------------
# The sentence
# ---------------------------------------------------------------------------
#
# Written to be read once, quickly, by someone who is mid-task and mildly
# annoyed at having been interrupted. Consequence first, instruction second, no
# clause that could be mistaken for reassurance.

#: How a finding is named *inside a sentence*, with the article that belongs in
#: front of it.
#:
#: A detector's ``label`` is a column heading — "API Key / Secret", "PAN
#: (Permanent Account Number)". Dropping one into prose with ``.lower()`` and a
#: hard-coded "a" produces "a api key / secret", which is both ungrammatical and
#: no longer a name the user recognises: the acronym is the part they read, and
#: lower-casing destroys it. So the sentence form is written out once, here,
#: rather than derived from a string that was written for a different purpose.
#:
#: The article is stored rather than computed because English decides it by
#: *sound*: "an API key" (ay-pee-eye) but "a UPI ID" (yoo-pee-eye), and both
#: start with a vowel letter. A rule that gets one of those wrong is a rule that
#: has to be special-cased anyway, so the table states it and the code does not
#: guess.
_PHRASES: dict[str, tuple[str, str]] = {
    "jwt": ("a", "session token"),
    "api_key": ("an", "API key"),
    "password": ("a", "password"),
    "aadhaar": ("an", "Aadhaar number"),
    "pan": ("a", "PAN"),
    "passport": ("a", "passport number"),
    "credit_card": ("a", "card number"),
    "bank_account": ("a", "bank account number"),
    "ifsc": ("an", "IFSC code"),
    "upi_id": ("a", "UPI ID"),
    "email": ("an", "email address"),
    "phone": ("a", "phone number"),
    "dob": ("a", "date of birth"),
    "coordinates": ("a", "precise location"),
}

#: Words whose leading vowel *letter* is a consonant *sound*, for the fallback
#: path only. Tier 2 invents finding types this file has never seen, so the
#: fallback has to guess — but it should not guess badly on the handful of
#: openings that actually occur.
_CONSONANT_VOWELS = ("u", "eu", "one")


def _phrase(label: str, pii_type: str) -> str:
    """Return the finding named for prose, article included — ``"an API key"``.

    Falls back to the lower-cased label for a type not in ``_PHRASES``, which is
    how a Tier-2 finding like ``home_address`` is handled. The fallback article
    is the vowel-letter rule with the ``_CONSONANT_VOWELS`` exceptions; it is a
    heuristic, and it is only ever reached for a type nobody has written a
    sentence for.
    """
    known = _PHRASES.get(pii_type)
    if known is not None:
        return f"{known[0]} {known[1]}"

    thing = label.lower().strip()
    if not thing:
        return "this"
    vowel = thing[0] in "aeiou" and not thing.startswith(_CONSONANT_VOWELS)
    return f"{'an' if vowel else 'a'} {thing}"


def _sentence_start(phrase: str) -> str:
    """Capitalise a phrase for the front of a sentence without flattening it.

    ``str.capitalize()`` would turn "an API key" into "An api key". Only the
    first character moves.
    """
    return phrase[:1].upper() + phrase[1:]


def note_for(label: str, pii_type: str, destination: Destination) -> tuple[Appropriateness, str]:
    """Return ``(fit, sentence)`` for one finding at one destination.

    ``label`` is the detector's display name and is used only as the fallback
    for a ``pii_type`` with no entry in ``_PHRASES`` — see ``_phrase``.

    The UNKNOWN sentence is the one that took the longest to word. It has to
    convey "we do not know" without either alarming someone pasting into their
    company intranet or reassuring someone pasting into a site set up an hour
    ago. It does that by declining to grade the site at all and restating the
    only thing that is certain — what the string is.
    """
    fit = appropriateness(pii_type, destination.kind)
    thing = _phrase(label, pii_type)

    if fit is Appropriateness.NEVER:
        return fit, f"{destination.name} is not a place {thing} belongs."
    if fit is Appropriateness.RARELY:
        return fit, f"{_sentence_start(thing)} is rarely something {destination.name} needs."
    if fit is Appropriateness.EXPECTED:
        return fit, f"{_sentence_start(thing)} is a normal thing to enter on {destination.name}."

    if destination.recognised:
        # Recognised site, unrecognised PII type. Name the site anyway — it is
        # information the user can act on even when we cannot grade the pair.
        return fit, (
            f"SentinelAI cannot say whether {thing} belongs on {destination.name}. "
            "Check that you meant to send it."
        )
    return fit, (
        f"SentinelAI does not recognise {destination.name}, so it cannot say whether "
        f"{thing} belongs here. That is not the same as it being safe."
    )
