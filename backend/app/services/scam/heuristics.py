"""Conversation heuristics — the deterministic half of Module 11.

Module 3 reads a document. This module reads a *conversation*, and the
difference is not cosmetic. An email arrives complete: a sender line, a subject,
a body, links, a signature. A chat scam arrives as fourteen messages of small
talk followed by one sentence that costs someone their savings. The signal is
almost never in any single message; it is in a **pair of facts spread across
several of them** — a large sum offered here, a small action required there.

So the unit of analysis is the joined conversation, not the message, and every
rule below is a proximity rule over that joined text.

Three constraints shape everything here:

**Only incoming messages are ever examined.** What the user typed is Module 1's
job. Scanning it here would double-warn on one action, and a user warned twice
about one thing learns to dismiss both. ``incoming_text`` is the only way text
reaches a pattern in this file, and it drops outgoing messages before anything
else happens — before the heuristics, before the prompt, before the network.

**Evidence is a literal substring of the input, always.** Chat text is
attacker-authored by definition; it is strictly more hostile than the pasted
email of Module 3, because the attacker is watching the conversation and can
adapt. Every quote this module emits is a raw slice of the message that produced
it. It is never reassembled, never normalised, never paraphrased — so a quote
the user does not recognise cannot be produced at all.

**Nothing here is stored.** See ``routers/scam.py``: there is no database
session in the signature, and that absence is the enforcement.

Signal families are reimplemented from the fraud patterns documented in RBI and
CERT-In public advisories and the APWG trends reports already cited in
``phishing/heuristics.py``. No corpus is redistributed and none is needed: these
scripts are public precisely because the agencies want them recognised.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from app.services.phishing.heuristics import Hit, GroupResult, combine, near

#: Per message. A WhatsApp message can be long; a 2,000-character one that is
#: still a message is rare, and past that it is a pasted document, which is what
#: Module 3 is for.
MAX_MESSAGE_CHARS = 2_000

#: How many messages one request may carry. Roughly a screen and a half of
#: conversation — enough for the setup and the ask, bounded so a compromised
#: content script cannot hand the backend a chat history.
MAX_MESSAGES = 40

#: Hard cap on what any regex runs over, for the same reason Module 3 has one.
MAX_CONVERSATION_CHARS = 8_000

#: Below this there is nothing to judge. Deliberately far lower than Module 3's
#: 40: "send me the otp" is fifteen characters and is the single highest-signal
#: string this module will ever see. A floor tuned for emails would refuse to
#: answer the question the feature exists to answer.
MIN_CONVERSATION_CHARS = 12

#: Quotes shown to the user. Longer than the email module's 120 because a chat
#: signal usually spans two short messages and cutting between them loses the
#: half that makes it legible.
MAX_EVIDENCE_CHARS = 140

#: How far apart two facts can sit and still count as one ask. Wider than the
#: email module's 80-character clause window, and that is the central tuning
#: decision in this file: "I'll transfer ₹50,000 to your account" and "just
#: share the OTP you receive" are usually two separate messages, so a clause
#: window would see two innocent sentences and score nothing.
_WINDOW = 220


def _pair(text: str, left: re.Pattern[str], right: re.Pattern[str]) -> re.Match[str] | None:
    """``near`` at this module's window rather than the email module's.

    A one-line wrapper so the wider window is applied in one place instead of
    being repeated — and remembered — at every call site. Calling ``near``
    directly here would silently score conversations on an 80-character clause
    window, which is the opposite of what ``_WINDOW`` above says this module does.
    """
    return near(text, left, right, window=_WINDOW)


@dataclass(frozen=True)
class Message:
    """One message in a conversation.

    ``incoming=False`` means the user wrote it. Those are dropped, not scored —
    see the module docstring.
    """

    text: str
    incoming: bool = True


def incoming_text(messages: Sequence[Message]) -> str:
    """Join what the *other* party said, and nothing else.

    The single choke point for this module's input. Every pattern below runs on
    this string, so the "outgoing messages are never scanned" rule is one line
    of code rather than a discipline applied in seven places.
    """
    parts = [m.text.strip() for m in messages[:MAX_MESSAGES] if m.incoming and m.text.strip()]
    return "\n".join(parts)[:MAX_CONVERSATION_CHARS]


def _quote(text: str, start: int, end: int) -> str:
    """A window around a match that is still a literal substring of ``text``.

    Slicing and stripping both preserve the substring property; collapsing
    whitespace would not. Module 3 collapses because an email arrives wrapped in
    HTML and the raw slice is unreadable. Here the raw slice *is* the message,
    and keeping it verbatim means the sentence on the panel is character-for-
    character the sentence in the chat window — which is the whole basis for a
    user believing the warning.
    """
    left = max(0, start - 60)
    right = min(len(text), end + 60)

    # Pull both edges in to a word boundary. A quote that opens mid-word — "ll
    # send you Rs 50,000" — reads as a machine artefact on a panel whose entire
    # purpose is to show the user a line they recognise from their own chat
    # window. Moving inward preserves the substring property; nothing is added.
    # Never past the match itself, so a long match still arrives whole.
    if left > 0:
        boundaries = [p for p in (text.find(" ", left, start), text.find("\n", left, start)) if p != -1]
        if boundaries:
            left = min(boundaries) + 1
    if right < len(text):
        boundaries = [p for p in (text.rfind(" ", end, right), text.rfind("\n", end, right)) if p != -1]
        if boundaries:
            right = max(boundaries)

    window = text[left:right].strip()
    if len(window) > MAX_EVIDENCE_CHARS:
        window = window[:MAX_EVIDENCE_CHARS]
        # Same rule at the truncation edge, and no ellipsis: a "…" would make the
        # string stop being a literal substring of the conversation, which is the
        # one property `tests/test_scam.py` checks by searching for it.
        cut = window.rfind(" ")
        if cut > MAX_EVIDENCE_CHARS // 2:
            window = window[:cut]
        window = window.rstrip()
    return window


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
#
# Written as noun/verb pairs joined by proximity rather than as single phrases,
# for the reason `phishing/heuristics.py` gives: a fixed phrase list is beaten
# by rewording, and every one of these scripts is now reworded by a language
# model before it is sent.

#: The one-time code, in every name it goes by in Indian banking apps.
_OTP_NOUNS = re.compile(
    r"\b(otps?|o\.t\.p\.?|one[-\s]?time\s+(?:password|passcode|code|pin)|"
    r"verification\s+code|confirmation\s+code|security\s+code|login\s+code|"
    r"\d[-\s]?digit\s+(?:code|pin|number)|sms\s+code|code\s+(?:you|u)\s+(?:got|received)|"
    r"upi\s+pin|m-?pin|atm\s+pin|cvv|card\s+pin)\b",
    re.IGNORECASE,
)

#: Any way of asking for something. Broad on purpose — the noun above is the
#: specific half, and specificity in both halves is how a rule misses.
_ASK_VERBS = re.compile(
    r"\b(send|share|tell|give|forward|type|enter|read\s+out|confirm|provide|paste|"
    r"reply\s+with|need|require|what(?:'s| is)|sms\s+me|whats\s?app\s+me|dictate)\b",
    re.IGNORECASE,
)

#: Money, written the way people actually write it in an Indian chat.
_LARGE_SUM = re.compile(
    r"(?:₹|rs\.?|inr|\$)\s?\d[\d,\s]{2,}"
    r"|\b\d+(?:\.\d+)?\s*(?:k|lakh|lakhs|lac|lacs|crore|crores)\b"
    r"|\b\d{1,3}(?:,\d{2,3})+\b",
    re.IGNORECASE,
)

#: Somebody claiming money is coming *to* you. The direction matters: this is
#: what separates an advance-fee script from an ordinary invoice.
_OFFER = re.compile(
    r"\b(i\s?(?:'|a)?m\s+send(?:ing)?|i\s+will\s+send|i\s+will\s+transfer|will\s+transfer\s+you|"
    r"transferr?(?:ing)?\s+(?:you|to\s+you)|sending\s+you|credit(?:ed)?\s+to\s+your|"
    r"you\s+(?:have\s+)?won|you\s+are\s+(?:the\s+)?(?:winner|selected)|lottery|jackpot|"
    r"prize|reward\s+of|refund\s+of|inheritance|compensation|"
    r"cash\s?back\s+of|claim\s+your)\b",
    re.IGNORECASE,
)

#: The small thing you must do first. The tell of an advance-fee scam is not the
#: large sum — it is that a large sum is gated behind a small one.
_SMALL_ACTION = re.compile(
    r"\b(processing\s+fee|registration\s+fee|activation\s+fee|convenience\s+fee|small\s+fee|"
    r"gst\s+(?:amount|charges?|payment)|customs\s+(?:duty|fee|clearance|charges?)|"
    r"clearance\s+(?:fee|charges?)|token\s+(?:amount|money)|security\s+deposit|"
    r"just\s+(?:pay|send|share|tell|give|transfer)|first\s+(?:pay|send|transfer)|"
    r"only\s+(?:₹|rs\.?)\s?\d|refundable\s+amount)\b",
    re.IGNORECASE,
)

#: UPI virtual payment addresses. The handle list is the NPCI-published set of
#: live PSP suffixes, hand-entered — about twenty of the ones a person actually
#: sees. Anchoring on real handles rather than on `something@something` keeps an
#: email address from being read as a payment request.
_UPI_VPA = re.compile(
    r"\b[a-z0-9][a-z0-9._-]{1,}@"
    r"(?:ok(?:hdfcbank|icici|axis|sbi)|ybl|ibl|axl|paytm|apl|upi|airtel|freecharge|"
    r"fbl|jupiteraxis|abfspay|kotak|indus|barodampay|yesbank|hdfcbank|icici|axisbank|sbi)\b",
    re.IGNORECASE,
)

#: Verbs only. The names of the rails themselves — ``upi``, ``gpay``,
#: ``phonepe``, ``paytm`` — were here and had to come out: "my upi is
#: ravi@okhdfcbank" contains the word ``upi`` immediately beside a VPA, so the
#: pattern satisfied its own proximity requirement and turned every person who
#: shares their payment ID into a suspected fraud. A rail name says which rail;
#: only a verb says someone is asking you to move money along it.
_PAY_VERBS = re.compile(
    r"\b(pay|paying|send|sending|transfer|transferring|deposit|remit|scan|"
    r"credit\s+(?:it|this|the\s+amount)|make\s+the\s+payment)\b",
    re.IGNORECASE,
)

#: Bodies people are frightened of, and the language of coercion they use. Two
#: separate patterns joined by proximity: "police" in a chat is a word, and
#: "police" beside "arrest warrant" is a script.
_AUTHORITY = re.compile(
    r"\b(cbi|c\.b\.i\.?|police|cyber\s+(?:cell|crime|police)|crime\s+branch|narcotics|"
    r"enforcement\s+directorate|\bed\s+department|income\s+tax\s+department|"
    r"customs\s+(?:department|officer|official)|trai|trai\s+officer|rbi|reserve\s+bank|"
    r"court|magistrate|advocate\s+general|embassy|fedex\s+(?:security|legal))\b",
    re.IGNORECASE,
)
_COERCE = re.compile(
    r"\b(arrest(?:ed|ing)?|warrant|non[-\s]?bailable|fir\b|summons?|custody|remand|"
    r"digital\s+arrest|investigation|seiz(?:e|ed|ure)|freeze|frozen|"
    r"money\s+laundering|illegal\s+(?:parcel|package|activity)|penalty|fine\s+of|"
    r"legal\s+action|case\s+(?:against|registered|filed))\b",
    re.IGNORECASE,
)

#: Task and job scams. The recruitment half.
_JOB = re.compile(
    r"\b(part[-\s]?time\s+(?:job|work)|work\s+from\s+home|home\s+based\s+job|"
    r"daily\s+(?:task|income|earning|payout)|simple\s+tasks?|prepaid\s+tasks?|"
    r"like\s+and\s+subscribe|rate\s+(?:the|our|this)\s+(?:hotel|product|video|app)|"
    r"no\s+experience\s+(?:needed|required)|hiring\s+(?:for|now)|"
    r"join\s+(?:our|the|this)\s+(?:telegram|whats\s?app)\s+group)\b",
    re.IGNORECASE,
)
#: The earnings half. Required nearby, because "work from home" on its own is
#: a description of most people's Tuesday.
_EARNINGS = re.compile(
    r"(?:₹|rs\.?|inr)\s?\d|\bper\s+day\b|\bdaily\s+(?:income|payout|salary)\b|"
    r"\bsalary\b|\bcommission\b|\bearn\b|\bincome\b|\bpayout\b",
    re.IGNORECASE,
)

#: Moving the conversation somewhere with no record and no moderation.
_OFF_PLATFORM = re.compile(
    r"\b(?:message|msg|contact|reach|add|ping|dm|text|chat|talk|continue)\s+(?:me|us)\s+on\s+"
    r"(?:whats\s?app|telegram|signal|wechat|instagram|hangouts|wickr)\b"
    r"|\bjoin\s+(?:this|our|the)\s+(?:telegram|whats\s?app)\b"
    r"|\bt\.me/|\bwa\.me/|\bchat\.whatsapp\.com/",
    re.IGNORECASE,
)

#: Secrecy. Almost uniquely diagnostic: there is no ordinary reason for a
#: stranger to ask you not to tell your family about a money transfer, and the
#: phrasing below is narrow enough that it does not fire on a surprise party.
_SECRECY = re.compile(
    r"\b(do\s?n[o']?t\s+tell\s+(?:anyone|anybody|your\s+(?:family|husband|wife|son|"
    r"daughter|parents|children))|keep\s+(?:this|it)\s+(?:a\s+)?secret|"
    r"strictly\s+confidential|between\s+us\s+only|"
    r"do\s?n[o']?t\s+(?:inform|involve|call)\s+(?:the\s+)?(?:police|bank|anyone)|"
    r"stay\s+on\s+(?:the\s+)?(?:video\s+)?(?:call|line)|"
    r"do\s?n[o']?t\s+(?:disconnect|hang\s+up|end\s+the\s+call))\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# The group
# ---------------------------------------------------------------------------


def analyse_conversation(messages: Sequence[Message]) -> GroupResult:
    """Score what the other party is trying to get the user to do.

    Always available when there is text: "we read the conversation and found no
    scam pattern" is a real answer. It becomes unavailable only when there was
    nothing incoming to read, which is a different fact and is reported as one.
    """
    text = incoming_text(messages)
    if len(text) < MIN_CONVERSATION_CHARS:
        return GroupResult(
            available=False,
            penalty=0,
            hits=(),
            detail=(
                "There was not enough of the other person's messages to judge the "
                "conversation."
            ),
        )

    hits: list[Hit] = []

    def add(name: str, penalty: int, detail: str, match: re.Match[str] | None) -> None:
        evidence = _quote(text, match.start(), match.end()) if match is not None else None
        hits.append(Hit(name=name, penalty=penalty, detail=detail, evidence=evidence))

    # -- the one that matters most -------------------------------------------
    # Placed first because it is the only signal in this file that is sufficient
    # on its own. Everything else is context; this is a confession.
    otp = _pair(text, _OTP_NOUNS, _ASK_VERBS)
    if otp:
        add(
            "otp_solicitation",
            95,
            "Someone in this chat is asking you for a one-time code or PIN. No bank, "
            "no company, and no delivery service ever needs it. The only person a code "
            "helps is the person asking for it.",
            otp,
        )

    # -- a large sum offered, a small one required ---------------------------
    offer = _pair(text, _OFFER, _LARGE_SUM)
    if offer and (_SMALL_ACTION.search(text) or otp):
        add(
            "advance_fee",
            85,
            "A large amount of money is being offered, but only after you do something "
            "small first — a fee, a code, or a transfer. That order is the scam: the "
            "small thing is real and the large thing never arrives.",
            offer,
        )

    # -- someone frightening claiming to be someone official -----------------
    authority = _pair(text, _AUTHORITY, _COERCE)
    if authority:
        add(
            "authority_impersonation",
            80,
            "This chat claims to be from the police, a court, customs, or a similar "
            "office, and threatens you with a case or an arrest. Real agencies do not "
            "open cases over chat, and they never settle them for a payment.",
            authority,
        )

    # -- a job that pays you to do nothing -----------------------------------
    job = _pair(text, _JOB, _EARNINGS)
    if job:
        add(
            "job_task_scam",
            70,
            "This offers easy paid work — small tasks, ratings, or likes — for daily "
            "money. These start by paying you a little, then ask you to deposit your "
            "own money to unlock more.",
            job,
        )

    # -- pay this UPI ID ------------------------------------------------------
    # Requires a payment verb nearby. A UPI ID on its own is how people split a
    # restaurant bill, and alarming on that would make the extension unusable in
    # the country it is built for.
    vpa = _pair(text, _UPI_VPA, _PAY_VERBS)
    if vpa:
        add(
            "payment_rail_ask",
            60,
            "You are being asked to pay a UPI ID. Money sent to a UPI ID cannot be "
            "recalled, and the name your app shows is chosen by whoever registered it — "
            "it is not proof of who they are.",
            vpa,
        )

    # -- don't tell anyone ----------------------------------------------------
    secrecy = _SECRECY.search(text)
    if secrecy:
        add(
            "urgency_secrecy",
            55,
            "You are being asked to keep this quiet or to stay on the line. Scams need "
            "you not to check with anyone, because one question to a family member or "
            "your bank ends them.",
            secrecy,
        )

    # -- come talk to me somewhere else --------------------------------------
    off_platform = _OFF_PLATFORM.search(text)
    if off_platform:
        add(
            "off_platform_migration",
            50,
            "You are being moved to another app or a private group. That is where the "
            "conversation stops being seen by anyone who could warn you, and where "
            "nothing you are told can be traced afterwards.",
            off_platform,
        )

    if hits:
        # Breadth bump of 10 — the highest in the project, and deliberately so.
        # These signals are individually weak and jointly conclusive: an offer of
        # money is a lottery text, an offer of money plus secrecy plus a UPI ID
        # is a fraud in progress, and the arithmetic has to say so before the
        # last message arrives rather than after.
        return GroupResult(True, combine(hits, 10), tuple(hits), "")

    return GroupResult(
        True,
        0,
        (),
        "Nothing in these messages matches a known scam script.",
    )
