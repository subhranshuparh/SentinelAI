"""Module 10 — Clipboard Guardian.

Three things are under test, in increasing order of how badly they would fail
in the demo:

1. the origin table and the fit matrix, which are ordinary pure functions;
2. the endpoint contract — specifically that a *typed* scan leaves the
   destination fields null rather than filling them with a cheerful default;
3. the seam between `extension/content/clipboard.js` and `detectors.py`. That
   one is the reason this file reads a JavaScript source from Python. The
   extension blocks a paste synchronously on a hard-coded prefix list; if
   someone adds a provider to the backend and not the extension, or removes one
   from the backend that the extension still blocks, the product starts holding
   pastes it cannot explain. Nothing else in the suite would notice.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.pii.destinations import (
    _FAMILIES,
    _PHRASES,
    Appropriateness,
    Destination,
    DestinationClass,
    appropriateness,
    classify,
    note_for,
)
from app.services.pii.detectors import DETECTORS, API_KEY_PREFIXES, JWT_PREFIX, scan_text
from app.services.pii.engine import assess_destination, scan

# A key-shaped string that is not a real credential: the AKIA prefix followed by
# sixteen characters that spell out what it is. Used throughout so a reader of a
# failure message can tell instantly that nothing real leaked into the repo.
FAKE_AWS_KEY = "AKIANOTAREALKEY01234"


class TestClassify:
    def test_an_exact_host_is_found(self):
        assert classify("https://discord.com").name == "Discord"

    def test_a_subdomain_falls_back_to_its_parent(self):
        result = classify("https://canary.discord.com")
        assert result.kind is DestinationClass.CHAT
        assert result.name == "Discord"

    def test_the_more_specific_entry_wins(self):
        # Both web.whatsapp.com and whatsapp.com are in the table, and the
        # display name differs. The user is on the web client, so say so.
        assert classify("https://web.whatsapp.com").name == "WhatsApp Web"
        assert classify("https://www.whatsapp.com").name == "WhatsApp"

    def test_a_lookalike_domain_is_not_the_real_one(self):
        # The entire reason the walk is by label rather than by `endswith`. A
        # substring match would classify this as Discord and hand a phishing
        # site a reassuring sentence with a real brand name in it.
        assert classify("https://evil-discord.com").kind is DestinationClass.UNKNOWN
        assert classify("https://notgithub.com").kind is DestinationClass.UNKNOWN

    def test_a_bare_tld_is_never_looked_up(self):
        assert classify("https://com").kind is DestinationClass.UNKNOWN

    def test_case_port_and_path_are_tolerated(self):
        for value in (
            "https://Discord.com",
            "https://discord.com:443",
            "https://discord.com/channels/1/2",
            "discord.com",
        ):
            assert classify(value).name == "Discord", value

    def test_an_unrecognised_origin_is_unknown_not_safe(self):
        result = classify("https://some-intranet.example")
        assert result.kind is DestinationClass.UNKNOWN
        assert result.recognised is False

    def test_empty_input_does_not_raise(self):
        assert classify("").kind is DestinationClass.UNKNOWN

    def test_localhost_is_a_developer_console(self):
        assert classify("http://localhost:3000").kind is DestinationClass.CLOUD_CONSOLE


class TestAppropriateness:
    def test_a_credential_never_belongs_in_a_chat_app(self):
        assert appropriateness("api_key", DestinationClass.CHAT) is Appropriateness.NEVER

    def test_a_credential_is_expected_in_a_cloud_console(self):
        # The case the whole module exists for: same string, opposite verdict.
        assert (
            appropriateness("api_key", DestinationClass.CLOUD_CONSOLE)
            is Appropriateness.EXPECTED
        )

    def test_a_credential_on_a_code_host_is_never_not_merely_rare(self):
        # Committing a secret to GitHub is one of the largest single causes of
        # credential compromise there is. A reputable domain does not soften it.
        assert appropriateness("api_key", DestinationClass.CODE_HOST) is Appropriateness.NEVER

    def test_aadhaar_is_expected_at_a_bank_and_never_on_social(self):
        assert (
            appropriateness("aadhaar", DestinationClass.TRUSTED_FINANCE)
            is Appropriateness.EXPECTED
        )
        assert appropriateness("aadhaar", DestinationClass.SOCIAL) is Appropriateness.NEVER

    def test_an_email_address_in_a_chat_app_is_normal(self):
        # The calibration test. If this ever returns NEVER the product starts
        # interrupting people for typing their own email address to a friend,
        # and it will be uninstalled by lunchtime.
        assert appropriateness("email", DestinationClass.CHAT) is Appropriateness.EXPECTED

    def test_an_unknown_destination_grades_nothing(self):
        for pii_type in ("api_key", "aadhaar", "email", "coordinates"):
            assert (
                appropriateness(pii_type, DestinationClass.UNKNOWN) is Appropriateness.UNKNOWN
            ), pii_type

    def test_an_unfamiliar_pii_type_grades_nothing(self):
        # Tier 2 invents types this table has never seen. Guessing a grade for
        # them would be exactly the fabrication this module avoids.
        assert (
            appropriateness("home_address", DestinationClass.CHAT) is Appropriateness.UNKNOWN
        )

    def test_every_family_covers_every_real_class(self):
        # A missing cell would silently return UNKNOWN and read as "we didn't
        # check", when the truth would be "we forgot".
        real = [c for c in DestinationClass if c is not DestinationClass.UNKNOWN]
        for pii_type in ("api_key", "aadhaar", "credit_card", "email", "dob"):
            for kind in real:
                assert (
                    appropriateness(pii_type, kind) is not Appropriateness.UNKNOWN
                ), f"{pii_type} x {kind.value}"


class TestTheSentence:
    def test_never_names_the_site(self):
        fit, sentence = note_for("API Key / Secret", "api_key", classify("https://discord.com"))
        assert fit is Appropriateness.NEVER
        assert "Discord" in sentence
        assert "api key" in sentence.lower()

    def test_unknown_says_so_and_refuses_to_reassure(self):
        _, sentence = note_for("API Key / Secret", "api_key", classify("https://nowhere.example"))
        lowered = sentence.lower()
        assert "does not recognise" in lowered
        assert "not the same as it being safe" in lowered
        # The words that would turn a non-answer into a clean bill of health.
        for word in ("safe to", "fine", "no problem", "looks good"):
            assert word not in lowered.replace("not the same as it being safe", "")

    def test_expected_is_calm(self):
        fit, sentence = note_for(
            "API Key / Secret", "api_key", classify("https://console.aws.amazon.com")
        )
        assert fit is Appropriateness.EXPECTED
        assert "normal thing to enter" in sentence
        assert "AWS Console" in sentence

    def test_a_recognised_site_is_still_named_for_an_ungradeable_type(self):
        _, sentence = note_for("Home Address", "home_address", classify("https://discord.com"))
        assert "Discord" in sentence

    @pytest.mark.parametrize("origin", ["https://discord.com", "https://nowhere.example"])
    def test_every_sentence_is_a_sentence(self, origin):
        for fit in (Appropriateness.NEVER, Appropriateness.UNKNOWN):
            _, sentence = note_for("API Key / Secret", "api_key", classify(origin))
            assert sentence.endswith(".")
            assert len(sentence) > 20
            assert fit is not None


class TestTheSentenceReadsLikeEnglish:
    """The copy is the product here.

    This panel interrupts someone mid-paste and is aimed at readers who are not
    fluent in security jargon — the same audience the whole UI is written for.
    "Discord is not a place a api key / secret belongs" fails that audience
    twice: it is ungrammatical, and it has lower-cased the acronym that was the
    only part they recognised. Both are cheap to regress and invisible in a test
    suite that only ever asserts a substring, so they are asserted directly.
    """

    #: Every origin class, one representative each, so a wording change is
    #: checked against all four sentence templates rather than one.
    ORIGINS = [
        "https://discord.com",            # NEVER for a credential
        "https://console.aws.amazon.com",  # EXPECTED / RARELY
        "https://nowhere.example",         # UNKNOWN, unrecognised site
    ]

    def test_every_detector_has_a_written_phrase(self):
        # The fallback exists for Tier-2 types, not as a resting place for a
        # detector someone forgot. A new detector should fail here.
        assert {d.name for d in DETECTORS} == set(_PHRASES)

    def test_phrases_and_families_describe_the_same_types(self):
        assert set(_PHRASES) == set(_FAMILIES)

    @pytest.mark.parametrize("origin", ORIGINS)
    def test_every_sentence_carries_the_written_phrase_verbatim(self, origin):
        # The strongest available check, and the reason it is phrased this way
        # rather than as a regex over articles: English picks "a" or "an" by
        # sound, so any rule a test could encode would be the same rule the
        # module deliberately refused to encode. The table is the ground truth,
        # so the test compares against the table.
        destination = classify(origin)
        for detector in DETECTORS:
            article, noun = _PHRASES[detector.name]
            _, sentence = note_for(detector.label, detector.name, destination)
            phrase = f"{article} {noun}"
            capitalised = phrase[:1].upper() + phrase[1:]
            assert phrase in sentence or capitalised in sentence, sentence

    @pytest.mark.parametrize("origin", ORIGINS)
    def test_no_sentence_says_a_before_a_vowel_sound(self, origin):
        # A narrower net than the letter rule, cast only over the openings where
        # letter and sound agree. "a UPI ID" is correct and must not fail here.
        destination = classify(origin)
        for detector in DETECTORS:
            _, sentence = note_for(detector.label, detector.name, destination)
            assert not re.search(r"\b[Aa] [aeioAEIO]", sentence), sentence

    @pytest.mark.parametrize("origin", ORIGINS)
    def test_acronyms_survive_into_the_sentence(self, origin):
        # The lower-casing bug this replaced turned these into "api key",
        # "ifsc code" and "upi id", which is not what the field is called
        # anywhere else in the product.
        destination = classify(origin)
        for pii_type, acronym in (("api_key", "API"), ("ifsc", "IFSC"),
                                  ("upi_id", "UPI"), ("pan", "PAN"),
                                  ("aadhaar", "Aadhaar")):
            label = next(d.label for d in DETECTORS if d.name == pii_type)
            _, sentence = note_for(label, pii_type, destination)
            assert acronym in sentence, sentence

    @pytest.mark.parametrize("origin", ORIGINS)
    def test_no_sentence_carries_a_slash_or_a_parenthetical(self, origin):
        # Both come from the detector labels, which are column headings. A
        # heading dropped into prose reads as a field name, which is the thing
        # the sentence exists to avoid.
        destination = classify(origin)
        for detector in DETECTORS:
            _, sentence = note_for(detector.label, detector.name, destination)
            assert "/" not in sentence, sentence
            assert "(" not in sentence, sentence

    def test_upi_takes_a_not_an(self):
        # "a UPI ID" — a vowel letter with a consonant sound, and the one case
        # a naive vowel rule gets wrong. Pinned so nobody replaces the table
        # with the rule.
        _, sentence = note_for("UPI ID", "upi_id", classify("https://discord.com"))
        assert "a UPI ID" in sentence

    def test_the_fallback_still_produces_english(self):
        # Tier 2 returns types this file has never seen.
        for label, pii_type, expected in (
            ("Home Address", "home_address", "a home address"),
            ("Employer Name", "employer", "an employer name"),
        ):
            _, sentence = note_for(label, pii_type, classify("https://discord.com"))
            assert expected in sentence, sentence

    def test_an_empty_label_does_not_produce_a_dangling_article(self):
        _, sentence = note_for("", "not_a_real_type", classify("https://discord.com"))
        assert sentence.endswith(".")
        assert " a ." not in sentence and " an ." not in sentence


class TestAssessDestination:
    def test_it_annotates_every_finding(self):
        result = assess_destination(scan_result(FAKE_AWS_KEY), "https://discord.com")
        assert result.findings
        for finding in result.findings:
            assert finding.destination_fit == "never"
            assert "Discord" in finding.destination_note

    def test_it_does_not_move_the_score(self):
        # Destination is context for the human, not an input to the arithmetic.
        # If a recognised site could lower a score, a convincing clone of a bank
        # would be able to argue its way out of a warning.
        before = scan_result(FAKE_AWS_KEY)
        after = assess_destination(before, "https://console.aws.amazon.com")
        assert after.risk_score == before.risk_score
        assert after.risk_level == before.risk_level

    def test_it_does_not_drop_findings_from_an_appropriate_site(self):
        # "Expected" earns a calmer sentence, never silence. The extension gets
        # to decide what to do with that, and only after being told what is there.
        after = assess_destination(scan_result(FAKE_AWS_KEY), "https://console.aws.amazon.com")
        assert [f.pii_type for f in after.findings] == ["api_key"]
        assert after.findings[0].destination_fit == "expected"

    def test_an_empty_scan_survives(self):
        after = assess_destination(scan_result("nothing interesting here at all"), "https://x.example")
        assert after.findings == []
        assert after.destination is not None


def scan_result(text: str):
    """A real ScanResult, Tier 1 only — the suite makes no network calls."""
    return scan(text, enable_tier_2=False)


class TestTheEndpoint:
    def test_a_paste_scan_returns_a_destination(self, client, auth_headers):
        response = client.post(
            "/api/v1/pii/scan",
            headers=auth_headers,
            json={
                "text": f"here you go: {FAKE_AWS_KEY}",
                "site_origin": "https://discord.com",
                "field_kind": "paste",
            },
        )
        assert response.status_code == 200
        body = response.json()

        assert body["destination"] == {
            "origin": "https://discord.com",
            "name": "Discord",
            "kind": "chat",
            "kind_label": "a chat app",
            "recognised": True,
        }
        finding = body["findings"][0]
        assert finding["destination_fit"] == "never"
        assert "Discord" in finding["destination_note"]

    def test_a_typed_scan_leaves_the_destination_null(self, client, auth_headers):
        # The distinction the schema exists to draw. Null is "not assessed".
        # Anything else here would be the API asserting something it never checked.
        response = client.post(
            "/api/v1/pii/scan",
            headers=auth_headers,
            json={
                "text": f"here you go: {FAKE_AWS_KEY}",
                "site_origin": "https://discord.com",
                "field_kind": "input",
            },
        )
        body = response.json()
        assert body["destination"] is None
        assert body["findings"][0]["destination_fit"] is None
        assert body["findings"][0]["destination_note"] is None

    def test_an_unrecognised_paste_target_is_reported_as_unrecognised(self, client, auth_headers):
        response = client.post(
            "/api/v1/pii/scan",
            headers=auth_headers,
            json={
                "text": f"here you go: {FAKE_AWS_KEY}",
                "site_origin": "https://intranet.example",
                "field_kind": "paste",
            },
        )
        body = response.json()
        assert body["destination"]["recognised"] is False
        assert body["destination"]["kind"] == "unknown"
        assert body["findings"][0]["destination_fit"] == "unknown"

    def test_paste_is_recorded_as_its_own_field_kind(self, client, auth_headers):
        from app.db.models import PiiEvent
        from app.db.session import SessionLocal

        client.post(
            "/api/v1/pii/scan",
            headers=auth_headers,
            json={
                "text": f"here you go: {FAKE_AWS_KEY}",
                "site_origin": "https://discord.com",
                "field_kind": "paste",
            },
        )
        with SessionLocal() as db:
            kinds = [row.field_kind for row in db.query(PiiEvent).all()]
        assert kinds == ["paste"]

    def test_the_clipboard_text_is_not_persisted(self, client, auth_headers):
        from app.db.models import PiiEvent
        from app.db.session import SessionLocal

        client.post(
            "/api/v1/pii/scan",
            headers=auth_headers,
            json={
                "text": f"here you go: {FAKE_AWS_KEY}",
                "site_origin": "https://discord.com",
                "field_kind": "paste",
            },
        )
        with SessionLocal() as db:
            rows = db.query(PiiEvent).all()
            assert rows
            for row in rows:
                # Every column, not just the ones we expect to be clean.
                for column in row.__table__.columns:
                    value = getattr(row, column.name)
                    if isinstance(value, str):
                        assert FAKE_AWS_KEY not in value, column.name


# ---------------------------------------------------------------------------
# The anti-drift seam
# ---------------------------------------------------------------------------

CLIPBOARD_JS = (
    Path(__file__).resolve().parents[2] / "extension" / "content" / "clipboard.js"
)


def extension_prefixes() -> list[str]:
    """Extract the `prefix:` literals the extension blocks pastes on.

    Reading a sibling source file from a test is unusual and is the point. The
    two lists live in different languages, in different processes, shipped by
    different mechanisms, and there is no import that could tie them together.
    A regex over the source is the only honest way to assert they still agree.
    """
    source = CLIPBOARD_JS.read_text(encoding="utf-8")
    body = source.split("BLOCKING_PATTERNS", 1)[1].split("];", 1)[0]
    return re.findall(r"prefix:\s*'([^']+)'", body)


class TestExtensionParity:
    def test_the_file_is_where_the_test_thinks_it_is(self):
        # Guards the guard. A silently-empty extraction would make every
        # assertion below pass vacuously, which is worse than no test at all.
        assert CLIPBOARD_JS.is_file(), CLIPBOARD_JS
        assert len(extension_prefixes()) >= 10

    def test_every_blocked_prefix_is_known_to_the_backend(self):
        known = set(API_KEY_PREFIXES) | {JWT_PREFIX}
        unknown = [p for p in extension_prefixes() if p not in known]
        assert not unknown, (
            f"clipboard.js blocks pastes on {unknown}, which Tier 1 cannot name. "
            "Add them to API_KEY_PREFIXES or stop blocking on them — a held paste "
            "the backend cannot explain is a dead end for the user."
        )

    def test_the_backend_still_finds_a_key_for_every_blocked_prefix(self):
        # Parity of names is not parity of behaviour. This builds a shaped value
        # per prefix and asserts Tier 1 actually detects it, so a regex tightened
        # on one side cannot pass the set-comparison above while silently
        # rejecting everything the extension blocks.
        samples = {
            "AKIA": FAKE_AWS_KEY,
            "ASIA": "ASIANOTAREALKEY01234",
            "AIza": "AIza" + "B" * 35,
            "ghp_": "ghp_" + "c" * 36,
            "gho_": "gho_" + "c" * 36,
            "ghu_": "ghu_" + "c" * 36,
            "ghs_": "ghs_" + "c" * 36,
            "sk_l": "sk_live_" + "d" * 24,
            "sk_t": "sk_test_" + "d" * 24,
            "sk-p": "sk-proj-" + "e" * 32,
            "sk-": "sk-" + "f" * 48,
            "xoxb": "xoxb-1234567890-abcdefghij",
            "xoxp": "xoxp-1234567890-abcdefghij",
            "xoxa": "xoxa-1234567890-abcdefghij",
            "xoxs": "xoxs-1234567890-abcdefghij",
            "xoxo": "xoxo-1234567890-abcdefghij",
            "eyJ": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }
        for prefix in extension_prefixes():
            assert prefix in samples, f"no sample for {prefix!r}; add one"
            findings = scan_text(samples[prefix])
            assert findings, f"Tier 1 missed the {prefix!r} sample the extension blocks"
            assert findings[0].pii_type in {"api_key", "jwt"}

    def test_the_prefix_table_is_ordered_longest_match_first(self):
        # `sk-` would shadow `sk-p` if the order were ever sorted, and an OpenAI
        # project key would be reported as a plain OpenAI key. Cheap to assert,
        # invisible if it breaks.
        keys = list(API_KEY_PREFIXES)
        assert keys.index("sk-p") < keys.index("sk-")


class TestDestinationDataclass:
    def test_recognised_is_derived_from_the_class_not_from_the_name(self):
        unknown = Destination("https://x.example", "x.example", DestinationClass.UNKNOWN, "…")
        assert unknown.recognised is False
        known = Destination("https://discord.com", "Discord", DestinationClass.CHAT, "a chat app")
        assert known.recognised is True
