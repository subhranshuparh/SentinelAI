"""Site-trust tests.

Two clusters carry the weight here.

**False positives**, same discipline as the PII detectors: ``amazonaws.com``
contains "amazon" and must stay silent, or every AWS-hosted page in the world
gets a red badge and the extension is uninstalled by lunchtime.

**Missing signals**, which is the harder and more important one. A security tool
that reports "safe" when it could not check anything is worse than no tool. The
``TestUnknownIsNotSafe`` class asserts that it cannot.

Nothing here makes a network call: RDAP and Safe Browsing are monkeypatched, so
the scoring logic is verified in milliseconds and stays verified offline.
"""

from __future__ import annotations

import pytest

from app.core.cache import TTLCache
from app.services.site.brand import check_brand, registrable_domain
from app.services.site.engine import clear_cache, evaluate
from app.services.site.safebrowsing import strip_sensitive_parts


@pytest.fixture(autouse=True)
def _clean_cache():
    """Six-hour caching would otherwise leak verdicts between tests."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch):
    """Both network signals unavailable — the hotel-wifi case."""
    monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: None)
    monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: None)


@pytest.fixture
def signals(monkeypatch: pytest.MonkeyPatch):
    """Factory: pin both network signals to chosen values."""

    def _apply(sb: tuple[bool, list[str]] | None, age: int | None):
        monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: sb)
        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: age)

    return _apply


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("mail.google.com", "google.com"),
            ("google.com", "google.com"),
            ("login.secure.amazon-verify.co.in", "amazon-verify.co.in"),
            ("www.hdfcbank.com", "hdfcbank.com"),
            ("sub.domain.example.co.uk", "example.co.uk"),
            ("localhost", "localhost"),
        ],
    )
    def test_reduces_to_what_was_registered(self, host: str, expected: str) -> None:
        assert registrable_domain(host) == expected

    def test_subdomains_belong_to_whoever_registered_the_domain(self) -> None:
        """`amazon.attacker.com` is an attacker domain and must be judged as one."""
        assert registrable_domain("amazon.attacker.com") == "attacker.com"


class TestBrandFalsePositives:
    """The tests that decide whether this module is trusted or muted."""

    @pytest.mark.parametrize(
        "host",
        [
            "amazonaws.com",          # contains "amazon" — but as part of one token
            "s3.amazonaws.com",
            "amazonia-travel.com",    # a real word that starts with the brand
            "www.amazon.in",          # the brand, on its own domain
            "mail.google.com",
            "smart-apple-orchard.com",  # "apple" here is fruit
            "pnbindia.in",
            "onlinesbi.sbi",
        ],
    )
    def test_legitimate_hosts_stay_silent(self, host: str) -> None:
        assert check_brand(host).mismatch is False

    def test_official_domain_is_not_flagged_for_a_second_brand_token(self) -> None:
        """`pay.google.com` mentions no other brand; `paypal.google.com` would.

        An official domain must never be reported because some other token in
        the hostname resembled a different brand.
        """
        assert check_brand("accounts.google.com").mismatch is False


class TestBrandTruePositives:
    @pytest.mark.parametrize(
        "host,brand",
        [
            ("amazon-login-security.xyz", "amazon"),
            ("secure-paypal-verify.com", "paypal"),
            ("hdfc-netbanking-update.info", "hdfc"),
            ("uidai-aadhaar-kyc.top", "uidai"),
            ("amazon.attacker.com", "amazon"),
        ],
    )
    def test_impersonation_is_caught(self, host: str, brand: str) -> None:
        result = check_brand(host)
        assert result.mismatch is True
        assert result.brand == brand
        assert result.reasons, "a mismatch with no explanation is a bare verdict"

    @pytest.mark.parametrize("host", ["paypa1.com", "g00gle.com", "arnazon-deals.com"])
    def test_lookalike_spellings_are_caught_and_ranked_worse(self, host: str) -> None:
        """Nobody registers `arnazon` by accident, so this outranks a plain mismatch."""
        result = check_brand(host)
        assert result.mismatch is True
        assert result.lookalike is True

    def test_lure_words_are_reported_separately(self) -> None:
        result = check_brand("sbi-account-verify.xyz")
        assert "verify" in result.lures
        assert len(result.reasons) == 2, "the lure deserves its own sentence"


class TestPrivacy:
    """The Safe Browsing promise: query strings never leave this process."""

    def test_query_and_fragment_are_stripped(self) -> None:
        url = "https://bank.example.com/reset?token=SECRET123&email=a@b.com#otp=999"
        stripped = strip_sensitive_parts(url)
        assert "SECRET123" not in stripped
        assert "a@b.com" not in stripped
        assert "999" not in stripped

    def test_path_is_kept_because_phishing_lives_on_paths(self) -> None:
        assert strip_sensitive_parts("https://sites.google.com/view/scam?x=1") == (
            "https://sites.google.com/view/scam"
        )


class TestVerdicts:
    def test_safe_browsing_hit_overrides_everything(self, signals) -> None:
        """A ten-year-old domain actively serving malware is not 'medium risk'."""
        signals((True, ["phishing — a fake page built to steal your details"]), 4000)
        result = evaluate("https://compromised-but-old.com/login")
        assert result.verdict == "dangerous"
        assert result.trust_score < 10
        assert result.summary

    def test_new_domain_plus_brand_mismatch_is_dangerous(self, signals) -> None:
        signals((False, []), 4)
        result = evaluate("https://amazon-login-security.xyz/signin")
        assert result.verdict == "dangerous"
        assert result.brand_mismatch is True
        assert any("4 days ago" in r.detail for r in result.reasons)

    def test_established_clean_domain_is_safe(self, signals) -> None:
        signals((False, []), 5000)
        result = evaluate("https://www.wikipedia.org/wiki/Main_Page")
        assert result.verdict == "safe"
        assert result.trust_score >= 75

    def test_young_but_otherwise_clean_domain_is_only_suspicious(self, signals) -> None:
        """A new domain is a reason to be careful, not an accusation."""
        signals((False, []), 20)
        result = evaluate("https://my-new-startup-blog.com/")
        assert result.verdict == "suspicious"
        assert result.brand_mismatch is False


class TestImpersonationOutranksABlocklistMiss:
    """A clean blocklist result must not soften a hostname that spells the fraud out."""

    def test_brand_plus_lure_is_dangerous_even_with_clean_safe_browsing(self, signals) -> None:
        """The live-run regression: this scored 64/'suspicious' before the cap."""
        signals((False, []), None)
        result = evaluate("https://amazon-login-security.xyz/signin")
        assert result.verdict == "dangerous"
        assert result.trust_score <= 25

    def test_lookalike_alone_is_enough(self, signals) -> None:
        signals((False, []), 4000)
        result = evaluate("https://paypa1.com/login")
        assert result.verdict == "dangerous"

    def test_bare_brand_token_stays_merely_suspicious(self, signals) -> None:
        """`amazon-fanclub.net` is unofficial, not an attack. Do not overclaim."""
        signals((False, []), 4000)
        result = evaluate("https://amazon-fanclub.net/")
        assert result.brand_mismatch is True
        assert result.verdict == "suspicious"

    def test_summary_never_contradicts_the_evidence(self, signals) -> None:
        """"No problems found" above a listed problem is how a tool loses trust."""
        signals((False, []), 4000)
        result = evaluate("https://amazon-fanclub.net/")
        assert "no problems found" not in result.summary.lower()
        assert any(r.weight == "bad" for r in result.reasons)

    def test_the_cap_does_not_hide_the_other_evidence(self, signals) -> None:
        signals((False, []), 4000)
        result = evaluate("https://hdfc-verify-account.top/")
        signal_names = {r.signal for r in result.reasons}
        assert {"brand", "safe_browsing", "domain_age"} <= signal_names


class TestBlocklistLag:
    """"Not on Google's list" is worth less when the domain may be hours old."""

    def test_unknown_age_does_not_earn_full_credit(self, monkeypatch) -> None:
        monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: (False, []))

        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: 4000)
        established = evaluate("https://plain-site.com/")
        clear_cache()

        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: None)
        unknown_age = evaluate("https://plain-site.com/")

        assert unknown_age.confidence < established.confidence

    def test_fresh_domain_does_not_earn_full_credit(self, signals) -> None:
        signals((False, []), 3)
        fresh = evaluate("https://brand-new-site.com/")
        clear_cache()
        signals((False, []), 4000)
        old = evaluate("https://brand-new-site.com/")
        assert fresh.confidence < old.confidence


class TestUnknownIsNotSafe:
    """The rule the roadmap calls out by name: a missing signal is never a pass."""

    def test_both_network_signals_down_yields_unknown(self, offline) -> None:
        result = evaluate("https://some-ordinary-site.com/")
        assert result.verdict == "unknown"
        assert result.confidence <= 0.35

    def test_unknown_never_publishes_a_reassuring_score(self, offline) -> None:
        result = evaluate("https://some-ordinary-site.com/")
        assert result.trust_score <= 50

    def test_failed_checks_are_shown_not_hidden(self, offline) -> None:
        result = evaluate("https://some-ordinary-site.com/")
        skipped = [r for r in result.reasons if r.weight == "unknown"]
        assert len(skipped) == 2, "the user must be told which checks did not run"

    def test_offline_still_catches_impersonation(self, offline) -> None:
        """The offline signal is why this module works on hotel wifi at all."""
        result = evaluate("https://icici-netbanking-verify.top/login")
        assert result.brand_mismatch is True
        assert result.verdict == "dangerous"

    def test_missing_rdap_redistributes_rather_than_voting_clean(self, monkeypatch) -> None:
        """Same site, RDAP absent vs. RDAP saying 'ancient'. The absent case must not score higher."""
        monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", lambda _u: (False, []))

        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: 4000)
        old = evaluate("https://example-site.com/")
        clear_cache()

        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: None)
        unknown = evaluate("https://example-site.com/")

        assert unknown.trust_score <= old.trust_score
        assert unknown.confidence < old.confidence


class TestExplainability:
    def test_every_verdict_carries_reasons_and_a_summary(self, signals) -> None:
        signals((False, []), 4)
        for url in [
            "https://amazon-login-security.xyz/",
            "https://www.wikipedia.org/",
            "https://not-a-brand-at-all.com/",
        ]:
            clear_cache()
            result = evaluate(url)
            assert result.summary, "a bare verdict is not allowed"
            assert result.reasons, "a verdict with no itemised reasons is not allowed"
            for reason in result.reasons:
                assert reason.detail and reason.signal

    def test_reasons_avoid_jargon(self, signals) -> None:
        """Target user is a senior citizen. 'Reputation score' means nothing to them."""
        signals((False, []), 3)
        result = evaluate("https://sbi-account-verify.xyz/")
        text = " ".join(r.detail for r in result.reasons).lower()
        for jargon in ("reputation", "heuristic", "entropy", "tld", "dns"):
            assert jargon not in text

    def test_malformed_url_degrades_instead_of_raising(self) -> None:
        result = evaluate("https://")
        assert result.verdict == "unknown"
        assert result.reasons


class TestCaching:
    def test_repeat_checks_do_not_re_query_the_network(self, monkeypatch) -> None:
        """Rehearsing a demo must not burn Safe Browsing quota."""
        calls = {"sb": 0, "rdap": 0}

        def _sb(_url):
            calls["sb"] += 1
            return False, []

        def _rdap(_domain):
            calls["rdap"] += 1
            return 4000

        monkeypatch.setattr("app.services.site.engine.safe_browsing_lookup", _sb)
        monkeypatch.setattr("app.services.site.engine.domain_age_days", _rdap)

        for _ in range(20):
            evaluate("https://example.com/page")

        assert calls == {"sb": 1, "rdap": 1}

    def test_different_paths_are_cached_separately(self, monkeypatch) -> None:
        """Two pages on one host can carry different Safe Browsing verdicts."""
        seen = []
        monkeypatch.setattr(
            "app.services.site.engine.safe_browsing_lookup",
            lambda url: seen.append(url) or (False, []),
        )
        monkeypatch.setattr("app.services.site.engine.domain_age_days", lambda _d: 4000)

        evaluate("https://sites.google.com/view/a")
        evaluate("https://sites.google.com/view/b")
        assert len(seen) == 2


class TestTTLCache:
    def test_expired_entries_are_not_returned(self) -> None:
        cache = TTLCache()
        cache.set("k", "v", ttl=-1)
        assert cache.get("k") is None

    def test_live_entries_are_returned(self) -> None:
        cache = TTLCache()
        cache.set("k", "v", ttl=60)
        assert cache.get("k") == "v"

    def test_size_is_bounded(self) -> None:
        cache = TTLCache(max_entries=10)
        for i in range(50):
            cache.set(f"k{i}", i, ttl=60)
        assert len(cache._data) <= 10
