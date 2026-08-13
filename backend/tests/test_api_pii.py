"""End-to-end tests for POST /api/v1/pii/scan.

These assert the *contract* the Chrome extension will code against — status
codes, field presence, and the two privacy guarantees (no raw text persisted,
origin truncated). Getting them wrong here means debugging them through a
content script in Phase 2, which is far slower.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import PiiEvent
from app.db.session import SessionLocal
from app.services.pii.checksums import verhoeff_checksum_digit

from .conftest import DEVICE_ID


def make_aadhaar(prefix: str = "22345678901") -> str:
    number = prefix + str(verhoeff_checksum_digit(prefix))
    return f"{number[:4]} {number[4:8]} {number[8:]}"


def scan(client: TestClient, headers: dict, text: str, **kwargs):
    body = {"text": text, "site_origin": "https://mail.google.com", "field_kind": "contenteditable"}
    body.update(kwargs)
    return client.post("/api/v1/pii/scan", json=body, headers=headers)


class TestHealth:
    def test_reports_tiers_without_leaking_keys(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["tiers"]["regex"] is True
        # Capability booleans only — no key material anywhere in the payload.
        assert "key" not in str(body).lower()


class TestAuth:
    def test_missing_device_header_is_401(self, client: TestClient) -> None:
        assert scan(client, {}, "hello").status_code == 401

    def test_malformed_device_header_is_401(self, client: TestClient) -> None:
        response = scan(client, {"X-Sentinel-Device-Id": "bad id\nwith newline"}, "hello")
        assert response.status_code == 401


class TestScanContract:
    def test_aadhaar_full_response_shape(self, client: TestClient, auth_headers: dict) -> None:
        response = scan(client, auth_headers, f"My Aadhaar is {make_aadhaar()}")
        assert response.status_code == 200

        body = response.json()
        assert body["risk_level"] in {"low", "medium", "high", "critical"}
        assert 0 <= body["risk_score"] <= 100
        # Tier 2 has no key in tests, so it is "disabled" — deliberately NOT
        # "unavailable". The boolean stays true because nothing was lost: a tier
        # that was never meant to run has not failed, and the extension must not
        # show "couldn't fully check" for a configuration the user chose.
        assert body["tier_2_status"] == "disabled"
        assert body["tier_2_available"] is True

        finding = next(f for f in body["findings"] if f["pii_type"] == "aadhaar")
        # The explainability contract, asserted field by field.
        for required in ("reason", "explanation", "recommendation", "confidence", "detection_tier"):
            assert finding[required], f"{required} must be present and non-empty"
        assert finding["confidence"] >= 0.9
        assert finding["masked_preview"].startswith("XXXX")

    def test_clean_text_is_200_not_404(self, client: TestClient, auth_headers: dict) -> None:
        """'Nothing found' is success. A 404 would look identical to 'broken'."""
        response = scan(client, auth_headers, "Hi, see you on Friday!")
        assert response.status_code == 200
        assert response.json()["findings"] == []
        assert response.json()["risk_score"] == 0

    def test_empty_text_is_accepted(self, client: TestClient, auth_headers: dict) -> None:
        assert scan(client, auth_headers, "").status_code == 200

    def test_oversized_text_is_rejected(self, client: TestClient, auth_headers: dict) -> None:
        assert scan(client, auth_headers, "a" * 20_001).status_code == 422

    def test_spans_slice_the_submitted_text(self, client: TestClient, auth_headers: dict) -> None:
        """Masking writes back using these offsets, so they must be exact."""
        text = f"My Aadhaar is {make_aadhaar()} thanks"
        finding = scan(client, auth_headers, text).json()["findings"][0]
        assert text[finding["start"] : finding["end"]] == make_aadhaar()

    def test_suppressed_type_is_absent_from_response(self, client: TestClient, auth_headers: dict) -> None:
        text = "call 9876543210 or mail a@b.com"
        assert {f["pii_type"] for f in scan(client, auth_headers, text).json()["findings"]} == {
            "phone",
            "email",
        }
        response = scan(client, auth_headers, text, suppressed_types=["phone"])
        assert {f["pii_type"] for f in response.json()["findings"]} == {"email"}

    def test_severity_dominates_volume(self, client: TestClient, auth_headers: dict) -> None:
        """Ten emails must not outrank one leaked credential."""
        many_low = scan(client, auth_headers, " ".join(f"a{i}@b.com" for i in range(10)))
        one_critical = scan(client, auth_headers, "AKIA1234567890ABCDEF")
        assert one_critical.json()["risk_score"] > many_low.json()["risk_score"]

    def test_score_and_level_never_disagree(self, client: TestClient, auth_headers: dict) -> None:
        body = scan(client, auth_headers, "AKIA1234567890ABCDEF").json()
        assert body["risk_score"] >= 85 and body["risk_level"] == "critical"


class TestPrivacyGuarantees:
    """The two promises the whole project rests on."""

    def test_raw_pii_is_never_persisted(self, client: TestClient, auth_headers: dict) -> None:
        aadhaar = make_aadhaar()
        scan(client, auth_headers, f"My Aadhaar is {aadhaar}")

        with SessionLocal() as db:
            events = db.scalars(select(PiiEvent)).all()
            assert len(events) == 1
            event = events[0]
            # Neither the formatted nor the digits-only form may appear in ANY column.
            row = " ".join(str(v) for v in event.__dict__.values())
            assert aadhaar not in row
            assert aadhaar.replace(" ", "") not in row
            assert event.masked_preview.startswith("XXXX")
            assert event.reason, "reason is NOT NULL by design"

    def test_full_url_is_truncated_to_origin(self, client: TestClient, auth_headers: dict) -> None:
        """A client bug sending a full URL must not leak its query string."""
        scan(
            client,
            auth_headers,
            f"Aadhaar {make_aadhaar()}",
            site_origin="https://mail.google.com/mail/u/0?token=SECRET123",
        )
        with SessionLocal() as db:
            event = db.scalars(select(PiiEvent)).first()
            assert event.site_origin == "https://mail.google.com"
            assert "SECRET123" not in event.site_origin

    def test_clean_scan_writes_no_rows(self, client: TestClient, auth_headers: dict) -> None:
        """A row per keystroke would swamp the timeline and break the demo."""
        scan(client, auth_headers, "Hello there, all good.")
        with SessionLocal() as db:
            assert db.scalars(select(PiiEvent)).all() == []

    def test_event_is_attributed_to_the_calling_device(self, client: TestClient, auth_headers: dict) -> None:
        scan(client, auth_headers, f"Aadhaar {make_aadhaar()}")
        with SessionLocal() as db:
            assert db.scalars(select(PiiEvent)).first().device_id == DEVICE_ID


class TestRateLimit:
    def test_burst_eventually_429s_with_retry_after(self, client: TestClient) -> None:
        """Protects the Gemini quota from a runaway content script."""
        headers = {"X-Sentinel-Device-Id": "ratelimit-probe-device"}
        statuses = [scan(client, headers, "hello").status_code for _ in range(200)]
        assert 429 in statuses, "limiter never engaged"
        limited = next(
            r for r in (scan(client, headers, "hello"),) if r.status_code == 429
        )
        assert "Retry-After" in limited.headers


class TestTimelineWording:
    """The timeline headline must say *how* a value was about to leave.

    ``FieldKind``'s own docstring states that the timeline's question is "how did
    this leave you", and that "in a screenshot" is a materially different answer
    from "you typed it". These assert the router actually spends that field
    rather than rendering three different events as one sentence.
    """

    def _titles(self, client: TestClient, headers: dict) -> list[str]:
        summary = client.get("/api/v1/dashboard/summary", headers=headers).json()
        return [e["title"] for e in summary["timeline"] if e["kind"] == "pii"]

    def test_typed_finding_reads_as_caught_on(self, client: TestClient, auth_headers: dict) -> None:
        scan(client, auth_headers, f"Aadhaar {make_aadhaar()}", field_kind="textarea")
        assert self._titles(client, auth_headers) == ["Aadhaar number caught on mail.google.com"]

    def test_pasted_finding_says_pasted(self, client: TestClient, auth_headers: dict) -> None:
        scan(client, auth_headers, f"Aadhaar {make_aadhaar()}", field_kind="paste")
        assert self._titles(client, auth_headers) == [
            "Aadhaar number pasted into mail.google.com"
        ]

    def test_image_finding_says_image(self, client: TestClient, auth_headers: dict) -> None:
        scan(client, auth_headers, f"Aadhaar {make_aadhaar()}", field_kind="image", source="ocr")
        assert self._titles(client, auth_headers) == [
            "Aadhaar number found in an image on mail.google.com"
        ]

    def test_html_field_kinds_never_reach_the_sentence(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """`contenteditable` is the same event told in HTML, not a fact about the user."""
        scan(client, auth_headers, f"Aadhaar {make_aadhaar()}", field_kind="contenteditable")
        assert "contenteditable" not in self._titles(client, auth_headers)[0]


class TestVendoredAssetMount:
    """The dashboard's screenshot panel loads its OCR engine from this mount.

    Not decoration: without it the drop-zone cannot start Tesseract at all, and
    the failure looks like "the panel is broken" rather than "a route is
    missing". See the mount comment in ``app/main.py``.
    """

    def test_serves_the_extensions_own_copy(self, client: TestClient) -> None:
        response = client.get("/vendor/tesseract/tesseract.min.js")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/javascript")

    def test_supports_range_requests(self, client: TestClient) -> None:
        """Tesseract fetches the 4 MB language model in chunks, not in one read."""
        response = client.get(
            "/vendor/tesseract/eng.traineddata", headers={"Range": "bytes=0-99"}
        )
        assert response.status_code == 206
        assert len(response.content) == 100

    def test_refuses_traversal_outside_the_mount(self, client: TestClient) -> None:
        assert client.get("/vendor/../app/main.py").status_code == 404
