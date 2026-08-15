"""Offline unit tests for Module 7 — Grounded Security Assistant."""

from app.db.models import Device, PiiEvent, utcnow
from app.db.session import SessionLocal
from app.schemas.assistant import AssistantRequest
from app.services.assistant.cards import load_corpus
from app.services.assistant.engine import ask_assistant
from app.services.assistant.retrieval import retrieve_cards



def test_corpus_loading():
    corpus = load_corpus()
    assert len(corpus) >= 4
    card_ids = [c.id for c in corpus]
    assert "qr_scams" in card_ids
    assert "pii_privacy" in card_ids


def test_bm25_retrieval_qr_scam():
    corpus = load_corpus()
    matches = retrieve_cards("How do QR code scams work?", corpus)
    assert len(matches) > 0
    top_card = matches[0][0]
    assert top_card.id == "qr_scams"


def test_assistant_ask_qr_scams():
    req = AssistantRequest(question="How does SentinelAI handle QR scams?")
    res = ask_assistant(req)

    assert res.answered is True
    assert res.mode == "extractive"
    assert len(res.sources) > 0
    assert any(s.id == "qr_scams" for s in res.sources)


def test_assistant_relevance_floor_refusal():
    req = AssistantRequest(question="What is the weather like in Tokyo today?")
    res = ask_assistant(req)

    assert res.answered is False
    assert "do not have specific information" in res.answer
    assert len(res.sources) == 0


def test_personal_posture_retrieval():
    db = SessionLocal()
    dev = Device(id="test-device-ast-01", created_at=utcnow(), last_seen_at=utcnow())
    db.add(dev)
    event = PiiEvent(
        device_id="test-device-ast-01",
        occurred_at=utcnow(),
        site_origin="test-site.com",
        field_kind="input",
        pii_type="aadhaar",
        risk_level="critical",
        confidence=0.98,
        detection_tier="regex",
        reason="Aadhaar number detected",
        masked_preview="XXXX XXXX 9014",
        action_taken="ignored",
    )
    db.add(event)
    db.commit()
    db.close()

    req = AssistantRequest(
        question="Why is my score so low?", device_id="test-device-ast-01"
    )
    res = ask_assistant(req)

    assert res.answered is True
    assert res.personal_context_used is True
    assert any(s.id.startswith("user_") for s in res.sources)
