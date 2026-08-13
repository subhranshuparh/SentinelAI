"""Populates a realistic demo history.

Two reasons this exists, and neither is laziness:

1. **An empty dashboard is indistinguishable from a broken one.** A trend chart
   with one point is a dot. A timeline with nothing in it looks like the backend
   is down. Developing the UI against real-shaped data means the empty state gets
   designed deliberately rather than discovered at hour 20.
2. **Demo insurance.** If the wifi dies mid-presentation, the dashboard still
   tells its story. The live extension demo proves the pipeline; this proves the
   score is doing arithmetic over history.

The data is deliberately *mixed*, not uniformly bad. A seed where everything is
critical produces a red screen that demonstrates nothing about the model — the
interesting claim is that masked findings score better than ignored ones, and
that only shows when both are present.

Run: ``python -m app.db.seed``  (add ``--reset`` to clear this device first)
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

from sqlalchemy import delete

from app.db.models import (
    Device,
    DetectionTier,
    PiiEvent,
    ScoreSnapshot,
    SiteCheck,
    UserAction,
    utcnow,
)
from app.db.session import SessionLocal, init_db
from app.services.risk.engine import compute

#: Fixed id so the seed is idempotent and the demo can point at one device.
#: Deliberately not a UUID — a human has to be able to type this into a URL.
SEED_DEVICE_ID = "demo-device-sentinel-01"

#: Fixed seed so two runs produce the same screenshots. A demo that looks
#: different every time it is prepared is a demo you cannot rehearse.
RANDOM_SEED = 20260601

DAYS_OF_HISTORY = 21


# --------------------------------------------------------------------------
# Event templates
#
# Every entry carries a real ``reason``. Writing seed rows with placeholder
# reasons would put text on the demo screen that the detectors would never
# actually produce, which is the kind of thing a judge notices.
# --------------------------------------------------------------------------

PII_TEMPLATES = [
    (
        "aadhaar", "critical", 0.98, DetectionTier.REGEX.value,
        "12-digit number passing the Verhoeff checksum used by Aadhaar.",
        "XXXX XXXX 9014",
    ),
    (
        "credit_card", "critical", 0.97, DetectionTier.REGEX.value,
        "16-digit number passing the Luhn checksum used by payment cards.",
        "XXXX XXXX XXXX 4242",
    ),
    (
        "pan", "high", 0.95, DetectionTier.REGEX.value,
        "Matches the PAN format: five letters, four digits, one letter.",
        "ABXXX1234X",
    ),
    (
        "phone", "medium", 0.88, DetectionTier.REGEX.value,
        "10-digit Indian mobile number starting with 6-9.",
        "98XXXXXX10",
    ),
    (
        "email", "low", 0.92, DetectionTier.REGEX.value,
        "Email address in a public text field.",
        "p****a@example.com",
    ),
    (
        "api_key", "critical", 0.94, DetectionTier.REGEX.value,
        "High-entropy string matching a known API key prefix.",
        "sk-****************7fd2",
    ),
    (
        "travel_plan", "medium", 0.61, DetectionTier.LLM.value,
        "Context suggests you are describing when your home will be empty.",
        "[travel dates]",
    ),
    (
        "health_detail", "high", 0.58, DetectionTier.LLM.value,
        "Context suggests a medical condition tied to you personally.",
        "[health detail]",
    ),
]

ORIGINS = [
    "https://forum.example-community.com",
    "https://chat.example-support.net",
    "https://www.reddit.com",
    "https://docs.google.com",
    "https://mail.google.com",
]

#: Skewed toward the good outcome on purpose. A demo user who masks most things
#: and slips occasionally is the realistic case, and it is the one where the
#: action multipliers visibly do work.
ACTION_WEIGHTS = [
    (UserAction.MASKED.value, 5),
    (UserAction.NONE.value, 2),
    (UserAction.IGNORED.value, 2),
    (UserAction.ALLOWLISTED.value, 1),
]

SITE_TEMPLATES = [
    (
        "www.wikipedia.org", "safe", 100, 8000, False, False,
        [{"detail": "Not on Google's list of known unsafe sites.", "weight": "good"},
         {"detail": "Domain has been registered for over 20 years.", "weight": "good"}],
    ),
    (
        "onlinesbi.sbi", "safe", 100, 1400, False, False,
        [{"detail": "Secure connection (HTTPS).", "weight": "good"},
         {"detail": "Domain has been registered for about 4 years.", "weight": "good"}],
    ),
    (
        "amazon-login-security.xyz", "dangerous", 25, 4, False, True,
        [{"detail": "Uses the brand name \"amazon\" on a domain Amazon does not own.", "weight": "bad"},
         {"detail": "Contains words often used in scam links (login, security).", "weight": "bad"},
         {"detail": "Domain was registered 4 days ago.", "weight": "bad"}],
    ),
    (
        "paypa1-verify.com", "dangerous", 25, 11, False, True,
        [{"detail": "Domain looks like \"paypal\" with characters swapped.", "weight": "bad"},
         {"detail": "Domain was registered 11 days ago.", "weight": "bad"}],
    ),
    (
        "secure-kyc-update.info", "suspicious", 52, None, False, False,
        [{"detail": "Contains words often used in scam links (secure, kyc, update).", "weight": "bad"},
         {"detail": "Age of this domain could not be confirmed.", "weight": "unknown"}],
    ),
    (
        "internal-tools.local", "unknown", 50, None, None, False,
        [{"detail": "This site could not be checked. Treat it as unverified, not as safe.",
          "weight": "unknown"}],
    ),
]


def _weighted_action(rng: random.Random) -> str:
    population = [action for action, weight in ACTION_WEIGHTS for _ in range(weight)]
    return rng.choice(population)


def _build_history(rng: random.Random, now: datetime) -> tuple[list[PiiEvent], list[SiteCheck]]:
    """Spread events over the window so the trend line has somewhere to go.

    Event density rises toward the present. That gives the chart a visible slope
    instead of noise around a flat line, and it matches the story being told: a
    user who has recently started doing riskier things.
    """
    events: list[PiiEvent] = []
    checks: list[SiteCheck] = []

    for day in range(DAYS_OF_HISTORY, 0, -1):
        # 0 events on the oldest day, up to 3 on the most recent.
        density = 1.0 - (day / DAYS_OF_HISTORY)
        for _ in range(rng.randint(0, 1 + int(density * 2))):
            pii_type, level, confidence, tier, reason, preview = rng.choice(PII_TEMPLATES)
            occurred = now - timedelta(days=day, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            events.append(
                PiiEvent(
                    device_id=SEED_DEVICE_ID,
                    occurred_at=occurred,
                    site_origin=rng.choice(ORIGINS),
                    field_kind=rng.choice(["input", "textarea", "contenteditable"]),
                    pii_type=pii_type,
                    risk_level=level,
                    confidence=confidence,
                    detection_tier=tier,
                    reason=reason,
                    masked_preview=preview,
                    action_taken=_weighted_action(rng),
                )
            )

        if rng.random() < 0.55:
            domain, verdict, score, age, sb_hit, brand, reasons = rng.choice(SITE_TEMPLATES)
            checks.append(
                SiteCheck(
                    device_id=SEED_DEVICE_ID,
                    occurred_at=now - timedelta(days=day, hours=rng.randint(0, 23)),
                    domain=domain,
                    trust_score=score,
                    verdict=verdict,
                    reasons=reasons,
                    domain_age_days=age,
                    safe_browsing_hit=sb_hit,
                    brand_mismatch=brand,
                )
            )

    # Guarantee the headline moment exists regardless of the dice: one unmasked
    # critical finding and one dangerous site, both recent. A demo must not
    # depend on a random draw going the right way.
    events.append(
        PiiEvent(
            device_id=SEED_DEVICE_ID,
            occurred_at=now - timedelta(hours=3),
            site_origin="https://forum.example-community.com",
            field_kind="textarea",
            pii_type="aadhaar",
            risk_level="critical",
            confidence=0.98,
            detection_tier=DetectionTier.REGEX.value,
            reason="12-digit number passing the Verhoeff checksum used by Aadhaar.",
            masked_preview="XXXX XXXX 9014",
            action_taken=UserAction.IGNORED.value,
        )
    )
    # Module 10. `field_kind="paste"` is the only thing that distinguishes this
    # row from a typed one, and it is the whole story: the user did not compose
    # this key, they copied it out of a terminal and put it in a chat box.
    #
    # Note what is *not* stored: the destination assessment. "Discord is not a
    # place an API key belongs" is derived at request time from an origin the row
    # already has, so persisting it would be a second copy of a fact that can go
    # stale the moment the table is edited.
    events.append(
        PiiEvent(
            device_id=SEED_DEVICE_ID,
            occurred_at=now - timedelta(hours=5),
            site_origin="https://discord.com",
            field_kind="paste",
            pii_type="api_key",
            risk_level="critical",
            confidence=0.96,
            detection_tier=DetectionTier.REGEX.value,
            reason="Matches the AWS access key ID format, pasted into a chat app.",
            masked_preview="AKIA••••••••••••••••",
            action_taken=UserAction.MASKED.value,
        )
    )
    # Module 12. `field_kind="image"` and `detection_tier="ocr"` together say
    # something no other row in this table says: nobody typed this, nobody even
    # pasted it — it was printed on a photograph the user was about to attach,
    # and the number only matched after characters an optical reader commonly
    # confuses were corrected.
    #
    # The confidence is 0.75 rather than the 0.98 on the typed Aadhaar above,
    # and that gap is the point. Two substitutions were needed, so the value
    # carries `MAX_OCR_CONFIDENCE` less one penalty step — the number reports how
    # much inference went into it. What makes even 0.75 defensible is that the
    # corrected digits still satisfy Aadhaar's Verhoeff checksum, which is a
    # 1-in-10 accident to pass by chance and is the only reason this module is
    # allowed to rewrite anything at all.
    events.append(
        PiiEvent(
            device_id=SEED_DEVICE_ID,
            occurred_at=now - timedelta(hours=4),
            site_origin="https://web.whatsapp.com",
            field_kind="image",
            pii_type="aadhaar",
            risk_level="critical",
            confidence=0.75,
            detection_tier=DetectionTier.OCR.value,
            reason=(
                "Read from an image. Two characters were corrected before the number "
                "matched, and the corrected value passes the Verhoeff checksum."
            ),
            masked_preview="XXXX XXXX 4471",
            action_taken=UserAction.MASKED.value,
        )
    )
    checks.append(
        SiteCheck(
            device_id=SEED_DEVICE_ID,
            occurred_at=now - timedelta(hours=2),
            domain="amazon-login-security.xyz",
            trust_score=25,
            verdict="dangerous",
            reasons=SITE_TEMPLATES[2][6],
            domain_age_days=4,
            safe_browsing_hit=False,
            brand_mismatch=True,
        )
    )

    # A check that arrived through Module 9 — the user right-clicked a QR code
    # in a chat and it resolved to this page.
    #
    # Note what is *not* here: any marker saying "this came from a QR code".
    # There is no such column, and adding one just for the seed would put a fact
    # in the database that the running product cannot produce. A QR that
    # resolves to a web address is a site visit about to happen, so it goes
    # through the same `persist_site_check` with the same reasons the site
    # engine writes for a page the user navigated to — indistinguishable by
    # design, and correct for the Browsing sub-score, which cares about where
    # the user was headed and not about which gesture started it.
    checks.append(
        SiteCheck(
            device_id=SEED_DEVICE_ID,
            occurred_at=now - timedelta(hours=6),
            domain="upi-refund-verify.in",
            trust_score=22,
            verdict="dangerous",
            reasons=[
                {"detail": "Contains words often used in scam links (verify, refund).", "weight": "bad"},
                {"detail": "Domain was registered 6 days ago.", "weight": "bad"},
                {"detail": "Not on Google's list of known unsafe sites.", "weight": "good"},
            ],
            domain_age_days=6,
            safe_browsing_hit=False,
            brand_mismatch=False,
        )
    )

    return events, checks


def _build_snapshots(
    events: list[PiiEvent], checks: list[SiteCheck], now: datetime
) -> list[ScoreSnapshot]:
    """Replay the score once per day, using only what was known on that day.

    Computed by the real engine rather than invented, so the trend line and the
    current score are produced by one piece of code. A hand-drawn chart that
    disagrees with the number above it is worse than no chart.
    """
    snapshots: list[ScoreSnapshot] = []
    for day in range(DAYS_OF_HISTORY, -1, -1):
        as_of = now - timedelta(days=day)
        summary = compute(
            [e for e in events if e.occurred_at <= as_of],
            [c for c in checks if c.occurred_at <= as_of],
            identity_score=None,
            now=as_of,
        )
        snapshots.append(
            ScoreSnapshot(
                device_id=SEED_DEVICE_ID,
                captured_at=as_of,
                overall=summary.overall,
                privacy=summary.privacy or 0,
                browsing=summary.browsing or 0,
                identity=0,
            )
        )
    return snapshots


def seed(reset: bool = False) -> None:
    init_db()
    rng = random.Random(RANDOM_SEED)
    now = utcnow()

    with SessionLocal() as db:
        if reset:
            # Scoped to the demo device by design. A seed script that truncates
            # tables is one fat finger away from destroying real captured events.
            for model in (PiiEvent, SiteCheck, ScoreSnapshot):
                db.execute(delete(model).where(model.device_id == SEED_DEVICE_ID))
            db.execute(delete(Device).where(Device.id == SEED_DEVICE_ID))
            db.commit()

        if db.get(Device, SEED_DEVICE_ID) is not None:
            print(f"Device {SEED_DEVICE_ID} already seeded. Use --reset to rebuild.")
            return

        db.add(Device(id=SEED_DEVICE_ID, created_at=now - timedelta(days=DAYS_OF_HISTORY), last_seen_at=now))
        events, checks = _build_history(rng, now)

        # Computed *before* the commit. After it, SQLAlchemy expires these
        # instances and reloads them from SQLite, which hands back naive
        # datetimes — and the engine does arithmetic against an aware `now`.
        summary = compute(events, checks, identity_score=None, now=now)
        snapshots = _build_snapshots(events, checks, now)

        db.add_all(events)
        db.add_all(checks)
        db.add_all(snapshots)
        db.commit()

    print(f"Seeded {len(events)} PII events and {len(checks)} site checks over {DAYS_OF_HISTORY} days.")
    print(f"Device id : {SEED_DEVICE_ID}")
    print(f"Score     : {summary.overall}/100 ({summary.risk_level})")
    print(f"Headline  : {summary.headline}")
    print(f"Open      : http://127.0.0.1:8000/api/v1/dashboard/summary?device_id={SEED_DEVICE_ID}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Populate SentinelAI with demo history.")
    parser.add_argument("--reset", action="store_true", help="Delete the demo device's rows first.")
    seed(reset=parser.parse_args().reset)
