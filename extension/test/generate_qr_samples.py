"""
Generate the QR code images the test harness right-clicks on.

Run once, commit the output — the same arrangement as
``extension/icons/generate_icons.py``. Nothing in the extension, the backend or
the test suite imports this file, and ``segno`` is deliberately **not** in
``requirements.txt``: it is a tool for producing an asset, not a dependency of
the product.

    pip install segno
    python extension/test/generate_qr_samples.py

Why real PNGs instead of drawing the codes in the page with JavaScript: the
feature under test starts with a right-click on an ``<img>``, goes through
``chrome.contextMenus``, a ``fetch`` in the offscreen document, and a canvas
read. A canvas the page drew itself would short-circuit most of that and prove
almost nothing.

Every payload below is fabricated. The VPAs are syntactically valid and belong
to nobody; the handles are real PSP suffixes because that is the point of the
check. No real payment address, no real person, no real merchant appears here.
"""

from __future__ import annotations

from pathlib import Path

import segno

OUT_DIR = Path(__file__).parent / "qr"

#: filename -> (payload, what the harness page says it should produce)
#:
#: The set is chosen to cover both directions of the module's job. Three of
#: these must raise an alarm; three must stay quiet. A detector demonstrated
#: only on the things it catches is a detector nobody has shown you the false
#: positive rate of — and for UPI that rate is the whole design problem, since
#: every tea stall in India has a payment QR taped to the counter.
SAMPLES: dict[str, tuple[str, str]] = {
    # --- must raise an alarm ------------------------------------------------
    "scam-receive-money.png": (
        "upi://pay?pa=rahul-refund@ybl&pn=Amazon%20Refund&am=50000"
        "&tn=Scan%20to%20receive%20your%20refund%20urgently",
        "dangerous — pays out INR 50,000, brand name that does not match the VPA, urgent note",
    ),
    "scam-unknown-handle.png": (
        "upi://pay?pa=customercare@upisecure&am=25000&tn=KYC%20verification",
        "dangerous — handle is not a recognised PSP, and a large amount is pre-filled",
    ),
    "scam-shortened-link.png": (
        "https://bit.ly/3xSnT1nL",
        "flagged — a shortener hides the real destination. With the backend "
        "offline the verdict stays 'unknown' and the finding is still listed; "
        "it never becomes 'safe'",
    ),
    # --- must stay quiet ----------------------------------------------------
    "shop-counter.png": (
        "upi://pay?pa=q83719201@okhdfcbank&pn=Chai%20Point&am=45&mc=5812",
        "safe — a genuine merchant QR: known PSP, merchant category code, small amount",
    ),
    "person-open-amount.png": (
        "upi://pay?pa=priya.sharma@oksbi&pn=Priya%20Sharma",
        "safe — known PSP, no amount pre-filled, nothing to be alarmed about",
    ),
    "plain-link.png": (
        "https://www.wikipedia.org/",
        "safe once Safe Browsing and the registry answer; 'unknown' with the "
        "network down — a well-known name is never assumed to be fine",
    ),
    # --- must be honest about not knowing ------------------------------------
    "wifi-open.png": (
        "WIFI:T:nopass;S:Free Airport WiFi;;",
        "suspicious — the network is unencrypted. Who runs it is not something "
        "a QR code can tell you, and the panel says so rather than guessing",
    ),
}


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    for name, (payload, _expected) in SAMPLES.items():
        # Error correction M: the level printed material actually uses. H would
        # decode more reliably and would therefore make the harness easier than
        # reality, which is the wrong direction for a test fixture.
        code = segno.make(payload, error="m")
        # scale=6 gives roughly a 200px image — big enough to right-click
        # comfortably, small enough that the page is not all QR codes.
        code.save(OUT_DIR / name, scale=6, border=4, dark="#0b0e14", light="#ffffff")
        print(f"wrote {name}")


if __name__ == "__main__":
    main()
