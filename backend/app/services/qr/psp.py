"""UPI handles — which ``@bank`` suffixes are real, and who owns them.

Hand-entered from NPCI's published list of live UPI members and the handles the
major payment apps document publicly. Nothing here is scraped and nothing is
fetched at runtime: it is a static table, which is the point — a lookup that
needs a network is a lookup that can be unavailable, and this module is the
offline floor the UPI verdict stands on.

**What an unrecognised handle does and does not mean.** New PSPs launch. A
handle missing from this table is *not* proof of fraud, and the engine prices it
accordingly — a moderate penalty with a sentence that says "we do not recognise
this" rather than "this is fake". Treating an incomplete list as authoritative
would make the most common false positive in the module also its loudest.

The second table is the interesting one. ``_BRAND_HANDLES`` records which
handles a brand legitimately pays through, so ``amazon@apl`` (real: Amazon Pay
uses ``@apl``) is silent while ``amazon-refund@ybl`` is not. Without it, brand
matching on a VPA would fire on every genuine merchant.
"""

from __future__ import annotations

#: Live UPI handles. Grouped by the institution that operates them so an entry
#: can be checked against a source rather than trusted because it is in a set.
KNOWN_HANDLES: frozenset[str] = frozenset(
    {
        # --- BHIM and NPCI-operated ----------------------------------------
        "upi", "nsdl", "npci",
        # --- Google Pay -----------------------------------------------------
        "okhdfcbank", "okicici", "oksbi", "okaxis",
        # --- PhonePe --------------------------------------------------------
        "ybl", "ibl", "axl", "yesg",
        # --- Paytm ----------------------------------------------------------
        "paytm", "ptyes", "ptsbi", "pthdfc", "ptaxis",
        # --- Amazon Pay -----------------------------------------------------
        "apl", "yapl", "rapl",
        # --- WhatsApp Pay ---------------------------------------------------
        "waaxis", "waicici", "wahdfcbank", "wasbi",
        # --- Public sector banks --------------------------------------------
        "sbi", "pnb", "boi", "barodampay", "barodapay", "cnrb", "cbin", "uco",
        "unionbank", "uboi", "ubi", "iob", "idbi", "psb", "mahb", "indianbank",
        "allbank", "andb", "utbi", "united", "vijb", "jkb",
        # --- Private sector banks -------------------------------------------
        "hdfcbank", "payzapp", "icici", "pockets", "eazypay", "myicici",
        "axisbank", "axisb", "axisgo", "kotak", "kaypay", "kmbl", "kmb",
        "yesbank", "yesbankltd", "indus", "idfcbank", "idfcnetc", "rbl",
        "federal", "fbl", "sib", "csbpay", "dbs", "dcb", "dlb", "karb", "kbl",
        "kvb", "lvb", "tjsb", "cosb", "jsbp", "abfspay",
        # --- Small finance, payments banks, and fintech PSPs -----------------
        "equitas", "esfb", "ujjivan", "finobank", "airtel", "freecharge",
        "jupiteraxis", "slice", "slc", "fam", "naviaxis", "superyes", "seyes",
        "timecosmos", "ikwik", "imobile", "goaxb", "omni",
    }
)

#: Which handles a brand actually pays through. Only brands that operate a UPI
#: presence appear; a brand absent from this map has no legitimate VPA, so a
#: VPA carrying its name is a mismatch by definition.
#:
#: Keys are the same tokens as ``site.brand.BRAND_DOMAINS`` so the two tables
#: cannot describe different brands under the same name.
_BRAND_HANDLES: dict[str, frozenset[str]] = {
    "paytm": frozenset({"paytm", "ptyes", "ptsbi", "pthdfc", "ptaxis"}),
    "phonepe": frozenset({"ybl", "ibl", "axl"}),
    "amazon": frozenset({"apl", "yapl", "rapl"}),
    "google": frozenset({"okhdfcbank", "okicici", "oksbi", "okaxis"}),
    "sbi": frozenset({"sbi", "oksbi", "ptsbi", "wasbi"}),
    "hdfc": frozenset({"hdfcbank", "payzapp", "okhdfcbank", "pthdfc", "wahdfcbank"}),
    "icici": frozenset({"icici", "pockets", "eazypay", "myicici", "okicici", "waicici", "imobile"}),
    "axisbank": frozenset({"axisbank", "axisb", "axisgo", "okaxis", "ptaxis", "waaxis", "axl"}),
    "kotak": frozenset({"kotak", "kaypay", "kmbl", "kmb"}),
    "pnb": frozenset({"pnb"}),
    "flipkart": frozenset({"ybl"}),  # PhonePe was Flipkart's payments arm.
    "razorpay": frozenset({"rpy", "razorpay"}),
}


def is_known_handle(handle: str) -> bool:
    """Is this ``@suffix`` one we recognise? Case-insensitive, never raises."""
    return handle.strip().lower().lstrip("@") in KNOWN_HANDLES


def handles_for_brand(brand: str) -> frozenset[str]:
    """Handles ``brand`` legitimately pays through. Empty when it has none."""
    return _BRAND_HANDLES.get(brand.lower(), frozenset())
