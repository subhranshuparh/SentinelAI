"""
Generate SentinelAI extension PNG icons — brand-matching design.

The icon renders the SentinelAI shield with:
  - Navy-blue body with a gradient from dark royal blue to near-black
  - Cyan circuit accent traces on the left
  - Bold "S" letterform in light silver-blue
  - Lock icon at the bottom
  - Eye icon at the top-right

Written with zlib and struct rather than Pillow: this is the only
place in the project that would need an imaging library, and adding a
binary dependency to draw three flat-colour icons is a poor trade.

Run once and commit the output:

    python extension/icons/generate_icons.py
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

# --- Brand Colour Palette ---------------------------------------------------
# Navy shield body: linear interpolation across the Y axis
SHIELD_TOP    = (30, 58, 110)    # #1e3a6e — royal blue
SHIELD_MID    = (15, 31, 74)     # #0f1f4a — deep blue
SHIELD_BOTTOM = (8,  15, 42)     # #080f2a — near-black navy

# Cyan circuit / accent colour
CIRCUIT_RGB   = (56, 189, 248)   # #38bdf8 — sky-400

# S letterform: light silver-to-blue
S_TOP_RGB     = (226, 232, 240)  # #e2e8f0 — slate-200
S_BTM_RGB     = (96,  165, 250)  # #60a5fa — blue-400

# Lock & eye
LOCK_RGB      = (96, 165, 250)   # #60a5fa
EYE_RGB       = (96, 165, 250)   # #60a5fa

# Background: transparent
BG            = (0, 0, 0, 0)     # RGBA transparent

# Anti-aliasing supersamples per pixel
SUPERSAMPLE = 4

SIZES = (16, 48, 128)


# ---------------------------------------------------------------------------
# Shield geometry (normalised [0, 1] coordinates)
# ---------------------------------------------------------------------------

def _in_shield(x: float, y: float) -> bool:
    """Classic heraldic shield: flat top, tapered bottom point."""
    if not (0.06 <= y <= 0.95):
        return False

    # Rounded top corners: quarter-circle arc at each shoulder
    half_w = 0.42
    corner_r = 0.10
    corner_cx_l = 0.08 + corner_r
    corner_cx_r = 1.0 - 0.08 - corner_r
    corner_cy = 0.06 + corner_r

    if y < corner_cy:
        if x < corner_cx_l:
            return (x - corner_cx_l) ** 2 + (y - corner_cy) ** 2 <= corner_r ** 2
        if x > corner_cx_r:
            return (x - corner_cx_r) ** 2 + (y - corner_cy) ** 2 <= corner_r ** 2
        return 0.08 <= x <= 0.92

    shoulder = 0.62
    if y > shoulder:
        t = (y - shoulder) / (0.95 - shoulder)
        half_w = 0.42 * (1.0 - t) ** 0.55   # convex taper

    return abs(x - 0.5) <= half_w


def _shield_border(x: float, y: float, thickness: float = 0.04) -> bool:
    """True if (x, y) is inside the shield but close to its edge."""
    if not _in_shield(x, y):
        return False
    inner_scale = 1.0 - thickness
    ix = 0.5 + (x - 0.5) / inner_scale
    iy = y / inner_scale
    return not _in_shield(ix, iy)


# ---------------------------------------------------------------------------
# S letterform (approximated with strokes)
# ---------------------------------------------------------------------------

def _in_s_letter(x: float, y: float) -> bool:
    """Approximates a bold italic 'S' using Bézier-like swept paths."""
    # Normalise to an S bounding box
    x0, y0, x1, y1 = 0.25, 0.18, 0.75, 0.82
    if not (x0 <= x <= x1 and y0 <= y <= y1):
        return False

    # Map into local coords [-1, 1]
    lx = (x - (x0 + x1) / 2) / ((x1 - x0) / 2)
    ly = (y - (y0 + y1) / 2) / ((y1 - y0) / 2)

    # Two arcs and a diagonal crossbar
    # Upper arc (top half): open to left
    if ly < 0:
        cx, cy, r_out, r_in = 0.15, -0.48, 0.55, 0.25
        dist = math.sqrt((lx - cx) ** 2 + (ly - cy) ** 2)
        if r_in < dist < r_out and lx > cx - 0.1:
            return True

    # Lower arc (bottom half): open to right
    if ly > 0:
        cx, cy, r_out, r_in = -0.15, 0.48, 0.55, 0.25
        dist = math.sqrt((lx - cx) ** 2 + (ly - cy) ** 2)
        if r_in < dist < r_out and lx < cx + 0.1:
            return True

    # Diagonal crossbar connecting the two arcs
    # Line from approx (0.6, -0.05) to (-0.6, 0.05) in local coords
    slope = (0.05 - (-0.05)) / (-0.6 - 0.6)   # = -1/6
    expected_y = -0.05 + slope * (lx - 0.6)
    if abs(ly - expected_y) < 0.18:
        return True

    return False


# ---------------------------------------------------------------------------
# Lock icon
# ---------------------------------------------------------------------------

def _in_lock(x: float, y: float) -> bool:
    """Lock body + shackle at bottom-centre of the shield."""
    # Body rectangle
    bx0, by0, bx1, by1 = 0.38, 0.74, 0.62, 0.89
    # Shackle arc above body
    sx, sy, sr = 0.50, 0.71, 0.085

    in_body = bx0 <= x <= bx1 and by0 <= y <= by1
    dist_shackle = math.sqrt((x - sx) ** 2 + (y - sy) ** 2)
    # Shackle = thin ring (annulus) in top half
    in_shackle = (sr - 0.025 < dist_shackle < sr + 0.025) and y < sy

    # Keyhole in body
    kx, ky, kr = 0.50, 0.80, 0.035
    in_keyhole_circle = math.sqrt((x - kx) ** 2 + (y - ky) ** 2) < kr
    in_keyhole_slot   = abs(x - kx) < 0.018 and ky <= y <= 0.875

    if in_keyhole_circle or in_keyhole_slot:
        return False  # cut-out

    return in_body or in_shackle


# ---------------------------------------------------------------------------
# Eye icon
# ---------------------------------------------------------------------------

def _in_eye(x: float, y: float) -> bool:
    """Small eye icon at top-right of shield."""
    # Eye is a lens shape centred at (0.73, 0.24)
    ex, ey = 0.73, 0.24
    # Lens shape: intersection of two circles
    half_w, half_h = 0.085, 0.045
    if abs(x - ex) > half_w or abs(y - ey) > half_h:
        return False

    # Iris
    dist = math.sqrt((x - ex) ** 2 + (y - ey) ** 2)
    return dist < half_w * 0.65


# ---------------------------------------------------------------------------
# Circuit traces (decorative lines left side)
# ---------------------------------------------------------------------------

def _in_circuit(x: float, y: float) -> bool:
    """Thin horizontal/vertical traces with node dots."""
    lw = 0.018    # line half-width

    # Vertical spine
    if abs(x - 0.22) < lw and 0.28 <= y <= 0.60:
        return True

    # Horizontal branches
    if abs(y - 0.35) < lw and 0.22 <= x <= 0.36:
        return True
    if abs(y - 0.47) < lw and 0.22 <= x <= 0.32:
        return True
    if abs(y - 0.57) < lw and 0.22 <= x <= 0.38:
        return True

    # Node dots
    nodes = [(0.22, 0.35, 0.026), (0.22, 0.47, 0.022), (0.22, 0.57, 0.026),
             (0.36, 0.35, 0.020), (0.38, 0.57, 0.020)]
    for nx, ny, nr in nodes:
        if math.sqrt((x - nx) ** 2 + (y - ny) ** 2) < nr:
            return True

    return False


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))  # type: ignore[return-value]


def _shield_color(y: float) -> tuple[int, int, int]:
    if y < 0.5:
        return _lerp(SHIELD_TOP, SHIELD_MID, y / 0.5)
    return _lerp(SHIELD_MID, SHIELD_BOTTOM, (y - 0.5) / 0.5)


def _s_color(y: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, (y - 0.18) / 0.64))
    return _lerp(S_TOP_RGB, S_BTM_RGB, t)


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def _render(size: int) -> bytes:
    """Return raw RGBA pixel rows for one icon size."""
    rows = bytearray()
    step = 1.0 / (size * SUPERSAMPLE)

    for py in range(size):
        rows.append(0)  # PNG filter byte (none)
        for px in range(size):
            r_acc, g_acc, b_acc, a_acc = 0.0, 0.0, 0.0, 0.0
            total = SUPERSAMPLE * SUPERSAMPLE

            for sy in range(SUPERSAMPLE):
                for sx in range(SUPERSAMPLE):
                    x = (px * SUPERSAMPLE + sx + 0.5) * step
                    y = (py * SUPERSAMPLE + sy + 0.5) * step

                    if not _in_shield(x, y):
                        # fully transparent
                        continue

                    # Determine pixel colour, layered front-to-back
                    if size >= 48 and _in_eye(x, y):
                        col = EYE_RGB
                    elif size >= 48 and _in_lock(x, y):
                        col = LOCK_RGB
                    elif _in_s_letter(x, y):
                        col = _s_color(y)
                    elif size >= 32 and _in_circuit(x, y):
                        col = CIRCUIT_RGB
                    elif _shield_border(x, y, 0.030):
                        # Border blends cyan accent
                        base = _shield_color(y)
                        col = _lerp(base, (74, 144, 226), 0.55)
                    else:
                        col = _shield_color(y)

                    r_acc += col[0]
                    g_acc += col[1]
                    b_acc += col[2]
                    a_acc += 255.0

            # Normalise accumulated values
            coverage = a_acc / (total * 255.0)
            if coverage < 0.01:
                rows.extend((0, 0, 0, 0))
            else:
                alpha = round(a_acc / total)
                rows.extend((
                    round(r_acc / (a_acc / 255.0)) if a_acc > 0 else 0,
                    round(g_acc / (a_acc / 255.0)) if a_acc > 0 else 0,
                    round(b_acc / (a_acc / 255.0)) if a_acc > 0 else 0,
                    alpha,
                ))

    return bytes(rows)


# ---------------------------------------------------------------------------
# PNG writer (pure stdlib)
# ---------------------------------------------------------------------------

def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(size: int, raw: bytes) -> bytes:
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    out_dir = Path(__file__).parent
    for size in SIZES:
        path = out_dir / f"icon{size}.png"
        path.write_bytes(_png(size, _render(size)))
        print(f"wrote {path.name} ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
