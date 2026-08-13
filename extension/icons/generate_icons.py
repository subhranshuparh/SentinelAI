"""
Generate the extension's PNG icons.

Written with zlib and struct rather than Pillow on purpose: this is the only
place in the project that would need an imaging library, and adding a binary
dependency to draw three flat-colour shields is a poor trade. Run it once and
commit the output.

    python extension/icons/generate_icons.py

The shape is a shield with a keyhole -- readable at 16px, which is the only size
that actually matters, since that is what sits in the toolbar.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

# Matches --accent in popup.css. The icon and the UI should not disagree.
SHIELD_RGB = (96, 165, 250)
KEYHOLE_RGB = (11, 14, 20)

# Each output pixel is averaged from SUPERSAMPLE^2 samples. Without this the
# shield's curved edge is a visible staircase at 16px.
SUPERSAMPLE = 4

SIZES = (16, 48, 128)


def _in_shield(x: float, y: float) -> bool:
    """Point-in-shield test in normalised [0, 1] coordinates."""
    if not (0.08 <= y <= 0.94):
        return False

    half_width = 0.36
    shoulder = 0.60

    if y > shoulder:
        # Below the shoulder the sides taper to a point. The 0.6 exponent gives
        # a slightly convex taper, which reads as a shield rather than a funnel.
        taper = 1.0 - (y - shoulder) / (0.94 - shoulder)
        half_width *= taper**0.6

    return abs(x - 0.5) <= half_width


def _in_keyhole(x: float, y: float) -> bool:
    """Circle over a tapered slot -- the classic lock glyph."""
    dx, dy = x - 0.5, y - 0.40
    if dx * dx + dy * dy <= 0.105**2:
        return True

    if 0.40 <= y <= 0.66:
        progress = (y - 0.40) / 0.26
        half_width = 0.042 + 0.038 * progress
        return abs(dx) <= half_width

    return False


def _render(size: int) -> bytes:
    """Return raw RGBA rows for one icon, supersampled and averaged."""
    rows = bytearray()
    step = 1.0 / (size * SUPERSAMPLE)

    for py in range(size):
        rows.append(0)  # PNG filter type 0 (None) prefixes every scanline.
        for px in range(size):
            shield_hits = 0
            keyhole_hits = 0

            for sy in range(SUPERSAMPLE):
                for sx in range(SUPERSAMPLE):
                    x = (px * SUPERSAMPLE + sx + 0.5) * step
                    y = (py * SUPERSAMPLE + sy + 0.5) * step
                    if _in_shield(x, y):
                        shield_hits += 1
                        if _in_keyhole(x, y):
                            keyhole_hits += 1

            total = SUPERSAMPLE * SUPERSAMPLE
            if shield_hits == 0:
                rows.extend((0, 0, 0, 0))
                continue

            # Blend the keyhole into the shield colour by coverage, then let the
            # shield's own coverage drive alpha. Doing it in this order keeps the
            # keyhole from bleeding transparency into the shield's edge.
            keyhole_ratio = keyhole_hits / shield_hits
            colour = tuple(
                round(s * (1 - keyhole_ratio) + k * keyhole_ratio)
                for s, k in zip(SHIELD_RGB, KEYHOLE_RGB)
            )
            rows.extend((*colour, round(255 * shield_hits / total)))

    return bytes(rows)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    """One PNG chunk: length, type, data, CRC32 over type+data."""
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


def main() -> None:
    out_dir = Path(__file__).parent
    for size in SIZES:
        path = out_dir / f"icon{size}.png"
        path.write_bytes(_png(size, _render(size)))
        print(f"wrote {path.name} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
