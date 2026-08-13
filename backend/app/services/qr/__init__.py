"""Module 9 — QR code scam detection.

``parse`` turns a decoded QR payload into a structured destination; ``engine``
judges it. Decoding itself happens in the extension, so nothing in this package
ever sees an image.
"""
