#!/usr/bin/env python3
"""Check every text and background pair in the stylesheet for contrast.

The palette lives in frontend/app.css as custom properties, once for
the light theme and twice for the dark theme (under the system
preference and under the explicit choice). This reads those blocks
from the stylesheet itself, so the numbers it checks are the numbers
the browser paints, and it fails when any pair a person reads drops
below the Web Content Accessibility Guidelines ratio: 4.5 to 1 for
text, 3 to 1 for the focus ring, which is a component boundary rather
than text.

The tinted chips and tiles paint text in a tier color over that same
color mixed into the card surface. The mix is computed here the way
color-mix in the sRGB space computes it, channel by channel on the
encoded values, so those pairs are checked as the browser shows them
rather than as the untinted card would suggest.

Usage:
  check_contrast.py            report every pair and exit 1 on a failure
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STYLESHEET = Path(__file__).resolve().parent.parent / "frontend" / "app.css"

TEXT_RATIO = 4.5
COMPONENT_RATIO = 3.0
TINT = 0.12  # the chip and tile background: this much tier color in the card

# Each pair is (foreground token, background token, minimum ratio). The
# surfaces are the page, the card, and the pointed-at card; the text on
# each is the ink, the quiet ink, and the three tiers.
PAIRS: list[tuple[str, str, float]] = [
    ("ink", "paper", TEXT_RATIO),
    ("ink", "card", TEXT_RATIO),
    ("ink", "hover", TEXT_RATIO),
    ("quiet", "paper", TEXT_RATIO),
    ("quiet", "card", TEXT_RATIO),
    ("quiet", "hover", TEXT_RATIO),
    ("critical", "card", TEXT_RATIO),
    ("warning", "card", TEXT_RATIO),
    ("notice", "card", TEXT_RATIO),
    ("on-accent", "accent", TEXT_RATIO),
    ("focus", "paper", COMPONENT_RATIO),
    ("focus", "card", COMPONENT_RATIO),
]

# The tinted pairs: tier text over the tier mixed into the card.
TIERS = ("critical", "warning", "notice")

BLOCKS = {
    "light": ":root {",
    "dark by preference": ':root:not([data-theme="light"]) {',
    "dark by choice": ':root[data-theme="dark"] {',
}

TOKEN = re.compile(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;")


def tokens_in(css: str, opener: str) -> dict[str, str]:
    """The color tokens declared in the block that begins with opener."""
    start = css.index(opener) + len(opener)
    end = css.index("}", start)
    return {name: value.lower() for name, value in TOKEN.findall(css[start:end])}


def channels(hex_color: str) -> tuple[float, float, float]:
    value = hex_color.lstrip("#")
    return tuple(int(value[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def mix(top: str, bottom: str, amount: float) -> str:
    """color-mix(in srgb, top amount, bottom): a straight blend of the
    encoded channels, which is what the sRGB space means there."""
    blended = [
        round(255 * (a * amount + b * (1 - amount)))
        for a, b in zip(channels(top), channels(bottom), strict=True)
    ]
    return "#" + "".join(f"{c:02x}" for c in blended)


def luminance(hex_color: str) -> float:
    def linear(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(c) for c in channels(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(foreground: str, background: str) -> float:
    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def check(css: str) -> tuple[list[str], list[str]]:
    """Every pair in every theme: the lines of the report, and the
    failures among them. The two dark blocks must also match, because
    a token changed in one and not the other is a theme that depends
    on how it was reached."""
    report: list[str] = []
    failures: list[str] = []
    themes = {name: tokens_in(css, opener) for name, opener in BLOCKS.items()}
    if themes["dark by preference"] != themes["dark by choice"]:
        failures.append("the two dark theme blocks differ")
    for theme, palette in themes.items():
        pairs = list(PAIRS) + [
            (tier, f"{tier} tint", TEXT_RATIO) for tier in TIERS
        ]
        for foreground, background, minimum in pairs:
            if background.endswith(" tint"):
                tier = background.split()[0]
                background_hex = mix(palette[tier], palette["card"], TINT)
            else:
                background_hex = palette[background]
            value = ratio(palette[foreground], background_hex)
            verdict = "ok" if value >= minimum else "FAIL"
            line = (
                f"{theme:19} {foreground:>9} on {background:14} "
                f"{value:5.2f} (needs {minimum:.1f}) {verdict}"
            )
            report.append(line)
            if value < minimum:
                failures.append(line)
    return report, failures


def main() -> int:
    report, failures = check(STYLESHEET.read_text())
    print("\n".join(report))
    if failures:
        print(f"\n{len(failures)} pair(s) below the ratio", file=sys.stderr)
        return 1
    print("\nevery pair meets its ratio in every theme")
    return 0


if __name__ == "__main__":
    sys.exit(main())
