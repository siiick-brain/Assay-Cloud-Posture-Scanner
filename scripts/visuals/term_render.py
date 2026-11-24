"""Render captured terminal text to a PNG that looks like a dark terminal window."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from matplotlib import font_manager
from PIL import Image, ImageDraw, ImageFont

BG = (24, 26, 33)
BAR = (44, 47, 58)
FG = (220, 223, 228)
PROMPT = (126, 200, 120)
DIM = (140, 146, 160)
WORD_COLOURS = {
    "critical": (240, 98, 98),
    "high": (245, 160, 80),
    "medium": (235, 205, 95),
    "low": (110, 170, 240),
    "info": (160, 160, 170),
    "new": (240, 98, 98),
    "reopened": (245, 160, 80),
    "closed": (126, 200, 120),
    "claim": (160, 160, 170),
    "#": (160, 160, 170),
}

# Masks run before drawing, so nothing private reaches the pixels.
MASKS = [
    (re.compile(r"(?<!\d)\d{12}(?!\d)"), "************"),
    (re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.IGNORECASE), r"~"),
    (re.compile(r"/(?:home|Users)/[^/\s]+"), "~"),
    (re.compile(r"\bA(?:KIA|SIA)[A-Z0-9]{16}\b"), "REDACTED_KEY_ID"),
]


def mask(text: str) -> str:
    for pattern, repl in MASKS:
        text = pattern.sub(repl, text)
    return text


def mono_font(size: int) -> ImageFont.FreeTypeFont:
    path = font_manager.findfont(font_manager.FontProperties(family="DejaVu Sans Mono"))
    return ImageFont.truetype(path, size)


def line_colour(line: str) -> tuple[int, int, int]:
    if line.startswith("$ "):
        return PROMPT
    word = line.strip().split(" ", 1)[0].lower() if line.strip() else ""
    return WORD_COLOURS.get(word, FG)


def render(lines: list[str], out: Path, title: str = "terminal", size: int = 15, min_cols: int = 0) -> Path:
    lines = [mask(line.rstrip("\n")) for line in lines]
    font = mono_font(size)
    cell_w = font.getbbox("M")[2]
    cell_h = int(size * 1.45)
    cols = max([min_cols, *(len(line) for line in lines)])
    pad, bar_h = 18, 30
    width = pad * 2 + cols * cell_w
    height = bar_h + pad * 2 + cell_h * len(lines)
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, bar_h], fill=BAR)
    for i, colour in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        cx = 16 + i * 20
        draw.ellipse([cx - 6, bar_h // 2 - 6, cx + 6, bar_h // 2 + 6], fill=colour)
    draw.text((width // 2, bar_h // 2), title, font=mono_font(13), fill=DIM, anchor="mm")
    y = bar_h + pad
    for line in lines:
        draw.text((pad, y), line, font=font, fill=line_colour(line))
        y += cell_h
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, optimize=True)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--title", default="terminal")
    args = parser.parse_args()
    render(args.transcript.read_text(encoding="utf-8").splitlines(), args.out, args.title)


if __name__ == "__main__":
    main()
