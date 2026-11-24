"""Screenshot an offline report.html in headless Chromium at 1280 px wide."""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("html", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--height", type=int, default=1000, help="viewport height; 0 captures the full page")
    args = parser.parse_args()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": args.height or 1000}, color_scheme="light")
        page.goto(args.html.resolve().as_uri())
        page.wait_for_load_state("load")
        page.screenshot(path=str(args.out), full_page=args.height == 0)
        browser.close()


if __name__ == "__main__":
    main()
