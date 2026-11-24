"""Capture the public GitHub pages used in docs/images. No login, public pages only.

Usage: python scripts/visuals/capture_github.py RUN_ID
"""

import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

REPO = "https://github.com/siiick-brain/Assay-Cloud-Posture-Scanner"
OUT = Path("docs/images")


def _decline_cookies(page: Page) -> None:
    # Only essential cookies, if GitHub shows a consent banner.
    for label in ("Reject", "Reject all", "Decline"):
        button = page.get_by_role("button", name=label)
        if button.count():
            button.first.click()
            return


def main() -> int:
    run_id = sys.argv[1]
    shots = [
        (f"{REPO}/actions/runs/{run_id}", "ci-green.png", None),
        (REPO, "readme-top.png", None),
        (f"{REPO}/graphs/contributors", "contributors.png", "svg"),
    ]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme="light")
        for url, name, wait_for in shots:
            page.goto(url, wait_until="networkidle")
            _decline_cookies(page)
            if wait_for:
                page.wait_for_selector(wait_for, timeout=30000, state="attached")
            # The contributors chart draws after its data request returns.
            page.wait_for_timeout(6000)
            page.screenshot(path=str(OUT / name))
            print(f"{name}: {url}")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
