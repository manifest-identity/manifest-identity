#!/usr/bin/env python3
"""Capture the README walkthrough screenshots from a running instance.

The images in docs/screenshots/ are reproducible, not asserted: bring
up a fresh stack with its own generated environment, import the
curated sample estates oldest first, create one campaign so the page
shows a live review, then run this script. It needs Playwright, which
is deliberately not in the pinned trees; install it ad hoc in a
scratch environment (pip install playwright; playwright install
chromium). Credentials arrive as arguments and are never written here.

Seven captures: the inventory, an identity's detail beside the list,
its authorization section with the form, the delta, the imports view,
the campaigns, and, by hand, the report.

Usage:
  capture_screenshots.py BASE_URL USERNAME PASSWORD OUTPUT_DIR
"""
import sys
import time

from playwright.sync_api import sync_playwright


def main() -> int:
    base, user, password, outdir = sys.argv[1:5]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        # Wide enough for the split view, so the detail capture shows
        # the identity beside the list it came from.
        page = browser.new_page(viewport={"width": 1440, "height": 1200})
        page.goto(base)
        page.fill('#signin-form input[name="username"]', user)
        page.fill('#signin-form input[name="password"]', password)
        page.click('#signin-form button[type="submit"]')
        page.wait_for_selector("#identity-rows tr")
        time.sleep(0.5)
        page.screenshot(path=f"{outdir}/inventory.png")

        page.click("#identity-rows tr:first-child")
        page.wait_for_selector("#detail-name")
        time.sleep(0.5)
        page.screenshot(path=f"{outdir}/identity-detail.png")

        # The authorization section: scrolled to the top of the panel so
        # the whole form is on screen, then clipped to the section.
        page.wait_for_selector("#auth-active li")
        box = page.evaluate("""() => {
            const h = [...document.querySelectorAll("h3")]
                .find(e => e.textContent.trim().startsWith("Authorized to hold"));
            const f = document.getElementById("auth-form");
            h.scrollIntoView({block: "start"});
            const a = h.getBoundingClientRect(), b = f.getBoundingClientRect();
            const panel = f.parentElement.getBoundingClientRect();
            return {x: panel.left, y: Math.max(0, a.top - 12),
                    width: panel.width, height: b.bottom - a.top + 24};
        }""")
        time.sleep(0.3)
        page.screenshot(path=f"{outdir}/authorization.png", clip=box)
        page.click("#back")
        page.wait_for_selector("#identity-rows tr")

        page.click('button[data-view="delta"]')
        page.wait_for_selector("#delta-rows tr")
        time.sleep(0.5)
        page.screenshot(path=f"{outdir}/delta.png")

        page.click('button[data-view="imports"]')
        page.wait_for_selector("#import-form")
        time.sleep(1.0)
        page.screenshot(path=f"{outdir}/imports.png")

        page.click('button[data-view="campaigns"]')
        time.sleep(1.0)
        page.screenshot(path=f"{outdir}/campaigns.png")
        browser.close()
    # The report page carries the token in a header, so it is fetched
    # with an authenticated request and screenshotted from the saved
    # file; see the capture notes in the pull request that added this.
    print("captured; fetch report.html with the bearer token and "
          "screenshot the saved file for report.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
