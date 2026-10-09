"""The page, proven by use (1.13).

Every other test of the page scans its markup or reads its routes.
This one drives it: a real browser signs in, opens an identity beside
the list, authorizes a grant, decides a campaign item, reads the delta
by one class, switches the theme, and signs out. It runs against the
application on a throwaway SQLite database seeded by the demo command,
so the page it proves is the page a fresh clone shows.

The browser tree is pinned in its own file (requirements-browser.txt)
and is not part of the image or the ordinary suite; without it this
module skips, and the pipeline's browser job installs it.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parent.parent
ADMIN = "browser.admin"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """The application on its own port over a fresh database, seeded by
    the demo. The administrator's password is made here, used here,
    and never written anywhere."""
    workdir = tmp_path_factory.mktemp("browser")
    password = "browser-" + secrets.token_urlsafe(12)
    env = {
        **os.environ,
        "MANIFEST_IDENTITY_DATABASE_URL": f"sqlite+pysqlite:///{workdir / 'page.db'}",
        "MANIFEST_IDENTITY_ADMIN_USERNAME": ADMIN,
        "MANIFEST_IDENTITY_ADMIN_PASSWORD": password,
        "MANIFEST_IDENTITY_LOG_LEVEL": "WARNING",
    }
    subprocess.run(
        [sys.executable, "-m", "manifest_identity.demo"],
        cwd=ROOT, env=env, check=True, capture_output=True, timeout=300,
    )
    port = _free_port()
    server = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "uvicorn", "manifest_identity.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(base + "/health", timeout=1):  # noqa: S310
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("the server never answered its health check")
        yield {"base": base, "password": password}
    finally:
        server.terminate()
        server.wait(timeout=30)


@pytest.fixture(scope="module")
def page(site: dict[str, str]) -> Iterator[object]:
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1400, "height": 1000})
        page = context.new_page()
        page.set_default_timeout(15_000)
        # A script error anywhere in the walk fails the walk, rather
        # than hiding behind whichever wait times out next.
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.errors = errors  # type: ignore[attr-defined]
        page.goto(site["base"])
        yield page
        browser.close()


def test_sign_in_lands_on_the_inventory(page, site) -> None:  # type: ignore[no-untyped-def]
    page.fill('#signin-form input[name="username"]', ADMIN)
    page.fill('#signin-form input[name="password"]', site["password"])
    page.click('#signin-form button[type="submit"]')
    page.wait_for_selector("#identity-rows tr.clickable")
    assert page.locator("#nav button.current").inner_text().strip() == "Inventory"
    assert page.locator("#dashboard .tile").count() == 5
    assert page.locator("#identity-rows tr.skeleton").count() == 0, "the bones went away"


def test_an_identity_opens_beside_the_list(page) -> None:  # type: ignore[no-untyped-def]
    page.fill("#filter-text", "legacy-mike")
    # The filter waits a beat before asking, so wait for the list to be
    # the filtered one rather than for a row that the full list holds.
    # (A wait written as a page function would be evaluated as a string
    # in the page, which the content policy forbids; the count is
    # polled from outside instead.)
    playwright.expect(page.locator("#identity-rows tr.clickable")).to_have_count(1)
    page.click("#identity-rows tr.clickable:has-text('legacy-mike')")
    page.wait_for_selector("#detail-name:has-text('legacy-mike')")
    assert "split" in page.get_attribute("main", "class")
    assert page.is_visible("#identity-rows"), "the list stays beside the detail"
    assert page.is_visible("#detail")
    tiers = page.locator("#detail-findings .finding-tier").all_inner_texts()
    assert any("critical" in t.lower() for t in tiers)
    # Reloading the list keeps the panel open: the first version closed
    # it on every keystroke in the filter box.
    page.fill("#filter-text", "")
    page.wait_for_selector("#identity-rows tr.clickable >> nth=5")
    assert page.is_visible("#detail-name")
    assert "split" in page.get_attribute("main", "class")
    # And the panel stays in view while the list scrolls under it; the
    # first version stuck to a column that never moved.
    page.mouse.wheel(0, 1500)
    page.wait_for_timeout(300)
    assert page.evaluate("window.scrollY") > 500
    assert page.is_visible("#detail-name")
    assert page.evaluate("document.getElementById('detail').getBoundingClientRect().top") == 0


def test_an_authorization_written_from_the_page_appears_as_held(page) -> None:  # type: ignore[no-untyped-def]
    page.fill('#auth-form input[name="role_definition_external_id"]',
              "github:organization:sample-org:member")
    page.fill('#auth-form input[name="owner_ref"]', "identity-team")
    page.fill('#auth-form input[name="justification"]', "membership is expected")
    page.click('#auth-form button[type="submit"]')
    page.wait_for_selector("#auth-active li:has-text('github:organization:sample-org:member')")
    assert "authorized by browser.admin" in page.locator("#auth-active li").first.inner_text()


def test_closing_the_detail_gives_the_column_back(page) -> None:  # type: ignore[no-untyped-def]
    page.click("#back")
    assert "split" not in page.get_attribute("main", "class")
    assert not page.is_visible("#detail")
    assert page.locator("#identity-rows tr.clickable").count() > 5


def test_a_campaign_item_is_decided_from_the_page(page) -> None:  # type: ignore[no-untyped-def]
    page.click('#nav button[data-view="campaigns"]')
    page.wait_for_selector("#campaign-rows tr.clickable")
    page.click("#campaign-rows tr.clickable >> nth=0")
    page.wait_for_selector("#campaign-items .finding")
    first = page.locator("#campaign-items .finding").first
    first.locator("input.disposition-note").fill("confirmed with the owner")
    first.locator("button >> text=certify").click()
    page.wait_for_selector("#campaign-items .finding:has-text('decided: certify')")
    assert "confirmed with the owner" in page.locator("#campaign-items .finding").first.inner_text()


def test_the_delta_reads_by_one_class(page) -> None:  # type: ignore[no-untyped-def]
    page.click('#nav button[data-view="delta"]')
    page.wait_for_selector("#delta-rows tr:not(.skeleton)")
    tiles = page.locator("#delta-tiles .tile.clickable")
    assert tiles.count() >= 1
    # The tile's label is drawn in capitals by the stylesheet, and the
    # rendered text is what a browser hands back.
    label = tiles.first.locator(".tile-label").inner_text().lower()
    tiles.first.click()
    page.wait_for_selector("#delta-filtered:not([hidden])")
    cells = page.locator("#delta-rows tr td:first-child").all_inner_texts()
    assert {cell.strip().lower() for cell in cells} == {label}
    page.click("#delta-show-all")
    page.wait_for_selector("#delta-filtered[hidden]", state="attached")


def test_the_theme_is_a_choice_that_wins(page) -> None:  # type: ignore[no-untyped-def]
    before = page.evaluate("document.documentElement.dataset.theme || ''")
    page.click("#theme-toggle")
    after = page.evaluate("document.documentElement.dataset.theme")
    assert after in ("dark", "light") and after != before
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") != ""


def test_sign_out_returns_to_the_door(page) -> None:  # type: ignore[no-untyped-def]
    page.click("#signout")
    page.wait_for_selector("#signin:not([hidden])")
    assert not page.is_visible("#nav")
    assert page.errors == [], page.errors
