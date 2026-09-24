"""The page: served, headed, and unable to render markup.

Imported files control identity names, tags, and policy text, so this
suite treats the page as the place that content finally lands. The
scan is a gate rather than a habit: a future edit that reaches for a
markup sink fails the build instead of a review.
"""

from html.parser import HTMLParser
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.reportlib import HEADER

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

# Sinks that turn a string into markup or code. The page builds every
# element through the document interface instead, so none of these has
# a legitimate use here; a future one is a decision, not a detail.
FORBIDDEN_IN_SCRIPT = (
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "eval(", "new Function(", "dangerouslySet",
)

PAYLOAD = '<img src=x onerror="alert(1)">'


def script_without_comments() -> str:
    """Comments may name the sinks they warn about; code may not."""
    lines = []
    for line in (FRONTEND / "app.js").read_text().splitlines():
        if line.strip().startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)


def test_the_page_has_no_markup_sink() -> None:
    code = script_without_comments()
    for sink in FORBIDDEN_IN_SCRIPT:
        assert sink not in code, f"the page reaches for {sink}"


class MarkupScan(HTMLParser):
    """A real parser rather than an expression that looks like one.

    Matching tags with a regular expression is bypassable in ways this
    check would never see, which a static analyser pointed out about
    the first version of this test: a gate that a crafted tag can walk
    past is not a gate. The parser handles the evasions by construction.
    """

    def __init__(self) -> None:
        super().__init__()
        self.inline_script: list[str] = []
        self.handlers: list[str] = []
        self.styles: list[str] = []
        self._in_script = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        for name, _value in attrs:
            if name.lower().startswith("on"):
                self.handlers.append(f"{tag}[{name}]")
            if name.lower() == "style":
                self.styles.append(tag)
        if tag.lower() == "script":
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_script.append(data.strip()[:40])


def test_the_markup_has_no_inline_script_or_handler() -> None:
    """The content policy forbids inline execution; this proves the
    page does not need it, so the policy can stay strict."""
    scan = MarkupScan()
    scan.feed((FRONTEND / "index.html").read_text())
    assert not scan.inline_script, f"inline script: {scan.inline_script}"
    assert not scan.handlers, f"inline event handler: {scan.handlers}"
    assert not scan.styles, f"inline style attribute: {scan.styles}"


def test_the_markup_scan_notices_what_it_is_looking_for() -> None:
    """The gate is tested against the thing it exists to catch,
    including the shapes a pattern match would have missed."""
    for hostile in (
        "<script>alert(1)</script>",
        "<script >alert(1)</script >",
        "<script\ntype='text/javascript'>alert(1)</script>",
        "<div onclick='x()'>",
        "<div style='color:red'>",
    ):
        scan = MarkupScan()
        scan.feed(hostile)
        assert scan.inline_script or scan.handlers or scan.styles, hostile


def test_the_shell_is_served_with_its_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    policy = response.headers["content-security-policy"]
    assert "default-src 'self'" in policy
    assert "'unsafe-inline'" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"


def test_the_assets_are_served(client: TestClient) -> None:
    for path, kind in (("/static/app.js", "javascript"), ("/static/app.css", "css"),
                       ("/static/favicon.svg", "svg")):
        response = client.get(path)
        assert response.status_code == 200, path
        assert kind in response.headers["content-type"]


def test_api_responses_carry_the_headers_too(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, ROLE_USERS[Role.reviewer])
    response = client.get("/identities", headers=auth_header(token))
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in response.headers


def test_the_timeline_names_each_source_correctly(
    client: TestClient, db: Session
) -> None:
    """Both formats import at the same capture time, so a timeline
    keyed by time labels half the rows with the wrong source. Found by
    reading the rendered page, not by a passing test."""
    from manifest_identity.sample_data import GENERATIONS, file_set

    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    files = file_set()
    captured = GENERATIONS[0]
    day = captured.strftime("%Y-%m-%d")
    for name, route in (
        (f"{day}-credential-report.csv", "credential-report"),
        (f"{day}-authorization-details.json", "authorization-details"),
    ):
        client.post(
            f"/imports/{route}",
            headers=auth_header(token),
            files={"file": (name, files[name].encode(), "text/plain")},
            data={"captured_at": captured.isoformat()},
        )
    rows = client.get("/identities", headers=auth_header(token)).json()["rows"]
    target = [r for r in rows if r["display_name"] == "ci-deployer"][0]
    detail = client.get(
        f"/identities/{target['id']}", headers=auth_header(token)
    ).json()
    sources = {entry["source"] for entry in detail["timeline"]}
    assert sources == {"aws_credential_report", "aws_authorization_details"}


def test_hostile_names_survive_as_data_and_never_as_markup(
    client: TestClient, db: Session
) -> None:
    """The end-to-end canary: a name that is markup goes in through an
    import, comes back as a JSON string, and appears nowhere in the
    page the browser parses."""
    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    report = (
        HEADER + "\n"
        + f"{PAYLOAD},arn:aws:iam::123456789012:user/hostile,"
        "2025-01-01T00:00:00+00:00,FALSE,N/A,N/A,N/A,FALSE,"
        "FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,FALSE,N/A\n"
    ).encode()
    created = client.post(
        "/imports/credential-report",
        headers=auth_header(token),
        files={"file": ("hostile.csv", report, "text/csv")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert created.status_code == 201, created.text

    listed = client.get("/identities", headers=auth_header(token))
    assert "application/json" in listed.headers["content-type"]
    # The value is preserved exactly, because mangling data to make it
    # safe is how a tool starts lying about what it found.
    names = [row["display_name"] for row in listed.json()["rows"]]
    assert PAYLOAD in names
    # And it is delivered as a JSON string, not as a document a browser
    # would parse as markup.
    assert "<img" not in listed.text or '"<img' in listed.text

    # The shell is static: nothing from the database is templated into it.
    shell = client.get("/")
    assert PAYLOAD not in shell.text
    assert "hostile" not in shell.text


def test_the_hidden_attribute_always_wins_in_the_stylesheet() -> None:
    """The nav's flex rule silently overrode the hidden attribute and
    put the app tabs on the sign-in page. The stylesheet must carry
    the guard that makes hidden final, ahead of every display rule."""
    css = Path(__file__).parent.parent.joinpath(
        "frontend", "app.css"
    ).read_text()
    guard = css.find("[hidden] { display: none !important; }")
    assert guard != -1, "the [hidden] guard left the stylesheet"
    # Ahead of the first element display rule, so ordering never
    # becomes the next version of this bug.
    assert guard < css.find("nav { display:")


def test_the_shell_names_its_icon_and_its_empty_states() -> None:
    """The tab icon is same-origin, which the content policy requires,
    and each of the three list views carries one static sentence for
    the empty case, hidden until the render decides."""
    html = (FRONTEND / "index.html").read_text()
    assert 'rel="icon"' in html and 'href="/static/favicon.svg"' in html
    for view in ("inventory", "groups", "campaigns"):
        assert f'id="{view}-empty" class="empty" hidden' in html, view
    script = (FRONTEND / "app.js").read_text()
    for view in ("inventory", "groups", "campaigns"):
        assert f'$("{view}-empty").hidden = rows.length !== 0;' in script, view


def test_the_scopes_view_ships_hidden_and_is_gated_by_role() -> None:
    """The scope tree is read through an administrative route, so the
    button that asks for it must not be on the page for anyone else.
    It ships hidden in the markup and is shown only when the roles the
    session reports include administrator; a button that appears and
    then fails with a 403 teaches users to ignore refusals."""
    html = (FRONTEND / "index.html").read_text()
    assert '<button id="nav-scopes" data-view="scopes" hidden>' in html
    assert '<section id="scopes" hidden>' in html
    js = (FRONTEND / "app.js").read_text()
    assert '$("nav-scopes").hidden = !currentRoles.includes("administrator");' in js
    # The view is in the switcher's list, or showing it would leave the
    # previous view on the page beneath it.
    assert '"scopes",' in js


def test_the_authorization_form_offers_only_what_the_rules_need() -> None:
    """The second owner appears when a person owns it, and the group
    name when access arrives through one. A form that always asks for
    everything teaches people to fill fields in without reading them,
    and a form that never asks cannot express the rule the server
    enforces (D-038, D-073)."""
    html = (FRONTEND / "index.html").read_text()
    assert '<form id="auth-form" hidden>' in html
    # Both conditional blocks ship hidden, so the server's rule and the
    # page's first paint agree before any script runs.
    assert '<label id="auth-ref-label" hidden>' in html
    assert '<fieldset id="auth-secondary" hidden>' in html
    js = (FRONTEND / "app.js").read_text()
    assert '$("auth-secondary").hidden = ownerKind.value !== "individual";' in js
    assert '$("auth-ref-label").hidden = via.value === "direct";' in js
    # Written by the operator and the administrator, read by everyone,
    # matching the matrix rather than restating it.
    assert '$("auth-form").hidden = currentRole === "reviewer";' in js


def test_the_page_never_asks_who_authorized_something() -> None:
    """The authorizer comes from the session (threat 14). A field for
    it on the page would be the first step toward a field for it in
    the request, so there is not one."""
    html = (FRONTEND / "index.html").read_text()
    start = html.index('<form id="auth-form"')
    form = html[start:html.index("</form>", start)]
    for forbidden in ("authorizer", "authorized_at", "status"):
        assert forbidden not in form, f"the form offers {forbidden}"


def test_a_revocation_asks_for_its_reason() -> None:
    """The server refuses an empty reason; the page refuses to send
    one, so the person hears it before the round trip."""
    js = (FRONTEND / "app.js").read_text()
    assert 'window.prompt("Why is this being revoked?")' in js
    assert "if (!reason || !reason.trim()) return;" in js


def test_the_delta_view_says_when_each_side_was_last_heard_from() -> None:
    """A finding without its two timestamps is a claim, so the table
    carries both columns and the page says why they are there."""
    html = (FRONTEND / "index.html").read_text()
    assert '<section id="delta" hidden>' in html
    assert "<th>observed</th><th>authorized</th>" in html
    assert "stale side makes a" in html
    js = (FRONTEND / "app.js").read_text()
    assert 'f.observed_as_of || "never"' in js
    assert 'f.authorized_as_of || "never"' in js
