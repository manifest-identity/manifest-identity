"""The documentation site is generated from the documents, never
written beside them.

The generator splits the README into pages and rewrites links so the
split cannot strand a reader: every anchor the README uses resolves
to the page that now holds its heading, images travel with the
pages, and links to other repository files point at GitHub. The page
count follows the README's section count, so a section added without
the site noticing is impossible.
"""

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_docs  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_every_readme_section_becomes_a_page_and_every_anchor_resolves() -> None:
    readme = ROOT.joinpath("README.md").read_text()
    sections = [
        m.group(1) for m in re.finditer(r"^## (.+)$", readme, re.MULTILINE)
        if m.group(1) not in build_docs.SKIPPED_SECTIONS
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "site"
        written = build_docs.build(out)
        pages = [name for name in written if name[:2].isdigit() and name[:2] < "80"]
        assert len(pages) == len(sections), (pages, sections)
        assert "index.md" in written
        assert all(dst in written for _, dst in build_docs.EXTRA_PAGES)
        # Every anchor in every page names a heading that exists somewhere
        # in the generated site, on the page the link points at.
        headings: dict[str, set[str]] = {}
        for name in written:
            body = (out / name).read_text()
            headings[name] = {
                build_docs.slug(m.group(2))
                for m in build_docs.HEADING.finditer(body)
            }
        for name in written:
            body = (out / name).read_text()
            for m in re.finditer(r"\]\(([\w.-]+\.md)?#([\w-]+)\)", body):
                page = m.group(1) or name
                assert m.group(2) in headings[page], (name, m.group(0))
        # Images travel with the pages, and repository files point home.
        index = (out / "index.md").read_text()
        assert "](screenshots/" in index or "](screenshots/" in (out / pages[3]).read_text() or any(
            "](screenshots/" in (out / p).read_text() for p in pages
        )
        assert (out / "screenshots").is_dir()
        assert "docs/screenshots/" not in "".join((out / p).read_text() for p in written)
