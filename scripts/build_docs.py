"""Generate the documentation site's pages from the repository's own
documents, so the site has no source of its own to drift.

    python3 scripts/build_docs.py [--out docs/site]

The README becomes the site: everything above its first section is
the home page, and every top-level section becomes a page in README
order, with the section's headings promoted one level so each page
has its own title. SECURITY.md, CONTRIBUTING.md, DECISIONS.md,
AI-USAGE.md, and SCORING.md follow as further pages. Links are rewritten to survive
the split: a heading anchor points at the page that now holds the
heading, images are copied beside the pages, and links to other files
in the repository point at them on GitHub. The output directory is
generated at build time and never committed.
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/tltaylor1/role-call"
EXTRA_PAGES = [
    ("SECURITY.md", "90-security.md"),
    ("CONTRIBUTING.md", "91-contributing.md"),
    ("DECISIONS.md", "92-decisions.md"),
    ("AI-USAGE.md", "93-ai-usage.md"),
    ("SCORING.md", "94-scoring.md"),
]
ASSET_DIRS = {"docs/screenshots": "screenshots", "docs/brand": "brand", "diagrams": "diagrams"}
SKIPPED_SECTIONS = {"Contents"}  # the README's own table of contents
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$", re.MULTILINE)
LINK = re.compile(r"\]\(([^)\s]+)\)")


def slug(text: str) -> str:
    """The anchor both GitHub and the site's toc extension derive from
    a heading: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"[`*_]", "", text).lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text.strip())


def page_name(index: int, title: str) -> str:
    return f"{index:02d}-{slug(title)}.md"


def split_readme(text: str) -> list[tuple[str, str, str]]:
    """(page file, title, body) for the home page and each section."""
    parts = re.split(r"^## ", text, flags=re.MULTILINE)
    pages = [("index.md", "role-call", parts[0].rstrip() + "\n")]
    index = 1
    for part in parts[1:]:
        title, _, body = part.partition("\n")
        title = title.strip()
        if title in SKIPPED_SECTIONS:
            continue
        pages.append((page_name(index, title), title, "# " + title + "\n" + promote(body)))
        index += 1
    return pages


def promote(body: str) -> str:
    """Section headings move up one level so the page's own title is
    its only H1."""
    return HEADING.sub(
        lambda m: ("#" * max(1, len(m.group(1)) - 1)) + " " + m.group(2), body
    )


def anchor_map(pages: list[tuple[str, str, str]]) -> dict[str, str]:
    """Every heading slug to the page that holds it."""
    found: dict[str, str] = {}
    for name, title, body in pages:
        found.setdefault(slug(title), name)
        for m in HEADING.finditer(body):
            found.setdefault(slug(m.group(2)), name)
    return found


def rewrite_links(body: str, own: str, anchors: dict[str, str],
                  extras: dict[str, str]) -> str:
    def fix(m: re.Match[str]) -> str:
        target = m.group(1)
        if target.startswith("#"):
            page = anchors.get(target[1:])
            if page is None or page == own:
                return m.group(0)
            return f"]({page}{target})"
        if target.startswith(("http://", "https://", "mailto:")):
            return m.group(0)
        path, _, fragment = target.partition("#")
        for src, dst in ASSET_DIRS.items():
            if path.startswith(src + "/"):
                return f"]({dst}/{path[len(src) + 1:]})"
        if path in extras:
            return f"]({extras[path]}{'#' + fragment if fragment else ''})"
        if path == "README.md":
            page = anchors.get(fragment, "index.md") if fragment else "index.md"
            return f"]({page}{'#' + fragment if fragment else ''})"
        return f"]({REPO_URL}/blob/main/{path.lstrip('./')}{'#' + fragment if fragment else ''})"
    return LINK.sub(fix, body)


def build(out: Path) -> list[str]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    pages = split_readme((ROOT / "README.md").read_text())
    extras = {src: dst for src, dst in EXTRA_PAGES}
    for src, dst in EXTRA_PAGES:
        pages.append((dst, src, (ROOT / src).read_text()))
    anchors = anchor_map(pages)
    written = []
    for name, _, body in pages:
        (out / name).write_text(rewrite_links(body, name, anchors, extras))
        written.append(name)
    for src, dst in ASSET_DIRS.items():
        if (ROOT / src).is_dir():
            shutil.copytree(ROOT / src, out / dst)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="docs/site")
    args = parser.parse_args()
    written = build(ROOT / args.out)
    print(f"{len(written)} pages written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
