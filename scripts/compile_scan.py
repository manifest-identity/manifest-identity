#!/usr/bin/env python3
"""Compile the scanner tree, then override one pin the compiler cannot.

    python -m scripts.compile_scan        # or: .venv/bin/python scripts/compile_scan.py

Semgrep declares PyJWT ~=2.13.0, a line that carries twelve published
advisories, all in token verification paths Semgrep never runs here.
The resolver honors the declaration, so pip-compile alone leaves the
vulnerable pin in requirements-scan.txt and every audit of the tree
refuses it. This script runs the compile and then replaces the PyJWT
block with the fixed release, hashes read from the index for every
file of that release, so the tree stays installable with hashes
enforced. The pipeline installs the tree with --no-deps, which is
what makes the override hold: a complete lockfile needs no resolver
at install time. Semgrep 1.178.0 was run against this repository with
the override in place before it was recorded (D-086).

A recompile that skips this script puts the vulnerable pin back, and
tests/test_scans.py fails on it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TREE = ROOT / "requirements-scan.txt"
OVERRIDE = ("pyjwt", "2.15.1")
INDEX = "https://pypi.org/pypi/{name}/{version}/json"


def release_hashes(name: str, version: str) -> list[str]:
    url = INDEX.format(name=name, version=version)
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme, parts.netloc) != ("https", "pypi.org"):
        raise SystemExit(f"refusing to read {url}: the index is the only source")
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310  # scheme and host checked above
        files = json.load(r)["urls"]
    hashes = sorted(f["digests"]["sha256"] for f in files if not f.get("yanked"))
    if not hashes:
        raise SystemExit(f"{name} {version}: the index lists no files")
    return hashes


def override(text: str, name: str, version: str, hashes: list[str]) -> str:
    block = re.compile(rf"^{name}==\S+ \\\n(?:    --hash=\S+(?: \\)?\n)+", re.M)
    if not block.search(text):
        raise SystemExit(f"{name} is not pinned in {TREE.name}; nothing to override")
    lines = [f"{name}=={version} \\"] + [f"    --hash=sha256:{h} \\" for h in hashes]
    lines[-1] = lines[-1][:-2]
    note = (
        "# Overridden by scripts/compile_scan.py: semgrep declares ~=2.13.0,\n"
        "# which carries twelve advisories; the tree installs with --no-deps.\n"
    )
    return block.sub(note + "\n".join(lines) + "\n", text, count=1)


def main() -> int:
    subprocess.run(
        [sys.executable, "-m", "piptools", "compile", "--generate-hashes",
         "--strip-extras", "--quiet", "requirements-scan.in"],
        cwd=ROOT, check=True, timeout=600,
    )
    name, version = OVERRIDE
    TREE.write_text(override(TREE.read_text(), name, version, release_hashes(name, version)))
    print(f"{TREE.name}: compiled, {name} overridden to {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
