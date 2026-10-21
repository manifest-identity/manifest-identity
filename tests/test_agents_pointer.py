"""AGENTS.md points to the standards at the build the pipeline pins
(build-doctrine D-050), so moving the pin without the pointer fails."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_pointer_names_the_pinned_build() -> None:
    pinned = re.search(r"ref: ([0-9a-f]{40})", (ROOT / ".github/workflows/ci.yml").read_text())
    assert pinned, "the pipeline no longer pins build-doctrine by commit"
    assert f"/blob/{pinned.group(1)}/STANDARDS.md" in (ROOT / "AGENTS.md").read_text()
