#!/usr/bin/env python3
"""The actions inventory gate: the README names every action, and every
action is pinned by commit hash.

The workflows stand on third-party code the same way the application
stands on packages, so the README documents each action and each
workflow-run image with what it does. The table names them; it does not
repeat their pins, because a pin in two places is a pin an update tool
can only half move (D-061). What this holds instead is the property that
matters: every use is pinned to a full commit hash, and nothing runs
that the table does not name.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
# One character class rather than a repeated group: a nested quantifier
# over overlapping classes backtracks exponentially on a hostile string,
# which the deep analysis caught in the first draft of this file.
IMAGE = re.compile(r"docker run[^\n]*?([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})")
NAMED = re.compile(r"`([A-Za-z0-9_./-]+)`")


def main() -> int:
    unpinned: list[str] = []
    actions: set[str] = set()
    images: set[str] = set()
    for workflow in sorted(ROOT.glob(".github/workflows/*.yml")):
        text = workflow.read_text()
        where = workflow.relative_to(ROOT)
        for ref in USES.findall(text):
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            name, _, version = ref.partition("@")
            if not re.fullmatch(r"[0-9a-f]{40}", version):
                unpinned.append(f"{where}: {ref} is not pinned to a full commit hash")
            actions.add(name)
        images |= {image for image, _ in IMAGE.findall(text)}

    named = set(NAMED.findall((ROOT / "README.md").read_text()))
    problems = list(unpinned)
    for action in sorted(actions - named):
        problems.append(f"in a workflow but not named in the README table: {action}")
    for image in sorted(images - named):
        problems.append(f"run by a workflow but not in the README image table: {image}")

    for line in problems:
        print(line)
    if problems:
        return 1
    print(
        f"actions inventory matches: {len(actions)} actions and {len(images)} "
        f"workflow-run images, every use pinned by commit hash"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
