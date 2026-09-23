#!/usr/bin/env python3
"""Each image digest has one home, and the workflows hold no copy.

The parity gate this replaces held two copies of the same digest in
agreement. Agreement was the wrong goal: an update tool moves the home
and cannot see the copy, so every automated bump failed until a human
moved the copy by hand (D-061). The copies are gone, and this refuses
their return.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOMES = [
    ("python", "Dockerfile", r"python(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}"),
    ("postgres", "docker-compose.yml", r"postgres(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}"),
]


def main() -> int:
    failures = []
    for name, home, pattern in HOMES:
        if not re.search(pattern, (ROOT / home).read_text()):
            failures.append(f"{name}: no pinned image in {home}, which is its one home")
        for workflow in sorted(ROOT.glob(".github/workflows/*.yml")):
            if re.search(pattern, workflow.read_text()):
                failures.append(
                    f"{name}: {workflow.relative_to(ROOT)} carries a second copy of the "
                    f"digest; read it from {home} through the resolve job instead"
                )
    for line in failures:
        print(line)
    if failures:
        return 1
    print(f"digest homes are single: {', '.join(n for n, _, _ in HOMES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
