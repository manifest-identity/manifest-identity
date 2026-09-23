#!/usr/bin/env python3
"""Read each pinned image from its one home, for the workflow to use.

The pipeline used to carry a second copy of the Python and PostgreSQL
digests, which an update tool could not see, so every automated bump
arrived half done and failed a gate until a human moved the twin
(D-061). The digests now have one home each, and this prints them in
the form a job step writes to GITHUB_OUTPUT.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOMES = [
    ("python", "Dockerfile", r"(python(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64})"),
    ("postgres", "docker-compose.yml", r"(postgres(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64})"),
]


def main() -> int:
    for name, home, pattern in HOMES:
        found = re.search(pattern, (ROOT / home).read_text())
        if not found:
            print(f"{name}: no pinned image in {home}", file=sys.stderr)
            return 1
        print(f"{name}={found.group(1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
