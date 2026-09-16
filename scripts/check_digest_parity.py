#!/usr/bin/env python3
"""The digest-parity gate.

Two invariants live in comments and nowhere else: the pipeline tests in
the same Python image the Dockerfile ships, and against the same
PostgreSQL digest the compose file runs. Automated update tools cannot
see the workflow-embedded copies, so a hand bump that touches one file
and misses its twin lands silently. This check makes the comments a
mechanism: extract each digest from both homes and fail on mismatch.
"""

import re
import sys
from pathlib import Path


def digest(path: str, image: str) -> str | None:
    match = re.search(image + r"(?::[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})", Path(path).read_text())
    return match.group(1) if match else None


def main() -> int:
    failures = []
    pairs = [
        ("python", "Dockerfile", ".github/workflows/ci.yml"),
        ("postgres", "docker-compose.yml", ".github/workflows/ci.yml"),
    ]
    for image, home, twin in pairs:
        a, b = digest(home, image), digest(twin, image)
        if a is None or b is None:
            failures.append(
                f"{image}: digest missing from {home if a is None else twin}"
            )
        elif a != b:
            failures.append(
                f"{image}: {home} and {twin} disagree; move both in one commit"
            )
    # Single pins with no twin still need a named watcher, and this
    # check is it: the workflow-embedded GuardDog image is invisible
    # to update automation, and its two uses must carry one digest.
    guarddog = re.findall(
        r"ghcr\.io/datadog/guarddog@(sha256:[0-9a-f]{64})",
        Path(".github/workflows/ci.yml").read_text(),
    )
    if not guarddog:
        failures.append("guarddog: digest missing from ci.yml")
    elif len(set(guarddog)) > 1:
        failures.append("guarddog: ci.yml uses two digests; move both in one commit")
    for failure in failures:
        print(f"digest-parity: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
