#!/usr/bin/env python3
"""The docs-truth gate (D-031, narrowed at the control-plane split).

The phase-status machinery moved to control-plane with the
journey diagram; what remains here is the ban on the specific stale
claims that once sat in public documents for weeks. Scoped to the
status-bearing documents on purpose, so history-keeping files can
still quote them.

Run from the repository root; exits nonzero with the rule that failed.
"""

import sys
from pathlib import Path

FORBIDDEN = {
    "README.md": ["No application code exists", "does not exist yet",
                  "The skeleton runs", "Phase 0 is in progress"],
    "SECURITY.md": ["does not exist yet", "No application code exists"],
}


def main() -> int:
    failures: list[str] = []
    for name, phrases in FORBIDDEN.items():
        text = Path(name).read_text()
        for phrase in phrases:
            if phrase in text:
                failures.append(f"{name} contains the stale claim: {phrase!r}")
    for failure in failures:
        print(f"docs-truth: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
