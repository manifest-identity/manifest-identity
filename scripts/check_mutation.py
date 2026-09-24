#!/usr/bin/env python3
"""The mutation check (D-041): break a control, watch the suite notice.

Each mutation below removes one security control the way a refactor
accident would, then runs the tests that claim to prove that control.
A mutation the tests survive is a control whose proof is a claim, and
the check fails naming it. The mutation set is fixed and reviewed
rather than generated, so the kill list is readable in one screen and
runs in minutes, not hours; what it trades away is discovery of
untargeted gaps, which the coverage floor bounds from the other side.

Run from the repository root on a clean tree; every file is restored
whether or not the run succeeds.
"""

import subprocess
import sys
from pathlib import Path

MUTATIONS: list[tuple[str, str, str, str, list[str]]] = [
    (
        "authorization check removed",
        "manifest_identity/core/deps.py",
        "        if not held & {r.value for r in allowed}:",
        "        if False:",
        ["tests/test_matrix.py"],
    ),
    (
        "the scope check answers yes for every node",
        # The control D-070 and D-072 add: a binding at one node must
        # not act on another. Removing it leaves the matrix check
        # passing, which is exactly why the scoped pass exists.
        "manifest_identity/core/scope.py",
        "        if binding.role in wanted and binding.scope_node_id in covering:",
        "        if binding.role in wanted:",
        ["tests/test_scope.py"],
    ),
    (
        "the organization's required fields stop being enforced",
        "manifest_identity/authorize/authorizations.py",
        '    if options.get_bool(db, "authorization.justification_required") and not (',
        "    if False and not (",
        ["tests/test_authorizations.py"],
    ),
    (
        "an expired authorization still reads as live",
        # Expiry is the clock compared to a column (D-073's record): if
        # the comparison goes, every lapsed access reports as current
        # and the delta lies in the safest-looking direction.
        "manifest_identity/authorize/authorizations.py",
        "    if row.status == AuthorizationStatus.authorized and is_expired(row, now):",
        "    if False:",
        ["tests/test_authorizations.py"],
    ),
    (
        "audit rows silently dropped",
        "manifest_identity/core/audit.py",
        "    db.add(event)",
        "    return\n    db.add(event)",
        ["tests/test_governance.py"],
    ),
    (
        "session tokens no longer hashed uniquely",
        "manifest_identity/core/security.py",
        "    return hashlib.sha256(token.encode()).hexdigest()",
        "    return \"0\" * 64",
        ["tests/test_auth.py"],
    ),
    (
        "rate limiter always allows",
        "manifest_identity/core/ratelimit.py",
        "        kept = [t for t in self._failures.get(key, [])"
        " if now - t < self.window_seconds]",
        "        kept: list[float] = []\n"
        "        _ = [t for t in self._failures.get(key, [])"
        " if now - t < self.window_seconds]",
        ["tests/test_ratelimit.py"],
    ),
    (
        "formula escaping removed from the CSV exit",
        "manifest_identity/decide/reports.py",
        "    if text.startswith(FORMULA_LEADERS):",
        "    if False:",
        ["tests/test_reports.py"],
    ),
    (
        "assigned owners no longer answer the unowned finding",
        "manifest_identity/authorize/governance.py",
        "    if effective is not None and effective.source == \"assigned\":",
        "    if False:",
        ["tests/test_governance.py"],
    ),
    (
        "campaigns close with undecided items",
        "manifest_identity/decide/routes_campaigns.py",
        "    if open_items:",
        "    if False:",
        ["tests/test_campaigns.py"],
    ),
]


def run_tests(paths: list[str]) -> int:
    # The argument list is the fixed literal above plus reviewed test
    # paths from MUTATIONS; nothing here is caller-supplied.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
         *paths],
        capture_output=True,
    ).returncode


def main() -> int:
    survived: list[str] = []
    for name, filename, original, mutated, tests in MUTATIONS:
        path = Path(filename)
        source = path.read_text()
        if original not in source:
            print(f"mutation anchor missing in {filename}: {name}",
                  file=sys.stderr)
            return 2
        path.write_text(source.replace(original, mutated, 1))
        try:
            code = run_tests(tests)
        finally:
            path.write_text(source)
        if code == 0:
            survived.append(f"{name} ({filename}; {', '.join(tests)} passed)")
            print(f"SURVIVED: {name}", file=sys.stderr)
        else:
            print(f"killed: {name}")
    if survived:
        print(
            "mutation check: the tests above claim a control they do not "
            "prove", file=sys.stderr,
        )
        return 1
    print(f"mutation check: {len(MUTATIONS)} of {len(MUTATIONS)} killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
