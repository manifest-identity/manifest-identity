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
        # 1.6: access that arrives by assuming a role is the half an
        # inventory of attached policies cannot see. Treating it as
        # standing would hide it inside what an identity already holds.
        "assumable access is reported as if it were held",
        "manifest_identity/observe/paths.py",
        "            add(grant, list(chain), GrantMode.eligible)",
        "            add(grant, list(chain), GrantMode.standing)",
        ["tests/test_paths.py", "tests/test_delta.py"],
    ),
    (
        # The door itself: a trust nobody authorized is a finding about
        # the way in, and reporting no doors leaves every grant behind
        # them reading as neatly owned.
        "the doors an identity may cross are not reported",
        "manifest_identity/observe/paths.py",
        "        for row in _assumable_by(db, import_id, identity)",
        "        for row in []",
        ["tests/test_delta.py"],
    ),
    (
        # 1.7: the finding that names what a changed definition gained.
        # Without the names it says "the role changed", which tells a
        # reviewer to look and not what to look at.
        "the actions a changed definition gained go unnamed",
        "manifest_identity/observe/policy_analysis.py",
        "        added=sorted(now - was),",
        "        added=[],",
        ["tests/test_role_definitions.py"],
    ),
    (
        # A custom definition nobody authorized is the row worth reading
        # on that page, and losing it leaves every custom policy reading
        # as owned when nobody said so.
        "a custom definition nobody authorized goes unreported",
        "manifest_identity/compare/delta.py",
        "            if standing is None:",
        "            if False:",
        ["tests/test_role_definitions.py"],
    ),
    (
        # 1.8: a campaign driven by the delta must be populated by it.
        # Reading nothing leaves the campaign empty, which the route
        # refuses, and the test for the trigger must notice.
        "a delta-driven campaign ignores the delta",
        "manifest_identity/decide/routes_campaigns.py",
        "    for finding in delta.for_estate(db):",
        "    for finding in []:",
        ["tests/test_campaigns.py"],
    ),
    (
        # 1.9: a delivery that fails must be recorded as failed. Recording
        # it as delivered is the lie the whole table exists to prevent.
        "a failed delivery is recorded as delivered",
        "manifest_identity/decide/alerts.py",
        "            result, note = RESULT_FAILED, f",
        "            result, note = RESULT_RECORDED, f",
        ["tests/test_alerts.py"],
    ),
    (
        # 1.10: a revoked token must stop opening the read surface.
        "a revoked integration token still reads",
        "manifest_identity/api/deps.py",
        "    if row is None or row.revoked_at is not None:",
        "    if row is None:",
        ["tests/test_api.py"],
    ),
    (
        # 1.11: the source check must refuse a file shaped as another
        # source, or a credential report gets parsed as a table.
        "the source check accepts a mismatched file",
        "manifest_identity/observe/routes_imports.py",
        "    if found is not None and found != expected:",
        "    if False:",
        ["tests/test_generic_import.py"],
    ),
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
        "a file import stops naming the mapping that read it",
        # The property D-074 is built for: without the batch link, a
        # mapping later found wrong leaves nothing to find.
        "manifest_identity/authorize/csv_import.py",
        "        written.batch_id = batch.id",
        "        written.batch_id = None",
        ["tests/test_csv_import.py"],
    ),
    (
        "a date is guessed when the mapping declares no format",
        "manifest_identity/observe/mapping.py",
        "    if not fmt:",
        "    if False:",
        ["tests/test_csv_import.py"],
    ),
    (
        "the delta stops noticing access nobody authorized",
        # The product's central finding. Without it the page reports
        # agreement on an estate full of unauthorized access, which is
        # the failure that looks like success.
        "manifest_identity/compare/delta.py",
        "        if key not in live_keys:",
        "        if False:",
        ["tests/test_delta.py"],
    ),
    (
        "an expired authorization still covers the access it granted",
        "manifest_identity/compare/delta.py",
        "        if status == AuthorizationStatus.expired:",
        "        if False:",
        ["tests/test_delta.py"],
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
    (
        # 1.12: a provider whose roles are fixed levels reaches the
        # finding engine through a capability document. If the reading
        # ignored it, an organization owner would read as nobody.
        "a capability document that administers reads as nothing",
        "manifest_identity/observe/policy_analysis.py",
        '        reading.admin_equivalent = document.get("administers") is True',
        "        reading.admin_equivalent = False",
        ["tests/test_github_import.py"],
    ),
    (
        # A child team's members hold what the parent holds, by the
        # provider's rule; writing only the child's membership would
        # hide the parent's grants from everyone who inherits them.
        "a child team's members are not the parent's members",
        "manifest_identity/observe/github_importer.py",
        "            for ancestor in chain:",
        "            for ancestor in chain[:1]:",
        ["tests/test_github_import.py"],
    ),
    (
        # 1.14b: bind and escalate are the verbs that hand out roles.
        # A reading that ignored them would call a role that can make
        # itself cluster-admin harmless.
        "the verbs that hand out roles do not change access",
        "manifest_identity/observe/kubernetes_importer.py",
        "        if verbs & ACCESS_VERBS:",
        "        if False:",
        ["tests/test_kubernetes_import.py"],
    ),
    (
        # A RoleBinding grants inside its namespace; recording it at the
        # cluster would hand a namespace editor the whole cluster.
        "a namespace binding is recorded at the cluster",
        "manifest_identity/observe/kubernetes_importer.py",
        "        node = namespace_node(binding.namespace) if binding.namespace else cluster_node",
        "        node = cluster_node",
        ["tests/test_kubernetes_import.py"],
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
