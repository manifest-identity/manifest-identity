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
    (
        # 1.14c: a key the provider manages rotates on its own and is
        # nobody's credential; a key a person made is. Writing both as
        # credentials would flag every account for keys it cannot lose.
        "a provider-managed key is recorded as a credential",
        "manifest_identity/observe/google_cloud_importer.py",
        "            if not key.user_managed:",
        "            if False:",
        ["tests/test_google_cloud_import.py"],
    ),
    (
        # The permission that sets a policy is the one that changes who
        # holds what; a reading that ignored it would call a role that
        # can grant itself owner harmless.
        "a permission that sets policy does not change access",
        "manifest_identity/observe/google_cloud_importer.py",
        "        p in ACCESS_PERMISSIONS or p.endswith(ACCESS_PERMISSION_SUFFIXES)"
        " for p in permissions",
        "        p in ACCESS_PERMISSIONS for p in permissions",
        ["tests/test_google_cloud_import.py"],
    ),
    (
        # 1.14d: an eligibility is what an identity can obtain, and
        # recording it as standing would report every eligible
        # administrator as one already.
        "an eligibility is recorded as standing access",
        "manifest_identity/observe/azure_importer.py",
        "            mode=GrantMode.eligible, path=list(DIRECT),",
        "            mode=GrantMode.standing, path=list(DIRECT),",
        ["tests/test_azure_import.py"],
    ),
    (
        # A guest is from another tenant; recording it as a member
        # would give a contractor's account a password it does not hold
        # here and hide that it is a guest at all.
        "a guest is recorded as a member of the directory",
        "manifest_identity/observe/azure_importer.py",
        "        if user.guest:",
        "        if False:",
        ["tests/test_azure_import.py"],
    ),
    (
        # 1.14e: a federated user's password lives in the directory or
        # the identity provider that federates; writing one here would
        # flag every federated account for a second factor Okta does
        # not hold and mark it unused when Okta never sees it sign in.
        "a federated user is given an Okta password",
        "manifest_identity/observe/okta_importer.py",
        '        if user.provider_type == "OKTA":',
        "        if True:",
        ["tests/test_okta_import.py"],
    ),
    (
        # A role assigned to a group reaches its members through the
        # hop; dropping inactive assignments is right, dropping all of
        # them would hide every administrator assigned by group.
        "an inactive role assignment is recorded as held",
        "manifest_identity/observe/okta_importer.py",
        "        if not row.active:",
        "        if False:",
        ["tests/test_okta_import.py"],
    ),
    (
        # D-083: a disabled account's password is not a live credential;
        # recording it as one would flag every leaver for a stale key
        # and count every disabled administrator as one still held.
        "a disabled account's password is recorded as live",
        "manifest_identity/observe/active_directory_importer.py",
        '            kind=CredentialKind.password, external_id="password", active=account.enabled,',
        '            kind=CredentialKind.password, external_id="password", active=True,',
        ["tests/test_active_directory_import.py"],
    ),
    (
        # D-084: an inherited right is the directory's default flowing
        # down the tree, not a grant someone made; writing it would put
        # the built-in administrators on every object as able to obtain
        # what they already hold, and bury the one right that matters.
        "an inherited control right is recorded as obtainable",
        "manifest_identity/observe/active_directory_importer.py",
        "        if ace.inherited or ace.right in READ_ONLY_RIGHTS"
        " or ace.principal_sid in administers:",
        "        if ace.right in READ_ONLY_RIGHTS or ace.principal_sid in administers:",
        ["tests/test_active_directory_import.py"],
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


def table() -> str:
    """The mutation set as the README's table, generated so the count
    the document states is the count the check runs; a test holds the
    two together the way the route enumeration is held."""
    lines = ["| Mutation | Killed by |", "|---|---|"]
    for name, _filename, _original, _mutated, tests in MUTATIONS:
        suites = ", ".join(t.removeprefix("tests/test_").removesuffix(".py") for t in tests)
        lines.append(f"| {name[0].upper() + name[1:]} | the {suites} tests |")
    return "\n".join(lines) + "\n"


def main() -> int:
    if "--table" in sys.argv:
        print(table(), end="")
        return 0
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
