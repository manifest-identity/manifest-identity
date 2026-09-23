"""Privilege heuristics on crafted policies, attribution, and drift.

The policies here are written to be exactly one thing each, so a
failure names the heuristic that broke rather than a soup of them.
"""

from manifest_identity.policy_analysis import read_policy, read_trust_policy
from manifest_identity.privilege import (
    GroupFacts,
    PolicyIndex,
    evaluate_group,
    evaluate_privilege,
    membership_drift,
    read_identity_privilege,
)

ACCOUNT = "123456789012"


def policy(*statements: dict[str, object]) -> dict[str, object]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: object, resource: object = "*", **extra: object) -> dict[str, object]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


ADMIN = policy(allow("*"))
READONLY = policy(allow(["s3:GetObject", "s3:ListBucket"], "arn:aws:s3:::data/*"))


def codes(findings) -> dict[str, object]:
    return {f.code: f for f in findings}


def test_admin_equivalent_by_capability_not_by_name() -> None:
    assert read_policy(ADMIN).admin_equivalent is True
    # A policy whose name says admin but grants two reads is not admin.
    assert read_policy(READONLY).admin_equivalent is False
    assert read_policy(READONLY).privileged is False


def test_create_user_plus_attach_is_admin_in_effect() -> None:
    reading = read_policy(policy(allow(["iam:CreateUser", "iam:AttachUserPolicy"])))
    assert reading.admin_equivalent is True


def test_single_action_escalations_are_each_detected() -> None:
    for action, fragment in (
        ("iam:CreatePolicyVersion", "default version"),
        ("iam:AttachUserPolicy", "attach an administrator policy to itself"),
        ("iam:PutUserPolicy", "inline administrator policy"),
        ("iam:AddUserToGroup", "administrator group"),
        ("iam:CreateAccessKey", "mint credentials"),
        ("iam:UpdateAssumeRolePolicy", "assumable"),
    ):
        reading = read_policy(policy(allow(action, "arn:aws:iam::*:user/*")))
        assert reading.escalation, action
        assert any(fragment in path for path in reading.escalation), action


def test_escalation_is_reported_for_shadow_admins_not_administrators() -> None:
    """The finding that matters is the principal nobody calls an
    administrator that can become one."""
    index = PolicyIndex(managed={
        "admin": ADMIN,
        "shadow": policy(allow("iam:AttachUserPolicy", "arn:aws:iam::*:user/*")),
    })

    def findings_for(arn_key: str):
        return codes(evaluate_privilege(read_identity_privilege(
            identity_key="AIDAX000000000000001", tags={"owner": "t"},
            attached=[{"name": arn_key, "arn": arn_key}], group_names=[],
            trust_policy=None, account_id=ACCOUNT, index=index, groups={},
        )))

    shadow = findings_for("shadow")
    assert shadow["privilege_escalation_capable"].tier == "critical"
    assert "is not an administrator but can become one" in (
        shadow["privilege_escalation_capable"].explanation
    )
    # The administrator's own finding says it plainly; the escalation
    # list underneath would only bury it.
    administrator = findings_for("admin")
    assert "admin_equivalent" in administrator
    assert "privilege_escalation_capable" not in administrator


def test_pass_role_alone_is_ordinary_but_the_pair_escalates() -> None:
    alone = read_policy(policy(allow("iam:PassRole")))
    assert alone.escalation == []
    pair = read_policy(policy(allow(["iam:PassRole", "ec2:RunInstances"])))
    assert any("launch an instance" in path for path in pair.escalation)


def test_wildcards_are_read_at_the_service_level_too() -> None:
    reading = read_policy(policy(allow("s3:*", "*")))
    assert reading.wildcard_action is True
    assert reading.wildcard_write is True
    assert reading.wildcard_resource is True
    assert reading.admin_equivalent is False  # broad, not everything


def test_read_shaped_wildcards_are_a_notice_not_a_warning() -> None:
    """The provider's own read-only policies grant wildcards over read
    operations; scoring them like write access is how a tool gets muted."""
    read_only = read_policy(policy(allow(["s3:Get*", "s3:List*"], "*")))
    assert read_only.wildcard_action is True
    assert read_only.wildcard_write is False
    assert read_only.privileged is False

    index = PolicyIndex(managed={"ro": policy(allow(["s3:Get*", "s3:List*"], "*")),
                                 "rw": policy(allow("s3:*", "*"))})

    def finding_for(key: str):
        return codes(evaluate_privilege(read_identity_privilege(
            identity_key="AIDAX000000000000001", tags={"owner": "t"},
            attached=[{"name": key, "arn": key}], group_names=[],
            trust_policy=None, account_id=ACCOUNT, index=index, groups={},
        )))

    assert finding_for("ro")["broad_read"].tier == "notice"
    assert "wildcard_privilege" not in finding_for("ro")
    assert finding_for("rw")["wildcard_privilege"].tier == "warning"
    assert "broad_read" not in finding_for("rw")


def test_iam_mutating_without_admin() -> None:
    reading = read_policy(policy(allow("iam:UpdateUser", "arn:aws:iam::*:user/*")))
    assert reading.iam_mutating is True
    assert reading.admin_equivalent is False


def test_everything_except_reads_as_broad() -> None:
    reading = read_policy(
        policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    )
    assert reading.negated_allow is True
    assert reading.privileged is True


def test_deny_and_condition_are_noted_not_evaluated() -> None:
    reading = read_policy(policy(
        allow("*", "*", Condition={"StringEquals": {"aws:PrincipalTag/team": "x"}}),
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
    ))
    assert reading.admin_equivalent is True  # the grant is read
    assert reading.conditioned is True and reading.has_deny is True
    explanation = codes(evaluate_privilege(
        read_identity_privilege(
            identity_key="AIDAX000000000000001", tags=None,
            attached=[{"name": "P", "arn": "a"}], group_names=[],
            trust_policy=None, account_id=ACCOUNT,
            index=PolicyIndex(managed={"a": reading and policy(
                allow("*", "*", Condition={"StringEquals": {"x": "y"}}),
                {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
            )}),
            groups={},
        )
    ))["admin_equivalent"].explanation
    # The caveat rides with the claim rather than living in a footnote.
    assert "deny statement is present and is not evaluated" in explanation
    assert "condition is present and is not evaluated" in explanation


def test_malformed_documents_grant_nothing_and_never_raise() -> None:
    for bad in (None, "string", 42, [], {"Statement": "nope"}, {"Statement": [1, 2]},
                {"Statement": [{"Effect": 5}]}, {"Statement": {"Effect": "Allow"}}):
        assert read_policy(bad).privileged is False


def test_privilege_through_a_group_names_the_group() -> None:
    index = PolicyIndex(managed={"arn:policy/admin": ADMIN})
    groups = {
        "automation": GroupFacts(
            name="automation",
            key="AGPAAUTOMATION000001",
            attached=[{"name": "AdministratorAccess", "arn": "arn:policy/admin"}],
            members=["AIDAUSER"],
        )
    }
    picture = read_identity_privilege(
        identity_key="AIDACI00000000000001",
        tags={"owner": "platform"},
        attached=[],
        group_names=["automation"],
        trust_policy=None,
        account_id=ACCOUNT,
        index=index,
        groups=groups,
    )
    finding = codes(evaluate_privilege(picture))["admin_equivalent"]
    assert "through the automation group" in finding.explanation
    assert "AdministratorAccess" in finding.explanation
    assert finding.tier == "critical"


def test_direct_and_group_sources_are_distinguished() -> None:
    index = PolicyIndex(
        managed={"arn:policy/read": READONLY, "arn:policy/admin": ADMIN},
        inline={"AIDACI00000000000001": {"selfmade": ADMIN}},
    )
    picture = read_identity_privilege(
        identity_key="AIDACI00000000000001",
        tags=None,
        attached=[{"name": "ReadOnly", "arn": "arn:policy/read"}],
        group_names=[],
        trust_policy=None,
        account_id=ACCOUNT,
        index=index,
        groups={},
    )
    described = [source.describe() for source in picture.sources]
    assert "ReadOnly, held directly" in described
    assert "inline policy selfmade, held directly" in described


def test_unowned_privileged_is_a_finding_and_owned_is_not() -> None:
    index = PolicyIndex(managed={"a": ADMIN})
    def picture_with(tags: object):
        return read_identity_privilege(
            identity_key="AIDAX000000000000001", tags=tags,
            attached=[{"name": "P", "arn": "a"}], group_names=[],
            trust_policy=None, account_id=ACCOUNT, index=index, groups={},
        )
    assert "unowned_privileged" in codes(evaluate_privilege(picture_with(None)))
    owned = picture_with({"owner": "platform-team"})
    assert "unowned_privileged" not in codes(evaluate_privilege(owned))
    assert owned.owner == "platform-team"


def test_trust_policy_readings() -> None:
    public = read_trust_policy(
        policy({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}),
        ACCOUNT,
    )
    assert public.public is True

    cross = read_trust_policy(policy({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "sts:AssumeRole",
    }), ACCOUNT)
    assert cross.cross_account == ["999999999999"] and cross.public is False

    own = read_trust_policy(policy({
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
        "Action": "sts:AssumeRole",
    }), ACCOUNT)
    assert own.cross_account == []  # same account is not exposure

    service = read_trust_policy(policy({
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }), ACCOUNT)
    assert service.services == ["ec2.amazonaws.com"] and not service.cross_account


def test_trust_findings_tier_on_the_condition() -> None:
    def trust_finding(conditioned: bool):
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole",
        }
        if conditioned:
            statement["Condition"] = {"StringEquals": {"sts:ExternalId": "abc"}}
        picture = read_identity_privilege(
            identity_key="AROAVENDOR0000000001", tags={"owner": "t"},
            attached=[], group_names=[], trust_policy=policy(statement),
            account_id=ACCOUNT, index=PolicyIndex(), groups={},
        )
        return codes(evaluate_privilege(picture))["trust_cross_account"]

    assert trust_finding(conditioned=False).tier == "warning"
    assert trust_finding(conditioned=True).tier == "notice"
    assert "999999999999" in trust_finding(conditioned=False).explanation


def test_group_findings() -> None:
    index = PolicyIndex(managed={"a": ADMIN})
    empty = GroupFacts(name="dormant-admins", key="AGPADORMANT000000001",
                       attached=[{"name": "Admin", "arn": "a"}], members=[])
    reading, findings = evaluate_group(empty, index)
    assert reading.privileged is True
    assert "empty_privileged_group" in codes(findings)
    assert "unowned_privileged_group" in codes(findings)

    plain = GroupFacts(name="readers", key="AGPAREADERS000000001", attached=[], members=["x"])
    _, none_expected = evaluate_group(plain, index)
    assert none_expected == []


def test_membership_drift_reports_both_directions() -> None:
    assert membership_drift("admins", ["a"], ["a"]) == []
    finding = membership_drift("admins", ["a", "b"], ["a", "c"])[0]
    assert finding.code == "membership_drift"
    assert "1 added" in finding.explanation and "1 removed" in finding.explanation
