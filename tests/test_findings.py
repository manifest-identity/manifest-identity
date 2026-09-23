"""The engine and the findings: constructed lifecycles, tiers, the age gate."""

from datetime import UTC, datetime, timedelta

from manifest_identity.derive import derive
from manifest_identity.findings import evaluate
from manifest_identity.models import Observation

AS_OF = datetime(2026, 8, 15, tzinfo=UTC)


def obs(**fields: object) -> Observation:
    base: dict[str, object] = {"display_name": "x", "identity_id": 1, "snapshot_id": 1}
    base.update(fields)
    return Observation(**base)  # type: ignore[arg-type]


def days_ago(n: int) -> datetime:
    return AS_OF - timedelta(days=n)


def state_of(rows: list[tuple[Observation, datetime]], kind: str = "user"):
    s = derive(rows, AS_OF)
    s.identity_type = kind
    return s


def codes(rows, kind="user"):
    return {f.code: f for f in evaluate(state_of(rows, kind))}


def test_staleness_is_against_snapshot_time_not_wall_clock() -> None:
    s = state_of([(obs(key1_active=True, key1_last_used=days_ago(10)), days_ago(20))])
    assert s.last_activity_days == 10  # relative to AS_OF, whenever "now" is


def test_password_without_mfa_is_critical() -> None:
    found = codes([(obs(password_enabled=True, mfa_active=False), days_ago(1))])
    assert found["password_without_mfa"].tier == "critical"
    assert found["password_without_mfa"].anchor == "NHI4"


def test_mfa_present_clears_the_finding() -> None:
    found = codes([(obs(password_enabled=True, mfa_active=True), days_ago(1))])
    assert "password_without_mfa" not in found


def test_root_use_is_critical_and_root_is_never_unused() -> None:
    rows = [(obs(password_last_used=days_ago(3)), days_ago(30))]
    found = codes(rows, kind="root")
    assert found["root_used"].tier == "critical"
    assert "unused_identity" not in found


def test_key_age_tiers() -> None:
    old = codes([(obs(key1_active=True, key1_last_rotated=days_ago(400),
                      key1_last_used=days_ago(2)), days_ago(1))])
    assert old["key_age"].tier == "warning"
    mid = codes([(obs(key1_active=True, key1_last_rotated=days_ago(120),
                      key1_last_used=days_ago(2)), days_ago(1))])
    assert mid["key_age"].tier == "notice"
    fresh = codes([(obs(key1_active=True, key1_last_rotated=days_ago(30),
                        key1_last_used=days_ago(2)), days_ago(1))])
    assert "key_age" not in fresh


def test_unused_needs_the_observation_window() -> None:
    # Watched five days: not flaggable, the age gate holds.
    young = codes([(obs(key1_active=True), days_ago(5))])
    assert "unused_identity" not in young
    # Watched twenty days with no activity: flaggable.
    watched = codes([
        (obs(key1_active=True), days_ago(20)),
        (obs(key1_active=True), days_ago(1)),
    ])
    assert watched["unused_identity"].anchor == "NHI1"
    assert "no recorded activity" in watched["unused_identity"].explanation


def test_recent_activity_clears_unused() -> None:
    found = codes([
        (obs(key1_active=True, key1_last_used=days_ago(10)), days_ago(20)),
        (obs(key1_active=True), days_ago(1)),
    ])
    assert "unused_identity" not in found


def test_merged_view_takes_each_field_from_its_freshest_source() -> None:
    # Credential report knows keys; authorization details knows groups.
    s = state_of([
        (obs(key1_active=True, key1_last_rotated=days_ago(100)), days_ago(9)),
        (obs(group_names=["admins"], attached_policies=[{"name": "p", "arn": "a"}]),
         days_ago(2)),
    ])
    assert s.key1_active is True and s.group_names == ["admins"]
    assert s.attached_policies == 1


def test_multiple_keys_and_legacy_certificate() -> None:
    found = codes([(obs(key1_active=True, key2_active=True, cert1_active=True,
                        key1_last_used=days_ago(1)), days_ago(1))])
    assert found["multiple_active_keys"].tier == "warning"
    assert found["legacy_certificate"].anchor == "NHI7"


def test_every_finding_explains_itself_with_numbers_or_facts() -> None:
    rows = [
        (obs(password_enabled=True, mfa_active=False, key1_active=True,
             key1_last_rotated=days_ago(400), key2_active=True), days_ago(30)),
    ]
    for finding in evaluate(state_of(rows)):
        assert len(finding.explanation) > 20
        assert finding.tier in {"critical", "warning", "notice"}
        assert finding.anchor.startswith("NHI")
