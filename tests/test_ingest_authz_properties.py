"""The JSON fuzz suite: the second parser held to the first's contract."""

import json

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from manifest_identity.observe.providers.aws.authorization_details import (
    ParseError,
    parse_authorization_details,
)

CANARY = "canary-value-must-not-reflect"

json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.text(max_size=40),
    st.just(CANARY),
    st.just("x" * 3000),
    st.just("=cmd()"),
)
json_value = st.recursive(
    json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=20), children, max_size=4),
    ),
    max_leaves=25,
)


@given(data=st.binary(max_size=4096))
@example(data=b"")
@example(data=b"{}")
@example(data=b"[]")
@example(data=b'{"IsTruncated": true}')
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_crash_unhandled(data: bytes) -> None:
    try:
        parse_authorization_details(data)
    except ParseError:
        pass


@given(payload=st.dictionaries(
    st.sampled_from([
        "UserDetailList", "RoleDetailList", "GroupDetailList",
        "Policies", "IsTruncated", "Marker", "junk",
    ]),
    json_value,
    max_size=6,
))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_structures_never_crash_unhandled(
    payload: dict[str, object],
) -> None:
    try:
        parse_authorization_details(json.dumps(payload).encode())
    except ParseError:
        pass


@given(payload=st.dictionaries(
    st.sampled_from(["UserDetailList", "RoleDetailList", "Policies"]),
    json_value,
    max_size=4,
))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_rejections_never_echo_content(payload: dict[str, object]) -> None:
    try:
        parse_authorization_details(json.dumps(payload).encode())
    except ParseError as exc:
        assert CANARY not in str(exc)
