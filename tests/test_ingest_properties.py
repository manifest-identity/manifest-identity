"""The fuzz suite: properties the parser must hold against any input.

Hypothesis generates the inputs; the properties are the contract. The
parser may accept or reject, but it may never crash with anything but
ParseError, never echo file content in an error, and never let a
mixed-account file through.
"""

import csv
import io

from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from manifest_identity.observe.providers.aws.credential_report import (
    ParseError,
    parse_credential_report,
)
from tests.reportlib import HEADER, report, user_row

CANARY = "canary-value-must-not-reflect"

# Values that have broken CSV parsers before: quoting, embedded
# delimiters and newlines, formula prefixes, absurd lengths, absent
# markers in the wrong fields, and non-values.
hostile_value = st.one_of(
    st.just(""),
    st.just("N/A"),
    st.just("no_information"),
    st.just("not_supported"),
    st.just('"quoted"'),
    st.just("comma,inside"),
    st.just('embedded\nnewline'),
    st.just("=cmd()"),
    st.just("+SUM(A1)"),
    st.just("-2+3"),
    st.just("@import"),
    st.just("null"),
    st.just("None"),
    st.just("0"),
    st.just("TRUE"),
    st.just("FALSE"),
    st.just("2026-13-45T99:99:99+00:00"),
    st.just("2026-08-01T00:00:00"),
    st.just("x" * 3000),
    st.text(min_size=0, max_size=40),
)


@st.composite
def hostile_csv(draw: st.DrawFn) -> bytes:
    """A structurally valid CSV whose cells are drawn from the grid."""
    rows = draw(st.integers(min_value=1, max_value=8))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(HEADER.split(","))
    for _ in range(rows):
        writer.writerow([draw(hostile_value) for _ in range(len(HEADER.split(",")))])
    return out.getvalue().encode()


@given(data=st.binary(max_size=4096))
@example(data=b"")
@example(data=b"\xff\xfe garbage")
@example(data=HEADER.encode())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_crash_unhandled(data: bytes) -> None:
    try:
        parse_credential_report(data)
    except ParseError:
        pass  # rejection is a correct outcome; any other exception fails


@given(data=hostile_csv())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_cells_never_crash_unhandled(data: bytes) -> None:
    try:
        parse_credential_report(data)
    except ParseError:
        pass


@given(data=hostile_csv())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_rejections_never_echo_content(data: bytes) -> None:
    data = data.replace(b"comma,inside", CANARY.encode())
    try:
        parse_credential_report(data)
    except ParseError as exc:
        assert CANARY not in str(exc)


@given(
    names=st.lists(
        st.text(
            alphabet=st.characters(whitelist_categories=("Ll", "Nd")),
            min_size=1,
            max_size=20,
        ),
        min_size=1,
        max_size=10,
        unique=True,
    )
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_valid_reports_parse_completely(names: list[str]) -> None:
    data = report(*[user_row(f"u{n}") for n in names])
    parsed = parse_credential_report(data)
    assert len(parsed.rows) == len(names)
    assert parsed.skipped == 0
    assert parsed.account_id == "123456789012"


def test_the_row_bound_is_enforced() -> None:
    big = report(*[user_row(f"user{i}") for i in range(60)])
    # Shrink the bound rather than generating fifty thousand rows.
    import manifest_identity.observe.providers.aws.credential_report as cr

    original = cr.MAX_ROWS
    cr.MAX_ROWS = 50
    try:
        try:
            parse_credential_report(big)
            raise AssertionError("row bound not enforced")
        except ParseError as exc:
            assert "row bound" in str(exc)
    finally:
        cr.MAX_ROWS = original
