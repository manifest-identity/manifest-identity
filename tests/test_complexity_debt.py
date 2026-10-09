"""The functions past the complexity limit are counted, so the list
only changes on purpose (D-091).

ruff's C901 fails any function whose branches exceed ten. The functions
already past it when the rule was turned on carry `# noqa: C901`, and
this test pins how many there are. Simplifying one means removing its
marker and lowering LISTED here; adding one means raising LISTED, which
a reviewer sees in the diff.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTED = 31


def test_the_listed_complex_functions_are_counted() -> None:
    marked = sum(
        path.read_text().count("# noqa: C901")
        for folder in ("manifest_identity", "scripts", "tests", "migrations")
        for path in (ROOT / folder).rglob("*.py")
        if path.name != "test_complexity_debt.py"
    )
    assert marked == LISTED, (
        f"{marked} functions carry the complexity marker; LISTED says {LISTED}. "
        "Lower LISTED when one is simplified; raising it needs a reason in review."
    )
