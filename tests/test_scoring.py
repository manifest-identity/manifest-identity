"""The scoring page states nothing its snapshot does not hold.

The page is generated from a snapshot of the raters' data, so the
committed page must be exactly what the committed snapshot renders,
and every check the scanner reports must be one the generator can
describe, so a new check cannot appear on the page unexplained.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import render_scoring

ROOT = Path(__file__).resolve().parent.parent


def test_page_is_what_the_snapshot_renders() -> None:
    snapshot = json.loads((ROOT / "scoring" / "snapshot.json").read_text())
    assert (ROOT / "SCORING.md").read_text() == render_scoring.render(snapshot)


def test_every_reported_check_is_described() -> None:
    snapshot = json.loads((ROOT / "scoring" / "snapshot.json").read_text())
    reported = {c["name"] for c in snapshot["scorecard"]["checks"]}
    assert reported <= set(render_scoring.CHECKS), reported - set(render_scoring.CHECKS)
    criteria = {i for _, ids in render_scoring.CRITERIA for i in ids}
    assert set(snapshot["best_practices"]["criteria"]) <= criteria
