"""The repository's own scanner rules (D-086): each one is a lesson
a scanner taught after a push, and each must fire on the shape that
taught it and pass on the repository as it stands."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SEMGREP = Path(sys.executable).parent / "semgrep"

pytestmark = pytest.mark.skipif(
    not SEMGREP.exists() and shutil.which("semgrep") is None,
    reason="semgrep is not installed here",
)


def run(*paths: Path) -> list[str]:
    completed = subprocess.run(  # noqa: S603
        [str(SEMGREP) if SEMGREP.exists() else "semgrep", "--config", str(ROOT / ".semgrep"),
         "--metrics=off", "--quiet", "--json", *map(str, paths)],
        capture_output=True, text=True, timeout=300, cwd=ROOT,
    )
    return [r["check_id"].rsplit(".", 1)[-1] for r in json.loads(completed.stdout)["results"]]


def test_each_rule_fires_on_the_shape_that_taught_it(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        'def kind(ref):\n'
        '    if ref.endswith("amazonaws.com"):\n'
        '        return "service"\n'
        '    row = {"pwd": "2019-08-14"}\n'
        '    return row\n'
    )
    (tmp_path / "bad.js").write_text("function go() { loadInventory(); run(loadDelta()); }\n")
    fired = run(tmp_path)
    assert fired.count("no-decision-from-a-hostname-substring") == 1
    assert fired.count("no-credential-shaped-key-with-a-literal") == 1
    assert fired.count("no-unawaited-page-loader") == 1, "run() is the accepted form"


def test_the_repository_passes_its_own_rules() -> None:
    assert run(ROOT / "manifest_identity", ROOT / "frontend", ROOT / "scripts") == []


def test_the_scanner_tree_carries_the_override() -> None:
    """A recompile without scripts/compile_scan.py puts Semgrep's
    declared PyJWT line back, and that line carries twelve advisories."""
    tree = (ROOT / "requirements-scan.txt").read_text()
    pinned = re.search(r"^pyjwt==(\d+)\.(\d+)\.(\d+)", tree, re.M)
    assert pinned is not None, "the scanner tree pins pyjwt"
    assert tuple(map(int, pinned.groups())) >= (2, 15, 0), "compile with scripts/compile_scan.py"
