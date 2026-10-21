"""The repository's own code rules (D-086, D-097). Each is a lesson a
scanner taught after a push, and each must fire on the shape that
taught it and pass on the repository as it stands.

Three are held by tools that already run. CodeQL refuses a decision
made from a hostname substring, as it did here twice (PR 143, PR 161).
ruff refuses a handler that catches everything and says nothing (S110,
E722, BLE001), and the last test here proves it on each shape. ESLint
refuses a page loader nobody awaits (no-floating-promises).

The two that no tool here covers are read from the code below: a
dictionary key named like a credential holding a string literal, which
ruff does not check and SonarCloud refused twice in one pull request
(PR 152), and a path containment check made with a string prefix,
which accepts a sibling whose name begins the same way.
"""

import ast
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("manifest_identity", "scripts")
CREDENTIAL_WORD = re.compile(r"password|passwd|pwd|passphrase", re.IGNORECASE)


def _text(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def credential_keys(tree: ast.AST) -> Iterator[int]:
    """Lines where a dictionary key named like a credential holds text."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and CREDENTIAL_WORD.search(key.value) and _text(value)):
                    yield key.lineno


def _call_named(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id == name) or (
        isinstance(func, ast.Attribute) and func.attr == name)


def prefix_containment(tree: ast.AST) -> Iterator[int]:
    """Lines where one path is tested as inside another by a text prefix."""
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "startswith" and node.args):
            subject, prefix = node.func.value, node.args[0]
            if (_call_named(subject, "str") and _call_named(prefix, "str")) or _call_named(
                    subject, "abspath"):
                yield node.lineno


def findings(source: str) -> dict[str, list[int]]:
    tree = ast.parse(source)
    return {"credential": list(credential_keys(tree)), "prefix": list(prefix_containment(tree))}


def test_each_rule_fires_on_the_shape_that_taught_it() -> None:
    found = findings(
        'row = {"pwd": "2019-08-14"}\n'
        'fine = {"pwd_last_set": None, "name": "x"}\n'
        "def inside(target, root):\n"
        "    return str(target.resolve()).startswith(str(root.resolve()))\n"
        "def inside_too(target, root):\n"
        "    return os.path.abspath(target).startswith(root)\n"
        "def proper(target, root):\n"
        "    return target.is_relative_to(root)\n"
    )
    assert found == {"credential": [1], "prefix": [4, 6]}


def test_the_repository_passes_its_own_rules() -> None:
    broken = []
    for folder in SOURCES:
        for path in sorted((ROOT / folder).rglob("*.py")):
            for rule, lines in findings(path.read_text()).items():
                broken += [f"{path.relative_to(ROOT)}:{line} {rule}" for line in lines]
    assert broken == []


def test_ruff_refuses_each_silenced_exception_shape(tmp_path: Path) -> None:
    sample = tmp_path / "quiet.py"
    sample.write_text(
        "import os\n"
        "def one():\n"
        "    try:\n"
        "        os.remove('x')\n"
        "    except Exception:\n"
        "        pass\n"
        "def two():\n"
        "    try:\n"
        "        return int('x')\n"
        "    except Exception:\n"
        "        return 0\n"
        "def three():\n"
        "    try:\n"
        "        os.remove('x')\n"
        "    except:\n"
        "        print('x')\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "ruff", "check", "--config", str(ROOT / "pyproject.toml"),
         "--output-format", "concise", "--no-cache", str(sample)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    flagged = {(int(line.split(":")[1]), line.split()[1]) for line in result.stdout.splitlines()
               if line.startswith(str(sample))}
    assert {(5, "S110"), (5, "BLE001"), (10, "BLE001"), (15, "E722")} <= flagged
