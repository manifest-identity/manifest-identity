"""No two parts of the application depend on each other (D-093).

Two parts that import each other cannot change apart: that is the
tangle, and an agent adding a feature makes one by taking whatever
import is nearest. The two pairs that exist are listed with their
reasons, and the list is meant only to shrink. No part imports
manifest_identity.models either, because that module gathers every
part's tables and importing it ties a part to all the others at once.
"""

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "manifest_identity"
PARTS = {"core", "observe", "authorize", "compare", "decide", "api"}

KNOWN = {
    # The inventory shows owners and flags, which live in authorize, and
    # authorize reads what observe holds.
    frozenset({"authorize", "observe"}),
}


def imports() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {part: set() for part in PARTS}
    for path in PACKAGE.rglob("*.py"):
        part = path.relative_to(PACKAGE).parts[0]
        if part not in PARTS:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            if module and module.startswith("manifest_identity"):
                target = module.split(".")
                found[part].add(target[1] if len(target) > 1 else "(root)")
    return found


def test_no_new_pair_of_parts_depends_on_each_other() -> None:
    found = imports()
    pairs = {
        frozenset({a, b})
        for a in PARTS
        for b in found[a]
        if b in PARTS and a != b and a in found[b]
    }
    assert pairs == KNOWN, (
        f"two-way pairs now {sorted(sorted(p) for p in pairs)}; "
        "a new pair is a tangle to remove, and a pair that is gone comes off KNOWN"
    )


def test_no_part_imports_the_module_that_gathers_every_table() -> None:
    gathered = [
        f"{path.relative_to(PACKAGE)}:{node.lineno}"
        for path in PACKAGE.rglob("*.py")
        if path.relative_to(PACKAGE).parts[0] in PARTS
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.ImportFrom) and node.module == "manifest_identity.models"
    ]
    assert gathered == [], f"import tables from their own part instead: {gathered}"
