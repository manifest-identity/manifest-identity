"""The shipped mapping for the file door, on its own so the sample
generator can read it with nothing but the standard library.

The template's columns come from this mapping (D-074), and the release
workflow generates the scaled sample with the interpreter alone, before
any tree installs; the generator therefore imports this module and not
the importer, which needs the database layer. A test runs the
generator with site packages disabled to hold that line.
"""

from __future__ import annotations

# The shipped default: the template's own column names, so the easy
# path stays easy and the documented template imports clean through a
# mapping like any other file.
DEFAULT_MAPPING_NAME = "the shipped template"
DEFAULT_FIELDS: dict[str, dict[str, str | None]] = {
    "identity_external_id": {"column": "identity_id"},
    "role_definition_external_id": {"column": "role"},
    "mode": {"column": "mode"},
    "path": {"column": "path"},
    "owner_kind": {"column": "owner_kind"},
    "owner_ref": {"column": "owner"},
    "secondary_owner_kind": {"column": "secondary_owner_kind"},
    "secondary_owner_ref": {"column": "secondary_owner"},
    "justification": {"column": "justification"},
    "reference": {"column": "reference"},
    "control_reference": {"column": "control"},
    "valid_from": {"column": "valid_from", "format": "%Y-%m-%d"},
    "valid_until": {"column": "valid_until", "format": "%Y-%m-%d"},
}
