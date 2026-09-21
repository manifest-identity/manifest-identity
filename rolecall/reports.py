"""Exports and the risk report: every value escaped at the exit.

Two escaping regimes, each matched to where the value lands. The CSV
export neutralizes spreadsheet formula injection, because a cell that
begins with an operator executes in the reader's spreadsheet with the
reader's permissions, and imported files control names and tags. The
HTML report renders through an engine that escapes by default, so
markup injection is removed as a class the way the ORM removes query
injection, rather than remembered call by call (D-040). JSON carries
raw values, because JSON is data and its consumers parse rather than
interpret.

Ranking comes from the engine's tiers and nowhere else: the report
orders by critical, then warning, then notice, then name, so the
report and the dashboard can never disagree about what matters most.
"""

import csv
import io
from pathlib import Path
from typing import cast

from jinja2 import Environment, FileSystemLoader, select_autoescape

from rolecall.assessment import AssessedGroup, AssessedIdentity

# A cell beginning with one of these executes as a formula in common
# spreadsheets; a leading tab or carriage return smuggles the same.
FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_LEADERS):
        return "'" + text
    return text


def identity_row(a: AssessedIdentity) -> dict[str, object]:
    tiers = a.tier_counts()
    return {
        "account": a.account,
        "name": a.identity.first_display_name,
        "type": a.identity.identity_type,
        "owner": a.owner.name if a.owner else None,
        "owner_type": a.owner.owner_type if a.owner else None,
        "owner_source": a.owner.source if a.owner else None,
        "flagged": a.flagged,
        "critical": tiers["critical"],
        "warning": tiers["warning"],
        "notice": tiers["notice"],
        "findings": [
            {"code": f.code, "tier": f.tier, "anchor": f.anchor,
             "explanation": f.explanation}
            for f in a.findings
        ],
        "privilege_sources": (
            [s.describe() for s in a.picture.sources] if a.picture else []
        ),
        "last_activity": (
            a.state.last_activity.isoformat()
            if a.state and a.state.last_activity
            else None
        ),
        "observed_days": a.state.observed_days if a.state else 0,
    }


def group_row(g: AssessedGroup) -> dict[str, object]:
    return {
        "account": g.account,
        "name": g.name,
        "members": g.members,
        "privileged": g.privileged,
        "owner": g.owner.name if g.owner else None,
        "flagged": g.flagged,
        "findings": [
            {"code": f.code, "tier": f.tier, "anchor": f.anchor,
             "explanation": f.explanation}
            for f in g.findings
        ],
    }


def _tier(row: dict[str, object], key: str) -> int:
    return cast(int, row[key])


def rank(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """The single-source ranking rule: tiers, then name."""
    return sorted(
        rows,
        key=lambda r: (
            -_tier(r, "critical"),
            -_tier(r, "warning"),
            -_tier(r, "notice"),
            str(r["name"]),
        ),
    )


CSV_COLUMNS = (
    "account", "name", "type", "owner", "owner_type", "owner_source",
    "flagged", "critical", "warning", "notice", "finding_codes",
    "privilege_sources", "last_activity", "observed_days",
)


def to_csv(rows: list[dict[str, object]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rank(rows):
        findings = cast(list[dict[str, str]], row["findings"])
        codes = ", ".join(f["code"] for f in findings)
        sources = "; ".join(cast(list[str], row["privilege_sources"]))
        writer.writerow([
            csv_safe(row["account"]),
            csv_safe(row["name"]),
            csv_safe(row["type"]),
            csv_safe(row["owner"]),
            csv_safe(row["owner_type"]),
            csv_safe(row["owner_source"]),
            csv_safe(row["flagged"]),
            row["critical"],
            row["warning"],
            row["notice"],
            csv_safe(codes),
            csv_safe(sources),
            csv_safe(row["last_activity"]),
            row["observed_days"],
        ])
    return out.getvalue()


EVIDENCE_SUMMARY_FIELDS = (
    "campaign", "scope", "population_statement", "created_by",
    "created_at", "due_at", "closed_at", "closed_by", "total",
    "decided", "coverage", "exported_at", "audit_chain_head",
)

EVIDENCE_CSV_COLUMNS = (
    "display_name", "target_type", "recommendation",
    "recommendation_reasons", "evidence", "disposition",
    "disposition_note", "disposed_by", "disposed_at",
)


def evidence_to_csv(export: dict[str, object]) -> str:
    """The evidence file as one spreadsheet: summary rows first, as
    field and value pairs, then a blank row, then one row per decision,
    so the population statement travels in the same artifact as the
    decisions it frames. Every cell that carries imported or typed text
    passes through csv_safe, the same gate as the inventory CSV."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("field", "value"))
    for field in EVIDENCE_SUMMARY_FIELDS:
        writer.writerow((field, csv_safe(export[field])))
    writer.writerow(())
    writer.writerow(EVIDENCE_CSV_COLUMNS)
    for decision in cast(list[dict[str, object]], export["decisions"]):
        reasons = "; ".join(
            cast(list[str], decision["recommendation_reasons"])
        )
        evidence = "; ".join(
            f"{key}={value}"
            for key, value in sorted(
                cast(dict[str, object], decision["evidence"]).items()
            )
        )
        writer.writerow([
            csv_safe(decision["display_name"]),
            csv_safe(decision["target_type"]),
            csv_safe(decision["recommendation"]),
            csv_safe(reasons),
            csv_safe(evidence),
            csv_safe(decision["disposition"]),
            csv_safe(decision["disposition_note"]),
            csv_safe(decision["disposed_by"]),
            csv_safe(decision["disposed_at"]),
        ])
    return out.getvalue()


_environment = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
)


def render_report(
    identities: list[dict[str, object]],
    groups: list[dict[str, object]],
    as_of: str | None,
) -> str:
    tiles = {
        "identities": len(identities),
        "critical": sum(1 for r in identities if _tier(r, "critical") > 0),
        "warning": sum(
            1
            for r in identities
            if _tier(r, "critical") == 0 and _tier(r, "warning") > 0
        ),
        "quiet": sum(
            1
            for r in identities
            if _tier(r, "critical") == 0
            and _tier(r, "warning") == 0
            and _tier(r, "notice") == 0
        ),
    }
    template = _environment.get_template("report.html.j2")
    return template.render(
        identities=rank(identities),
        groups=groups,
        as_of=as_of,
        tiles=tiles,
    )
