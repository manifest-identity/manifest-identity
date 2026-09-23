#!/usr/bin/env python3
"""The scoring page, generated from a snapshot of every outside rater.

    python3 scripts/render_scoring.py --fetch   # re-read the raters into the snapshot, then render
    python3 scripts/render_scoring.py           # render SCORING.md from scoring/snapshot.json
    python3 scripts/render_scoring.py --check   # fail unless the page is what the snapshot renders

Five services rate this repository, and each measures something
different. The page lists every item each one scores, what it saw,
and where the gaps are, so a badge at the top of the README reads
down to the line that earned it. The page never states a figure the
snapshot does not hold: the render is deterministic, the check mode
holds the committed page to the committed snapshot, and only the
fetch touches the network, so every date on the page is a date
something was actually read.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "scoring" / "snapshot.json"
PAGE = ROOT / "SCORING.md"
REPO = "tltaylor1/manifest-identity"
BEST_PRACTICES_ID = 14563
SONAR_KEY = "manifest-identity_manifest-identity"

# The scanner's own documentation of each check, at a fixed commit so
# the links and the risk labels below cannot drift under the page.
CHECKS_DOC = (
    "https://github.com/ossf/scorecard/blob/"
    "c395761df6afe1a69e476bc60a013a94bcbc153f/docs/checks.md"
)
# Risk as the scanner weights it, and what the check reads.
CHECKS: dict[str, tuple[str, str]] = {
    "Binary-Artifacts": ("High", "no executable binaries committed to the repository"),
    "Branch-Protection": ("High", "the default and release branches refuse unreviewed merges"),
    "CI-Tests": ("Low", "pull requests run tests before they merge"),
    "CII-Best-Practices": ("Low", "an OpenSSF Best Practices badge, scored by its level"),
    "Code-Review": ("High", "recent changes were reviewed by a person other than their author"),
    "Contributors": ("Low", "recent contributors from more than one company or organization"),
    "Dangerous-Workflow": ("Critical", "no workflow lets untrusted input run with its token"),
    "Dependency-Update-Tool": ("High", "a tool that opens updates for dependencies"),
    "Fuzzing": ("Medium", "the project is fuzzed"),
    "License": ("Low", "a published license"),
    "Maintained": ("High", "recent commits and issue activity over the last ninety days"),
    "Packaging": ("Medium", "releases publish a package or image through a workflow"),
    "Pinned-Dependencies": ("Medium", "build and release inputs pinned to a version or digest"),
    "SAST": ("Medium", "static analysis runs on every commit"),
    "SBOM": ("Medium", "a software bill of materials is published"),
    "Security-Policy": ("Medium", "a published security policy"),
    "Signed-Releases": ("High", "release artifacts are signed or attested"),
    "Token-Permissions": ("High", "workflow tokens hold the least permission they need"),
    "Vulnerabilities": ("High", "no open, unfixed vulnerabilities in the project or its packages"),
    "Webhooks": ("Critical", "repository webhooks authenticate their origin"),
}

# The Best Practices criteria in the order the badge site presents
# them, so the table reads as the entry does.
CRITERIA: list[tuple[str, list[str]]] = [
    ("Basics", [
        "description_good", "interact", "contribution",
        "contribution_requirements", "floss_license", "floss_license_osi",
        "license_location", "documentation_basics",
        "documentation_interface", "sites_https", "discussion", "english",
        "maintained",
    ]),
    ("Change control", [
        "repo_public", "repo_track", "repo_interim", "repo_distributed",
        "version_unique", "version_semver", "version_tags",
        "release_notes", "release_notes_vulns",
    ]),
    ("Reporting", [
        "report_process", "report_tracker", "report_responses",
        "enhancement_responses", "report_archive",
        "vulnerability_report_process", "vulnerability_report_private",
        "vulnerability_report_response",
    ]),
    ("Quality", [
        "build", "build_common_tools", "build_floss_tools", "test",
        "test_invocation", "test_most", "test_continuous_integration",
        "test_policy", "tests_are_added", "tests_documented_added",
        "warnings", "warnings_fixed", "warnings_strict",
    ]),
    ("Security", [
        "know_secure_design", "know_common_errors", "crypto_published",
        "crypto_call", "crypto_floss", "crypto_keylength",
        "crypto_working", "crypto_weaknesses", "crypto_pfs",
        "crypto_password_storage", "crypto_random", "delivery_mitm",
        "delivery_unsigned", "vulnerabilities_fixed_60_days",
        "vulnerabilities_critical_fixed", "no_leaked_credentials",
    ]),
    ("Analysis", [
        "static_analysis", "static_analysis_common_vulnerabilities",
        "static_analysis_fixed", "static_analysis_often",
        "dynamic_analysis", "dynamic_analysis_unsafe",
        "dynamic_analysis_enable_assertions", "dynamic_analysis_fixed",
    ]),
]

LEVELS = [
    (0, "absent or false", "the rule is not met, or a claim about it is untrue"),
    (1, "stated", "a document says it"),
    (2, "attested", "a document says it and names where the evidence is"),
    (3, "checked on demand", "a command anyone can run verifies it"),
    (4, "gated", "the pipeline refuses a merge that breaks it"),
    (5, "gated and proven", "gated, and the repository records a run where the gate fired"),
]

SONAR_METRICS = {
    "ncloc": "lines of code",
    "bugs": "open reliability findings",
    "vulnerabilities": "open security findings",
    "security_hotspots": "security hotspots to review",
    "code_smells": "open maintainability findings",
    "duplicated_lines_density": "duplicated lines, percent",
    "coverage": "coverage as the analyzer measures it, percent",
}


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310  (https, fixed hosts)
        return json.load(response)


def fetch(doctrine: Path) -> dict:
    scorecard = _get(f"https://api.scorecard.dev/projects/github.com/{REPO}")
    entry = _get(f"https://www.bestpractices.dev/projects/{BEST_PRACTICES_ID}.json")
    gate = _get(
        "https://sonarcloud.io/api/qualitygates/project_status"
        f"?projectKey={SONAR_KEY}"
    )["projectStatus"]
    measures = _get(
        "https://sonarcloud.io/api/measures/component"
        f"?component={SONAR_KEY}&metricKeys={','.join(SONAR_METRICS)}"
    )["component"]["measures"]
    owner, name = REPO.split("/")
    codecov = _get(f"https://codecov.io/api/v2/github/{owner}/repos/{name}/")
    # Both commands are fixed argument lists over a path the operator
    # named on the command line; nothing here comes from a rater.
    score = json.loads(subprocess.run(  # noqa: S603
        [sys.executable, str(doctrine / "scripts" / "score.py"),
         "--repo", REPO, "--json", str(ROOT)],
        check=True, capture_output=True, text=True,
    ).stdout)
    git = shutil.which("git") or "git"
    doctrine_commit = subprocess.run(  # noqa: S603
        [git, "-C", str(doctrine), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    criteria = {
        key[: -len("_status")]: {
            "status": value,
            "justification": entry.get(key[: -len("_status")] + "_justification") or "",
        }
        for key, value in entry.items()
        if key.endswith("_status") and value in ("Met", "Unmet", "N/A")
        and not key.startswith("achieve_")  # level markers, not criteria
    }
    return {
        "taken": datetime.now(UTC).strftime("%Y-%m-%d"),
        "scorecard": {
            "score": scorecard["score"],
            "date": scorecard["date"][:10],
            "version": scorecard["scorecard"]["version"],
            "commit": scorecard["repo"]["commit"],
            "checks": [
                {
                    "name": c["name"],
                    "score": c["score"],
                    "reason": c["reason"],
                    "details": c.get("details") or [],
                }
                for c in sorted(scorecard["checks"], key=lambda c: c["name"])
            ],
        },
        "best_practices": {
            "level": entry["badge_level"],
            "percentage": entry["badge_percentage_0"],
            "achieved": (entry["achieved_passing_at"] or "")[:10],
            "updated": (entry["updated_at"] or "")[:10],
            "criteria": criteria,
        },
        "doctrine": {
            "commit": doctrine_commit,
            "kind": score["kind"],
            "rules": score["rules"],
        },
        "codecov": {
            "updated": codecov["updatestamp"][:10],
            "coverage": codecov["totals"]["coverage"],
            "files": codecov["totals"]["files"],
            "lines": codecov["totals"]["lines"],
            "hits": codecov["totals"]["hits"],
        },
        "sonarcloud": {
            "status": gate["status"],
            "since": (gate.get("periods") or [{}])[0].get("date", "")[:10],
            "conditions": [
                {
                    "metric": c["metricKey"],
                    "comparator": c["comparator"],
                    "threshold": c["errorThreshold"],
                    "actual": c["actualValue"],
                    "status": c["status"],
                }
                for c in gate["conditions"]
            ],
            "measures": {m["metric"]: m["value"] for m in measures},
        },
    }


ENTRY = f"https://www.bestpractices.dev/projects/{BEST_PRACTICES_ID}"


def _criterion_row(criterion: str, c: dict) -> str:
    just = c["justification"].replace("|", "\\|").replace("\n", " ").strip()
    return f"| [{criterion}]({ENTRY}#{criterion}) | {c['status']} | {just} |"


def _mean(rules: list[dict]) -> float:
    levels = [r["level"] for r in rules if r["level"] is not None]
    return round(sum(levels) / len(levels), 1)


def render(s: dict) -> str:
    sc, bp, dc, cc, sq = (
        s["scorecard"], s["best_practices"], s["doctrine"], s["codecov"], s["sonarcloud"]
    )
    out: list[str] = []
    w = out.append
    w("# Scoring")
    w("")
    w("Five outside services rate this repository, and each one measures")
    w("something different. This page lists every item each rater scores,")
    w("what it saw, and where the gaps are, so a badge at the top of the")
    w("[README](README.md) reads down to the line that earned it.")
    w("")
    w("The page is generated by `scripts/render_scoring.py` from a snapshot")
    w("of the raters' own data, `scoring/snapshot.json`; a gate fails the")
    w("build when the page and the snapshot disagree, and only a deliberate")
    w("refresh reads the raters again, so every date here is a date")
    w(f"something was actually read. Snapshot taken {s['taken']}, UTC.")
    w("")
    w("| Rater | Result | What it measures |")
    w("|---|---|---|")
    w(f"| [OpenSSF Scorecard](#openssf-scorecard) | {sc['score']} / 10 | "
      "supply-chain and project security practices, read from the repository by a scanner |")
    w(f"| [OpenSSF Best Practices](#openssf-best-practices) | {bp['level']} | "
      "criteria for open source projects, each answered with a justification the site publishes |")
    w(f"| [build-doctrine score](#build-doctrine-score) | {_mean(dc['rules'])} / 5 | "
      "how far each rule of the program's own doctrine is enforced here, "
      "from stated to gated and proven |")
    w(f"| [Codecov](#codecov) | {cc['coverage']} percent | "
      "line coverage of the application by its test suite |")
    w(f"| [SonarCloud](#sonarcloud) | quality gate {sq['status'].lower()} | "
      "static analysis of new code: reliability, security, maintainability, "
      "duplication, coverage |")
    w("")

    w("## OpenSSF Scorecard")
    w("")
    w(f"Scorecard {sc['version']} read commit `{sc['commit'][:12]}` on {sc['date']}.")
    w("Each check scores 0 to 10 and the overall score is a risk-weighted")
    w("average; a check that returns -1 is inconclusive and is left out of")
    w("the average. The scanner documents every check, with its risk and its")
    w(f"scoring, in [checks.md]({CHECKS_DOC}).")
    w("")
    w("| Check | Risk | Score | What the scanner saw |")
    w("|---|---|---|---|")
    for c in sc["checks"]:
        risk, _ = CHECKS[c["name"]]
        anchor = c["name"].lower()
        w(f"| [{c['name']}]({CHECKS_DOC}#{anchor}) | {risk} | {c['score']} | {c['reason']} |")
    w("")
    short = [c for c in sc["checks"] if c["score"] != 10]
    if short:
        w("### The checks below ten")
        w("")
        w("What each check reads, and the scanner's own detail lines for the")
        w("ones that did not reach ten.")
        w("")
        for c in short:
            _, reads = CHECKS[c["name"]]
            w(f"- **{c['name']}, {c['score']}**: reads {reads}.")
            for line in c["details"]:
                w(f"    - {line}")
        w("")

    w("## OpenSSF Best Practices")
    w("")
    w(f"The entry is [project {BEST_PRACTICES_ID}]({ENTRY}), at the {bp['level']}")
    w(f"level with {bp['percentage']} percent of that level's criteria met, achieved")
    w(f"{bp['achieved']} and last edited {bp['updated']}. Every answer is a")
    w("claim the badge holder makes, so each row below carries the")
    w("justification exactly as the entry states it; the gates and tests")
    w("named in them are the ones this repository runs.")
    w("")
    shown: set[str] = set()
    for section, ids in CRITERIA:
        rows = [(i, bp["criteria"][i]) for i in ids if i in bp["criteria"]]
        if not rows:
            continue
        w(f"### {section}")
        w("")
        w("| Criterion | Status | Justification |")
        w("|---|---|---|")
        for i, c in rows:
            shown.add(i)
            w(_criterion_row(i, c))
        w("")
    rest = sorted(i for i in bp["criteria"] if i not in shown)
    if rest:
        w("### Beyond the passing level")
        w("")
        w("| Criterion | Status | Justification |")
        w("|---|---|---|")
        for i in rest:
            w(_criterion_row(i, bp["criteria"][i]))
        w("")
    w("The silver and gold levels are not attempted. Both require more")
    w("than one maintainer, and silver requires a code of conduct, which")
    w("[D-026](DECISIONS.md) in the doctrine declines for a one-person")
    w("program; a criterion marked met without its evidence would score")
    w("zero on the doctrine's own scale, so the entry stops where the")
    w("evidence stops.")
    w("")

    w("## build-doctrine score")
    w("")
    w("The program's own doctrine, [build-doctrine](https://github.com/tltaylor1/build-doctrine),")
    w("scores each of its rules by how far the repository enforces it,")
    w("and the badge is the mean over the rules that apply to an")
    w(f"{dc['kind']} repository. The scorer ran at doctrine commit `{dc['commit'][:12]}`.")
    w("")
    w("| Level | Name | Meaning |")
    w("|---|---|---|")
    for level, name, meaning in LEVELS:
        w(f"| {level} | {name} | {meaning} |")
    w("")
    w("| Rule | Level | What the scorer saw |")
    w("|---|---|---|")
    for r in dc["rules"]:
        level = "not applicable" if r["level"] is None else str(r["level"])
        w(f"| {r['rule']} | {level} | {r['reason']} |")
    w("")
    w(f"Mean over the applicable rules: **{_mean(dc['rules'])}**. A rule at")
    w("level one is one the repository states and nothing checks; a rule")
    w("moves up only when a command, then a gate, then a recorded firing")
    w("stands behind it, and the scorer never infers the fifth level.")
    w("")

    w("## Codecov")
    w("")
    w("The pipeline's test run uploads its coverage report, and Codecov read")
    w(f"{cc['coverage']} percent on {cc['updated']}: {cc['hits']} of {cc['lines']} lines")
    w(f"across {cc['files']} files of the")
    w("application package. The pipeline floors the same figure at 90")
    w("percent, so the outside reading and the gate measure one report.")
    w("")

    w("## SonarCloud")
    w("")
    w(f"The quality gate is **{sq['status']}** on main, judged on code changed")
    w(f"since {sq['since']}.")
    w("The analyzer runs from the pipeline on the same commit the other")
    w("gates judged, and it imports the same coverage report. Findings are")
    w("triaged in the analyzer: a real one is fixed in the code, and a")
    w("false positive is accepted there with its reason written, never")
    w("silenced in the source.")
    w("")
    w("| Condition on new code | Threshold | Actual | Status |")
    w("|---|---|---|---|")
    for c in sq["conditions"]:
        comparator = "at most" if c["comparator"] == "GT" else "at least"
        metric = c["metric"].removeprefix("new_").replace("_", " ")
        w(f"| {metric} | {comparator} {c['threshold']} | {c['actual']} | {c['status']} |")
    w("")
    w("| Measure, whole project | Value |")
    w("|---|---|")
    for metric, label in SONAR_METRICS.items():
        if metric in sq["measures"]:
            w(f"| {label} | {sq['measures'][metric]} |")
    w("")
    w("The analyzer's coverage figure counts the frontend, which has no")
    w("coverage tool of its own and is tested through the application")
    w("suite, so it reads below the Codecov figure for the same report.")
    w("")

    w("## Refreshing this page")
    w("")
    w("```bash")
    w("python3 scripts/render_scoring.py --fetch   # re-read every rater, then render")
    w("python3 scripts/render_scoring.py --check   # what the gate runs")
    w("```")
    w("")
    w("The fetch needs a checkout of build-doctrine beside this repository")
    w("for the doctrine scorer; everything else is read from the raters'")
    w("public interfaces. The rendered page and the snapshot commit")
    w("together, and the gate refuses a page the snapshot does not")
    w("produce.")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fetch", action="store_true",
                        help="re-read the raters into the snapshot")
    parser.add_argument("--check", action="store_true",
                        help="fail unless the page matches the snapshot")
    parser.add_argument("--doctrine", default=str(ROOT.parent / "build-doctrine"),
                        help="checkout of build-doctrine, for the scorer (fetch only)")
    args = parser.parse_args()
    if args.fetch:
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(fetch(Path(args.doctrine)), indent=2) + "\n")
    page = render(json.loads(SNAPSHOT.read_text()))
    if args.check:
        if PAGE.read_text() != page:
            print("SCORING.md is not what scoring/snapshot.json renders; "
                  "run scripts/render_scoring.py")
            return 1
        print("scoring page matches its snapshot")
        return 0
    PAGE.write_text(page)
    print(f"rendered {PAGE.name} from {SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
