#!/usr/bin/env bash
# Audit every hash-pinned tree against known vulnerabilities.
#
# The runtime and development trees carry no exceptions. The scanner
# tree does: Semgrep pins PyJWT to a line the audit refuses, and no
# Semgrep release with a fixed PyJWT existed when the exceptions were
# recorded. Each exception is tied to the Semgrep pin it was recorded
# against, so a bump of that pin fails here until the list is re-read
# against the new release rather than carried forward unread (D-086).
#
# The tools live in the project's environment, so this prefers the
# documented .venv and falls back to the active interpreter.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python3"
fi

"$PYTHON" -m pip_audit --require-hashes -r requirements.txt
"$PYTHON" -m pip_audit --require-hashes -r requirements-dev.txt

# Recorded September 30, 2026 against semgrep==1.178.0, its newest
# release, which requires pyjwt~=2.13.0. The twelve advisories sit in
# PyJWT's token verification and key set fetching paths; Semgrep runs
# here against files on disk and never verifies a token.
RECORDED_AGAINST="semgrep==1.178.0"
EXCEPTIONS=(
  CVE-2026-101917 CVE-2026-101918 CVE-2026-102265 CVE-2026-102266
  CVE-2026-102267 CVE-2026-102268 CVE-2026-102269 CVE-2026-102270
  CVE-2026-102271 CVE-2026-102272 CVE-2026-102273 CVE-2026-102274
)

if ! grep -qxF "$RECORDED_AGAINST \\" requirements-scan.txt; then
  echo "requirements-scan.txt no longer pins $RECORDED_AGAINST;" \
       "re-read the exceptions in scripts/audit.sh against the new release" >&2
  exit 1
fi

ignore=()
for id in "${EXCEPTIONS[@]}"; do
  ignore+=(--ignore-vuln "$id")
done
"$PYTHON" -m pip_audit --require-hashes -r requirements-scan.txt "${ignore[@]}"
