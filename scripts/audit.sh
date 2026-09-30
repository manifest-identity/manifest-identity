#!/usr/bin/env bash
# Audit every hash-pinned tree against known vulnerabilities.
#
# No tree carries an exception. The scanner tree's one override, PyJWT
# above the line Semgrep declares, is made when the tree is compiled
# (scripts/compile_scan.py), so what the audit reads is what installs.
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
# The scanner tree is complete and installs without a resolver, so the
# audit reads its pins as written rather than handing them to pip,
# where Semgrep's declared line would reassert itself and refuse.
"$PYTHON" -m pip_audit --require-hashes --disable-pip -r requirements-scan.txt
