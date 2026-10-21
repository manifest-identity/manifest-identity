#!/usr/bin/env bash
# Audit every hash-pinned tree against known vulnerabilities.
#
# No tree carries an exception.
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

# Every tree, not only the ones the application installs: the Scorecard
# reads each lockfile in the repository, and three urllib3 advisories
# in the docs tree went unaudited for the day it took to learn that.
"$PYTHON" -m pip_audit --require-hashes -r requirements.txt
"$PYTHON" -m pip_audit --require-hashes -r requirements-dev.txt
"$PYTHON" -m pip_audit --require-hashes -r requirements-docs.txt
"$PYTHON" -m pip_audit --require-hashes -r requirements-browser.txt
