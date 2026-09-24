#!/usr/bin/env bash
# Lint and type-check at commit time.
#
# The other commit hooks are fast and dependency-light on purpose, and
# the language tooling ran only in the pipeline. That gap let a commit
# pass every hook while failing mypy, which is exactly the false
# assurance a hook set exists to prevent: a green commit that the
# pipeline will reject minutes later, or worse, that a reader trusts.
#
# Both tools live in the project's environment rather than on the
# path, so this prefers the documented .venv and falls back to the
# active interpreter, which makes the hook work whether or not the
# environment is activated.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python3"
fi

if ! "$PYTHON" -c "import ruff" >/dev/null 2>&1 \
   && ! "$PYTHON" -m ruff --version >/dev/null 2>&1; then
  echo "ruff is not installed in $PYTHON; run" \
       "pip install -r requirements-dev.txt" >&2
  exit 1
fi

"$PYTHON" -m ruff check .
"$PYTHON" -m mypy
