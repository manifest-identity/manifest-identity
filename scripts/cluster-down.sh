#!/usr/bin/env bash
# Remove the local cluster. The tools stay in .tools/ for the next run;
# nothing else survives, which is the point of a drill cluster.
set -euo pipefail
TOOLS="$(pwd)/.tools"
"$TOOLS/kind" delete cluster --name manifest-identity
