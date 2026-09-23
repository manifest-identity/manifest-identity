#!/bin/bash -eu
# Build every harness under fuzz/ against the pinned dependency tree.
# The application is run from its source tree rather than installed
# as a package, so the harnesses import it the same way: the tree goes
# on the path for the build and is bundled into each fuzzer binary.
pip3 install --require-hashes -r requirements.txt
export PYTHONPATH="$SRC/manifest-identity"
for harness in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness" --paths="$SRC/manifest-identity"
done
