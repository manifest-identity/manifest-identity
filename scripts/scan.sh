#!/usr/bin/env bash
# Run the pipeline's semantic analysis before the push (D-086): the
# same CodeQL queries the pipeline runs, on the same languages, here,
# so a finding reaches this terminal instead of a pull request page.
#
#   scripts/scan.sh            # python, actions, and javascript
#
# The CodeQL bundles are fetched once from their release, verified
# against the checksums pinned below, and kept under .tools/codeql,
# which is ignored by git. Nothing runs from an unverified download.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="codeql-bundle-v2.27.1"
declare -A SUMS=(
  ["python"]="ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0"
  ["actions"]="71247327cf3afe4115acc546fe3ac77f2865928205d7688d6a0b7153e055603f"
  ["javascript"]="8d30281899f150633913b08cf4eae755be607f282d643ad418ad638f4210e833"
)
TOOLS=".tools/codeql"
mkdir -p "$TOOLS"

fetch() {  # one language's bundle, verified, unpacked once
  local language="$1" file="$TOOLS/codeql-bundle-${language}-linux64.tar.zst"
  if [ ! -x "$TOOLS/$language/codeql/codeql" ]; then
    if [ ! -f "$file" ]; then
      curl -sSfL --retry 3 -o "$file" \
        "https://github.com/github/codeql-action/releases/download/$VERSION/codeql-bundle-${language}-linux64.tar.zst"
    fi
    echo "${SUMS[$language]}  $file" | sha256sum -c - >/dev/null
    mkdir -p "$TOOLS/$language"
    tar --zstd -xf "$file" -C "$TOOLS/$language"
  fi
}

analyze() {  # database, then the pipeline's default query suite
  local language="$1" db="$TOOLS/db-$language" out="$TOOLS/$language.sarif"
  local codeql="$TOOLS/$language/codeql/codeql"
  rm -rf "$db"
  "$codeql" database create "$db" --language="$language" --source-root=. \
    --overwrite --quiet >/dev/null
  "$codeql" database analyze "$db" --format=sarif-latest --output="$out" --quiet >/dev/null
  python3 - "$out" "$language" <<'PY'
import json, sys
sarif = json.load(open(sys.argv[1]))
results = [r for run in sarif["runs"] for r in run.get("results", [])]
for r in results:
    loc = r["locations"][0]["physicalLocation"]
    print(f"FAIL {sys.argv[2]} {r['ruleId']} {loc['artifactLocation']['uri']}:{loc.get('region', {}).get('startLine', '?')}: {r['message']['text'][:160]}")
print(f"{sys.argv[2]}: {len(results)} finding(s)")
sys.exit(1 if results else 0)
PY
}

status=0
for language in python actions javascript; do
  fetch "$language"
  analyze "$language" || status=1
done
exit $status
