#!/usr/bin/env bash
# Bring up the local Kubernetes cluster: kind with a digest-pinned node
# image and Calico from the vendored manifest. Tools are fetched from
# their canonical releases and checksum-verified before first use, the
# same discipline the pipeline applies, and land in .tools/, which git
# ignores. Run from the repository root; tear down with
# scripts/cluster-down.sh.
set -euo pipefail

KIND_VERSION="v0.32.0"
KIND_SHA256="50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54"
KUBECTL_VERSION="v1.36.3"
KUBECTL_SHA256="ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336"
CALICO_MANIFEST="deploy/kind/calico-v3.32.1.yaml"
CALICO_SHA256="a1df919d9721cf667accdc3e72848911b0cb25cfab7d2478ad0c996302c95744"

TOOLS="$(pwd)/.tools"
mkdir -p "$TOOLS"

fetch() {
  local name="$1" url="$2" sha="$3" dest="$TOOLS/$1"
  if [ ! -x "$dest" ]; then
    echo "fetching $name"
    curl -sSfL --retry 3 --retry-delay 2 --retry-connrefused -o "$dest" "$url"
    echo "$sha  $dest" | sha256sum -c - >/dev/null
    chmod +x "$dest"
  fi
}

fetch kind "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256"
fetch kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256"

# The vendored manifest is verified against its recorded digest, so a
# quiet edit to a 7800-line file is a loud failure instead.
echo "$CALICO_SHA256  $CALICO_MANIFEST" | sha256sum -c - >/dev/null

if "$TOOLS/kind" get clusters 2>/dev/null | grep -qx manifest-identity; then
  echo "cluster manifest-identity already exists; scripts/cluster-down.sh removes it"
  exit 1
fi

"$TOOLS/kind" create cluster --config deploy/kind/kind-config.yaml --wait 120s

"$TOOLS/kubectl" apply -f "$CALICO_MANIFEST"
echo "waiting for calico"
"$TOOLS/kubectl" -n kube-system rollout status daemonset/calico-node --timeout=180s
"$TOOLS/kubectl" -n kube-system rollout status deployment/calico-kube-controllers --timeout=180s
"$TOOLS/kubectl" wait --for=condition=Ready nodes --all --timeout=120s

echo
echo "cluster ready:"
"$TOOLS/kubectl" get nodes
"$TOOLS/kubectl" -n kube-system get pods -o wide | grep -E "calico|NAME"
