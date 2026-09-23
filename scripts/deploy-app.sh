#!/usr/bin/env bash
# Deploy the application to the local cluster: build the image, load it
# into kind, create the secrets from the environment, apply the
# manifests, and wait for readiness. Mirrors the compose contract: the
# database password and the two administrator keys must be set, and the
# script refuses to start while one is missing, because a generated
# default becomes the real credential the day nobody replaces it.
# Requires the cluster from scripts/cluster-up.sh. Environment:
#   POSTGRES_PASSWORD, ROLECALL_APP_DB_PASSWORD, ROLECALL_ADMIN_USERNAME,
#   ROLECALL_ADMIN_PASSWORD
set -euo pipefail

: "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD, see .env.example}"
: "${ROLECALL_APP_DB_PASSWORD:?set ROLECALL_APP_DB_PASSWORD, see .env.example}"
: "${ROLECALL_ADMIN_USERNAME:?set ROLECALL_ADMIN_USERNAME, see .env.example}"
: "${ROLECALL_ADMIN_PASSWORD:?set ROLECALL_ADMIN_PASSWORD, see .env.example}"

TOOLS="$(pwd)/.tools"
KUBECTL="$TOOLS/kubectl"

docker build -q -t rolecall:local .
"$TOOLS/kind" load docker-image rolecall:local --name rolecall

"$KUBECTL" apply -f deploy/k8s/namespace.yaml

# Secrets are created imperatively from the environment, never from a
# file in the repository, and never updated silently: delete and
# recreate is the visible path when a credential changes.
"$KUBECTL" -n rolecall create secret generic rolecall-db \
  --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=ROLECALL_APP_DB_PASSWORD="$ROLECALL_APP_DB_PASSWORD" \
  --from-literal=ROLECALL_OWNER_DATABASE_URL="postgresql+psycopg://rolecall:${POSTGRES_PASSWORD}@db:5432/rolecall" \
  --from-literal=ROLECALL_DATABASE_URL="postgresql+psycopg://rolecall_app:${ROLECALL_APP_DB_PASSWORD}@db:5432/rolecall" \
  --dry-run=client -o yaml | "$KUBECTL" apply -f -
"$KUBECTL" -n rolecall create secret generic rolecall-admin \
  --from-literal=ROLECALL_ADMIN_USERNAME="$ROLECALL_ADMIN_USERNAME" \
  --from-literal=ROLECALL_ADMIN_PASSWORD="$ROLECALL_ADMIN_PASSWORD" \
  --dry-run=client -o yaml | "$KUBECTL" apply -f -

# The whole directory, not named files: subphases 2.3 and 2.4 added
# manifests by hand and this script fell behind them, which a fresh
# rebuild exposed; applying the directory removes the class.
"$KUBECTL" apply -f deploy/k8s/

echo "waiting for the database"
"$KUBECTL" -n rolecall rollout status statefulset/db --timeout=180s
echo "waiting for the application"
"$KUBECTL" -n rolecall rollout status deployment/app --timeout=180s

echo
echo "ready: http://127.0.0.1:8000"
"$KUBECTL" -n rolecall get pods
