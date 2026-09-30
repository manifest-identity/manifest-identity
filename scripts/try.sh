#!/usr/bin/env bash
# Try manifest-identity in one command: a stack on Docker, the seven
# sample estates imported, the authorized record written, a campaign
# open, and a sign-in printed once.
#
#   ./scripts/try.sh
#
# Secrets are generated here and written to .env if no .env exists;
# nothing is defaulted in the repository (D-051). The administrator's
# password is printed to this terminal once and nowhere else. Run it
# again to bring the same stack back; delete .env and run
# `docker compose down -v` to start over.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "try: Docker is required (https://docs.docker.com/get-docker/)" >&2
  exit 1
fi

generate() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

if [ ! -f .env ]; then
  ADMIN_PASSWORD="$(generate)"
  {
    echo "POSTGRES_PASSWORD=$(generate)"
    echo "MANIFEST_IDENTITY_APP_DB_PASSWORD=$(generate)"
    echo "MANIFEST_IDENTITY_ADMIN_USERNAME=admin"
    echo "MANIFEST_IDENTITY_ADMIN_PASSWORD=${ADMIN_PASSWORD}"
  } > .env
  chmod 600 .env
  echo "try: wrote .env with generated secrets"
else
  ADMIN_PASSWORD=""
  echo "try: using the existing .env"
fi

docker compose up -d --build
for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then break; fi
  sleep 2
done
docker compose exec -T app python -m manifest_identity.demo

echo
echo "try: open http://127.0.0.1:8000 and sign in as admin"
if [ -n "$ADMIN_PASSWORD" ]; then
  echo "try: the password is ${ADMIN_PASSWORD} (also in .env, which is ignored by git)"
else
  echo "try: the password is MANIFEST_IDENTITY_ADMIN_PASSWORD in your .env"
fi
