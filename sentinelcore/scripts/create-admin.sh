#!/usr/bin/env bash
# Create an admin/enterprise account and print the credentials.
# Run from sentinelcore/ directory on the server.
# Usage: bash scripts/create-admin.sh <email> <password>
set -euo pipefail

EMAIL="${1:-kingtrevor981@gmail.com}"
PASSWORD="${2:-}"

if [[ -z "$PASSWORD" ]]; then
  echo "Usage: bash scripts/create-admin.sh <email> <password>"
  exit 1
fi

API="http://localhost/api/v1"

echo "==> Registering account: $EMAIL"
RESPONSE=$(curl -sf -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" 2>&1) || {
    echo "Registration failed (account may already exist). Trying login..."
    RESPONSE=$(curl -sf -X POST "$API/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
  }

TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: Could not get token. Response: $RESPONSE"
  exit 1
fi

echo "==> Upgrading to Enterprise tier in database..."
docker compose -f infra/docker-compose.prod.yml exec -T db \
  psql -U sentinel -d sentinelcore -c \
  "UPDATE users SET tier='enterprise', is_verified=true, trial_ends_at=NULL WHERE email='$EMAIL';"

echo ""
echo "==================================================================="
echo "  Admin account ready!"
echo "  Email   : $EMAIL"
echo "  Token   : $TOKEN"
echo "  Tier    : enterprise"
echo "==================================================================="
echo ""
echo "  Dashboard: http://dashboard.redgaurd.com"
echo "  API docs : http://api.redgaurd.com/docs"
