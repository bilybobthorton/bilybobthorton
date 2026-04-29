#!/usr/bin/env bash
# Rolling deploy — pull latest code, rebuild images, migrate, restart.
# Run from the sentinelcore/ directory on the VPS.
# Usage: bash scripts/deploy.sh [branch]
set -euo pipefail

BRANCH="${1:-claude/malware-detection-app-bRsUv}"
COMPOSE="docker compose -f infra/docker-compose.prod.yml"

echo "==================================================================="
echo "  SentinelCore Deploy"
echo "  Branch: $BRANCH"
echo "  Time  : $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo "==================================================================="

# ── Pull latest code ──────────────────────────────────────────────────────────
echo ""
echo "==> Pulling latest code from origin/$BRANCH..."
git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"

# ── Build images ──────────────────────────────────────────────────────────────
echo "==> Building Docker images..."
$COMPOSE build api worker dashboard

# ── Migrate ───────────────────────────────────────────────────────────────────
echo "==> Running database migrations..."
$COMPOSE run --rm migrate

# ── Restart services ──────────────────────────────────────────────────────────
echo "==> Restarting services..."
$COMPOSE up -d --remove-orphans

# ── Health check ──────────────────────────────────────────────────────────────
echo "==> Waiting for API health check..."
for i in $(seq 1 12); do
    if curl -sf http://localhost/health > /dev/null 2>&1; then
        echo ""
        echo "==================================================================="
        echo "  Deploy successful! Health check passed."
        echo "==================================================================="
        exit 0
    fi
    echo "    Attempt $i/12 — waiting 5s..."
    sleep 5
done

echo ""
echo "ERROR: Health check failed after 60s. Showing recent logs:"
$COMPOSE logs --tail=50 api
exit 1
