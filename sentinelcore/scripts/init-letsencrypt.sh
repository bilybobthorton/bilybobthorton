#!/usr/bin/env bash
# First-time Let's Encrypt certificate issuance.
# Run once from the sentinelcore/ directory after server-setup.sh.
# Usage: bash scripts/init-letsencrypt.sh <domain> <email>
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <email>}"
EMAIL="${2:?Usage: $0 <domain> <email>}"
COMPOSE="docker compose -f infra/docker-compose.prod.yml"

echo "==================================================================="
echo "  Let's Encrypt — initial certificate issuance"
echo "  Domain : $DOMAIN"
echo "  Email  : $EMAIL"
echo "==================================================================="

# Verify the nginx config has been patched
if grep -q "SENTINEL_DOMAIN" infra/nginx/nginx.prod.conf 2>/dev/null; then
    echo "ERROR: nginx.prod.conf still contains SENTINEL_DOMAIN placeholder."
    echo "       server-setup.sh should have patched it, or run:"
    echo "       sed -i 's/SENTINEL_DOMAIN/$DOMAIN/g' infra/nginx/nginx.prod.conf"
    exit 1
fi

# Ensure certbot volumes exist
docker volume create certbot_certs 2>/dev/null || true
docker volume create certbot_www   2>/dev/null || true

# Start a minimal nginx on port 80 to serve ACME challenges.
# Uses a temporary inline config — no SSL yet (certs don't exist yet).
echo ""
echo "==> Starting temporary HTTP-only nginx for ACME challenge..."
docker run -d --name sc_certbot_init \
    --rm \
    -p 80:80 \
    -v certbot_www:/var/www/certbot \
    nginx:1.25-alpine \
    /bin/sh -c "
        printf 'events{} http{ server{ listen 80;
            location /.well-known/acme-challenge/{ root /var/www/certbot; }
            location /{ return 200 \"ok\"; }
        }}' > /etc/nginx/nginx.conf && nginx -g 'daemon off;'
    "

# Give nginx a moment to start
sleep 3

echo "==> Requesting certificate from Let's Encrypt..."
docker run --rm \
    -v certbot_certs:/etc/letsencrypt \
    -v certbot_www:/var/www/certbot \
    certbot/certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

echo "==> Stopping temporary nginx..."
docker stop sc_certbot_init 2>/dev/null || true

echo ""
echo "==> Certificate issued successfully!"
echo "==> Running database migrations..."
$COMPOSE run --rm migrate

echo "==> Starting full production stack..."
$COMPOSE up -d

echo "==> Waiting for services to be healthy..."
sleep 15

if curl -sf "https://$DOMAIN/health" > /dev/null 2>&1; then
    echo ""
    echo "==================================================================="
    echo "  SentinelCore is live at https://$DOMAIN"
    echo "==================================================================="
else
    echo ""
    echo "  Health check on https://$DOMAIN/health did not respond yet."
    echo "  Check logs: docker compose -f infra/docker-compose.prod.yml logs"
    echo "  DNS may still be propagating — try again in a few minutes."
fi
