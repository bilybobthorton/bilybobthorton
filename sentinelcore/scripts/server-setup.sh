#!/usr/bin/env bash
# One-time VPS bootstrap — Ubuntu 22.04 LTS
# Run as root on a fresh server.
# Usage: bash server-setup.sh <your-domain.com> <your-email@example.com>
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <email>}"
EMAIL="${2:?Usage: $0 <domain> <email>}"
REPO="https://github.com/bilybobthorton/bilybobthorton.git"
BRANCH="claude/malware-detection-app-bRsUv"
APP_DIR="/opt/sentinelcore"

echo "==================================================================="
echo "  SentinelCore VPS Setup"
echo "  Domain : $DOMAIN"
echo "  Email  : $EMAIL"
echo "==================================================================="

# ── System packages ──────────────────────────────────────────────────────────
echo ""
echo "==> Updating packages..."
apt-get update -qq
apt-get install -y -qq \
    git curl ufw fail2ban \
    ca-certificates gnupg lsb-release

# ── Docker ───────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "==> Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "==> Docker already installed ($(docker --version))"
fi

if ! docker compose version &>/dev/null; then
    echo "==> Installing Docker Compose plugin..."
    apt-get install -y -qq docker-compose-plugin
fi

# ── Firewall ─────────────────────────────────────────────────────────────────
echo "==> Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP'
ufw allow 443/tcp  comment 'HTTPS'
ufw --force enable
echo "    UFW status:"
ufw status numbered

# ── fail2ban ─────────────────────────────────────────────────────────────────
echo "==> Enabling fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# ── Clone / update repo ──────────────────────────────────────────────────────
echo "==> Cloning repo to $APP_DIR..."
if [ -d "$APP_DIR/.git" ]; then
    git -C "$APP_DIR" fetch origin "$BRANCH"
    git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
    git clone --branch "$BRANCH" --depth 1 "$REPO" "$APP_DIR"
fi

# ── Patch nginx config with real domain ──────────────────────────────────────
echo "==> Patching nginx config with domain: $DOMAIN..."
sed -i "s/SENTINEL_DOMAIN/$DOMAIN/g" \
    "$APP_DIR/sentinelcore/infra/nginx/nginx.prod.conf"

# ── .env file ────────────────────────────────────────────────────────────────
ENV_FILE="$APP_DIR/sentinelcore/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$APP_DIR/sentinelcore/.env.example" "$ENV_FILE"
    # Generate secure keys automatically
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    PG_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    REDIS_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

    sed -i "s|APP_SECRET_KEY=.*|APP_SECRET_KEY=$SECRET_KEY|" "$ENV_FILE"
    sed -i "s|JWT_SECRET_KEY=.*|JWT_SECRET_KEY=$JWT_SECRET|" "$ENV_FILE"
    sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG_PASS|" "$ENV_FILE"
    sed -i "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=$REDIS_PASS|" "$ENV_FILE"
    sed -i "s|DOMAIN=.*|DOMAIN=$DOMAIN|" "$ENV_FILE"

    # Point URLs at Docker service names
    sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://sentinel:$PG_PASS@db:5432/sentinelcore|" "$ENV_FILE"
    sed -i "s|REDIS_URL=.*|REDIS_URL=redis://:$REDIS_PASS@redis:6379/0|" "$ENV_FILE"
    sed -i "s|CELERY_BROKER_URL=.*|CELERY_BROKER_URL=redis://:$REDIS_PASS@redis:6379/1|" "$ENV_FILE"
    sed -i "s|CELERY_RESULT_BACKEND=.*|CELERY_RESULT_BACKEND=redis://:$REDIS_PASS@redis:6379/2|" "$ENV_FILE"
    sed -i "s|APP_ENV=.*|APP_ENV=production|" "$ENV_FILE"

    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  .env created with auto-generated secrets.                  │"
    echo "  │  Fill in the remaining API keys before starting:            │"
    echo "  │    VIRUSTOTAL_API_KEY, OTX_API_KEY                          │"
    echo "  │    STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET                 │"
    echo "  │    STRIPE_PRICE_PRO, STRIPE_PRICE_ENTERPRISE                │"
    echo "  │  File: $ENV_FILE"
    echo "  └─────────────────────────────────────────────────────────────┘"
else
    echo "  .env already exists — skipping generation."
fi

# ── systemd service ───────────────────────────────────────────────────────────
echo "==> Installing sentinelcore.service..."
cat > /etc/systemd/system/sentinelcore.service <<EOF
[Unit]
Description=SentinelCore Malware Detection Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$APP_DIR/sentinelcore
ExecStart=docker compose -f infra/docker-compose.prod.yml up -d
ExecStop=docker compose -f infra/docker-compose.prod.yml down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable sentinelcore

echo ""
echo "==================================================================="
echo "  Setup complete. Next steps:"
echo ""
echo "  1. Edit secrets:  nano $ENV_FILE"
echo ""
echo "  2. Issue TLS cert (run once):"
echo "       bash $APP_DIR/sentinelcore/scripts/init-letsencrypt.sh \\"
echo "            $DOMAIN $EMAIL"
echo ""
echo "  3. Future deploys:"
echo "       bash $APP_DIR/sentinelcore/scripts/deploy.sh"
echo "==================================================================="
