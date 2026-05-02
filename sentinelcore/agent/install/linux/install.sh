#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelCore Endpoint Agent — Linux Installer
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Fedora 36+
#
# Usage:
#   curl -fsSL https://yourdomain.com/install/linux | sudo bash
# Or locally:
#   sudo bash install.sh --api-url https://yourdomain.com --api-key sk_...
#
# Options:
#   --api-url URL       SentinelCore API base URL (required)
#   --api-key KEY       Your SentinelCore API key (required)
#   --agent-id ID       Agent ID (auto-generated if omitted)
#   --install-dir DIR   Installation directory (default: /opt/sentinelcore)
#   --no-service        Install binary only, skip systemd service
#   --uninstall         Remove the agent and service
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

AGENT_NAME="sentinel-agent"
INSTALL_DIR="/opt/sentinelcore"
BIN_PATH="$INSTALL_DIR/$AGENT_NAME"
CONFIG_DIR="/etc/sentinelcore"
CONFIG_FILE="$CONFIG_DIR/agent.toml"
SERVICE_FILE="/etc/systemd/system/sentinel-agent.service"
LOG_DIR="/var/log/sentinelcore"

API_URL=""
API_KEY=""
AGENT_ID=""
NO_SERVICE=false
UNINSTALL=false

RELEASE_URL="https://github.com/bilybobthorton/bilybobthorton/releases/latest/download"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
step()  { echo -e "${BLU}[→]${NC} $*"; }

usage() {
  echo "Usage: sudo bash install.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --api-url URL       SentinelCore API base URL"
  echo "  --api-key KEY       Your API key from Settings → API Key"
  echo "  --agent-id ID       Agent identifier (default: hostname)"
  echo "  --install-dir DIR   Installation directory (default: /opt/sentinelcore)"
  echo "  --no-service        Install binary only, do not register systemd service"
  echo "  --uninstall         Remove agent and systemd service"
  echo "  --help              Show this help"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)    API_URL="$2";     shift 2 ;;
    --api-key)    API_KEY="$2";     shift 2 ;;
    --agent-id)   AGENT_ID="$2";   shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; BIN_PATH="$INSTALL_DIR/$AGENT_NAME"; shift 2 ;;
    --no-service) NO_SERVICE=true;  shift ;;
    --uninstall)  UNINSTALL=true;   shift ;;
    --help|-h)    usage ;;
    *) error "Unknown option: $1. Run with --help for usage." ;;
  esac
done

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash $0 $*"

# ── Uninstall ────────────────────────────────────────────────────────────────
if $UNINSTALL; then
  step "Stopping and disabling sentinel-agent service…"
  systemctl stop sentinel-agent 2>/dev/null || true
  systemctl disable sentinel-agent 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload 2>/dev/null || true

  step "Removing files…"
  rm -f "$BIN_PATH"
  rm -f "$CONFIG_FILE"
  rmdir --ignore-fail-on-non-empty "$CONFIG_DIR" "$INSTALL_DIR" "$LOG_DIR" 2>/dev/null || true

  info "SentinelCore agent uninstalled."
  exit 0
fi

# ── Validate args ─────────────────────────────────────────────────────────────
[[ -n "$API_URL" ]] || error "--api-url is required. Get it from your SentinelCore dashboard."
[[ -n "$API_KEY" ]] || error "--api-key is required. Get it from Settings → API Key."

API_URL="${API_URL%/}"  # strip trailing slash
AGENT_ID="${AGENT_ID:-$(hostname -s)}"

# ── Detect architecture ───────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  BINARY_ARCH="x86_64-unknown-linux-musl" ;;
  aarch64) BINARY_ARCH="aarch64-unknown-linux-musl" ;;
  armv7*)  BINARY_ARCH="armv7-unknown-linux-musleabihf" ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

BINARY_NAME="${AGENT_NAME}-${BINARY_ARCH}"
DOWNLOAD_URL="${RELEASE_URL}/${BINARY_NAME}"

# ── Detect OS / package manager ───────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
  PKG_MGR="yum"
else
  PKG_MGR="none"
fi

info "SentinelCore Linux Agent Installer"
echo "  Agent ID   : $AGENT_ID"
echo "  API URL    : $API_URL"
echo "  Install    : $BIN_PATH"
echo "  Arch       : $ARCH ($BINARY_ARCH)"
echo ""

# ── Install curl if missing ───────────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
  step "Installing curl…"
  case "$PKG_MGR" in
    apt) apt-get update -qq && apt-get install -y curl ;;
    dnf) dnf install -y curl ;;
    yum) yum install -y curl ;;
    *) error "curl not found and no supported package manager detected. Install curl manually." ;;
  esac
fi

# ── Download binary ───────────────────────────────────────────────────────────
step "Downloading sentinel-agent binary…"
mkdir -p "$INSTALL_DIR"

TMP_BIN=$(mktemp)
if curl -fsSL --progress-bar "$DOWNLOAD_URL" -o "$TMP_BIN"; then
  chmod +x "$TMP_BIN"
  mv "$TMP_BIN" "$BIN_PATH"
  info "Binary installed to $BIN_PATH"
else
  rm -f "$TMP_BIN"
  warn "GitHub release binary not found. Attempting to build from source…"

  if ! command -v cargo &>/dev/null; then
    step "Installing Rust toolchain…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    source "$HOME/.cargo/env"
  fi

  step "Building sentinel-agent from source (this takes ~2 minutes)…"
  REPO_DIR=$(mktemp -d)
  git clone --depth=1 https://github.com/bilybobthorton/bilybobthorton.git "$REPO_DIR"
  cd "$REPO_DIR/sentinelcore/agent"
  cargo build --release --target "$BINARY_ARCH" 2>/dev/null || cargo build --release
  BUILT_BIN=$(find target -name "$AGENT_NAME" -type f | head -1)
  [[ -n "$BUILT_BIN" ]] || error "Build succeeded but binary not found."
  cp "$BUILT_BIN" "$BIN_PATH"
  chmod +x "$BIN_PATH"
  cd /
  rm -rf "$REPO_DIR"
  info "Binary built and installed to $BIN_PATH"
fi

# ── Write config ──────────────────────────────────────────────────────────────
step "Writing config to $CONFIG_FILE…"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"

cat > "$CONFIG_FILE" << TOML
# SentinelCore Agent Configuration
# Managed by: $0

[agent]
id          = "$AGENT_ID"
api_url     = "$API_URL"
api_key     = "$API_KEY"
log_level   = "info"
log_file    = "$LOG_DIR/agent.log"

[scan]
watch_paths = ["/home", "/tmp", "/var/tmp", "/dev/shm"]
high_risk_extensions = [".exe", ".dll", ".sh", ".py", ".elf", ".so", ".bin"]

[network]
poll_interval_secs = 30
c2_ports = [4444, 1337, 31337, 50050, 6666, 9001, 8888]

[fim]
# File Integrity Monitoring — baseline these on first run
watch_files = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/etc/ssh/sshd_config",
  "/etc/crontab",
]
check_interval_secs = 30
TOML

chmod 600 "$CONFIG_FILE"
info "Config written."

# ── Verify binary works ───────────────────────────────────────────────────────
step "Verifying binary…"
if "$BIN_PATH" status 2>&1 | grep -q "SentinelCore\|agent\|not running" 2>/dev/null; then
  info "Binary verified."
elif "$BIN_PATH" --version &>/dev/null || "$BIN_PATH" --help &>/dev/null 2>/dev/null; then
  info "Binary verified."
else
  warn "Binary check returned non-zero (may be normal at first run)."
fi

# ── systemd service ───────────────────────────────────────────────────────────
if $NO_SERVICE; then
  warn "--no-service: skipping systemd registration."
else
  step "Installing systemd service…"
  cat > "$SERVICE_FILE" << UNIT
[Unit]
Description=SentinelCore Endpoint Agent
Documentation=https://yourdomain.com/api-docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH run --config $CONFIG_FILE
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel-agent

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$LOG_DIR /tmp

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now sentinel-agent

  sleep 2
  if systemctl is-active --quiet sentinel-agent; then
    info "sentinel-agent service is running."
  else
    warn "Service may not have started. Check: journalctl -u sentinel-agent -n 50"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GRN}  SentinelCore agent installed successfully!${NC}"
echo -e "${GRN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Binary     : ${YLW}$BIN_PATH${NC}"
echo -e "  Config     : ${YLW}$CONFIG_FILE${NC}"
echo -e "  Logs       : ${YLW}$LOG_DIR/agent.log${NC}"
echo ""
if ! $NO_SERVICE; then
  echo -e "  Service status : ${YLW}systemctl status sentinel-agent${NC}"
  echo -e "  Live logs      : ${YLW}journalctl -u sentinel-agent -f${NC}"
  echo -e "  Stop agent     : ${YLW}systemctl stop sentinel-agent${NC}"
  echo -e "  Uninstall      : ${YLW}sudo bash $0 --uninstall${NC}"
fi
echo ""
echo -e "  Alerts will appear in your dashboard: ${YLW}${API_URL}/alerts${NC}"
echo ""
