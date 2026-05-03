#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RedGuard VPN — WireGuard Node Setup Script
# Run this on each VPN droplet (Ubuntu 22.04 / Debian 12).
# Tested on DigitalOcean $6/mo basic droplet (1 vCPU, 1 GB RAM).
#
# Usage:  bash scripts/setup-wireguard.sh [SERVER_IP] [VPN_SUBNET]
#   SERVER_IP   — public IP of this droplet (auto-detected if omitted)
#   VPN_SUBNET  — WireGuard subnet (default: 10.8.0.0/24)
#
# After running, note the SERVER_PUBLIC_KEY printed at the end and paste it
# into your API server's .env as VPN_SERVER_PUBLIC_KEY.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SERVER_IP="${1:-$(curl -s --max-time 5 ifconfig.me || hostname -I | awk '{print $1}')}"
VPN_SUBNET="${2:-10.8.0.0/24}"
SERVER_ADDR="10.8.0.1"
WG_PORT=51820
WG_IFACE="wg0"
WG_DIR="/etc/wireguard"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash $0"

info "Installing WireGuard…"
apt-get update -qq
apt-get install -y wireguard wireguard-tools iptables iproute2 curl

# Detect primary network interface
NET_IFACE=$(ip route | awk '/default/{print $5; exit}')
[[ -n "$NET_IFACE" ]] || error "Cannot detect network interface"
info "Network interface: $NET_IFACE"

# Generate server keypair
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

if [[ -f "$WG_DIR/server_private.key" ]]; then
  warn "Server keypair already exists — reusing."
else
  info "Generating server keypair…"
  wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
  chmod 600 "$WG_DIR/server_private.key"
fi

SERVER_PRIVATE=$(cat "$WG_DIR/server_private.key")
SERVER_PUBLIC=$(cat "$WG_DIR/server_public.key")

# Enable IP forwarding
info "Enabling IP forwarding…"
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi
sysctl -p >/dev/null

# Write wg0.conf
info "Writing $WG_DIR/$WG_IFACE.conf…"
cat > "$WG_DIR/$WG_IFACE.conf" << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE}
Address    = ${SERVER_ADDR}/24
ListenPort = ${WG_PORT}
SaveConfig = false

# NAT masquerade — route client traffic through this server's internet connection
PostUp   = iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; \\
           iptables -A FORWARD -o ${WG_IFACE} -j ACCEPT; \\
           iptables -t nat -A POSTROUTING -o ${NET_IFACE} -j MASQUERADE; \\
           ip6tables -A FORWARD -i ${WG_IFACE} -j ACCEPT; \\
           ip6tables -t nat -A POSTROUTING -o ${NET_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; \\
           iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT; \\
           iptables -t nat -D POSTROUTING -o ${NET_IFACE} -j MASQUERADE; \\
           ip6tables -D FORWARD -i ${WG_IFACE} -j ACCEPT; \\
           ip6tables -t nat -D POSTROUTING -o ${NET_IFACE} -j MASQUERADE

# Peers are added dynamically via the SentinelCore API.
# To add a client manually:
#   [Peer]
#   PublicKey    = <client_public_key>
#   PresharedKey = <preshared_key>
#   AllowedIPs   = 10.8.0.X/32
EOF
chmod 600 "$WG_DIR/$WG_IFACE.conf"

# UFW / iptables firewall rules
info "Opening firewall port ${WG_PORT}/udp…"
if command -v ufw &>/dev/null; then
  ufw allow "${WG_PORT}/udp" comment "WireGuard VPN" >/dev/null
  ufw --force enable >/dev/null
  info "UFW rule added."
else
  iptables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT
  warn "UFW not installed — iptables rule added (not persistent). Install iptables-persistent to save."
fi

# Start and enable WireGuard
info "Starting WireGuard…"
systemctl enable --now "wg-quick@${WG_IFACE}"
sleep 1

if ip link show "${WG_IFACE}" &>/dev/null; then
  info "WireGuard interface ${WG_IFACE} is UP."
else
  error "WireGuard failed to start. Check: journalctl -u wg-quick@${WG_IFACE}"
fi

# Write a helper to add peers manually (useful for testing)
cat > /usr/local/bin/wg-add-peer << 'HELPER'
#!/usr/bin/env bash
# Usage: wg-add-peer <client_public_key> <preshared_key> <client_ip>
# Example: wg-add-peer "abc...=" "xyz...=" "10.8.0.5"
set -euo pipefail
PUB="$1"; PSK="$2"; IP="$3"
wg set wg0 peer "$PUB" preshared-key <(echo "$PSK") allowed-ips "${IP}/32"
echo "[Peer]" >> /etc/wireguard/wg0.conf
echo "PublicKey    = $PUB" >> /etc/wireguard/wg0.conf
echo "PresharedKey = $PSK" >> /etc/wireguard/wg0.conf
echo "AllowedIPs   = ${IP}/32" >> /etc/wireguard/wg0.conf
echo "Added peer $PUB → ${IP}/32"
HELPER
chmod +x /usr/local/bin/wg-add-peer

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GRN}  RedGuard VPN WireGuard node is ready!${NC}"
echo -e "${GRN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Server IP      : ${YLW}${SERVER_IP}${NC}"
echo -e "  WG interface   : ${YLW}${WG_IFACE} (${SERVER_ADDR}/24)${NC}"
echo -e "  Listen port    : ${YLW}${WG_PORT}/udp${NC}"
echo ""
echo -e "  ${GRN}SERVER PUBLIC KEY (paste into API .env as VPN_SERVER_PUBLIC_KEY):${NC}"
echo -e "  ${YLW}${SERVER_PUBLIC}${NC}"
echo ""
echo -e "  Add to your API .env:"
echo -e "  ${YLW}VPN_SERVER_PUBLIC_KEY=${SERVER_PUBLIC}${NC}"
echo -e "  ${YLW}VPN_SERVER_ENDPOINT=${SERVER_IP}:${WG_PORT}${NC}"
echo ""
echo -e "  View connected peers : ${YLW}wg show${NC}"
echo -e "  Add peer manually    : ${YLW}wg-add-peer <pubkey> <psk> <ip>${NC}"
echo -e "  Restart WireGuard    : ${YLW}systemctl restart wg-quick@${WG_IFACE}${NC}"
echo ""
