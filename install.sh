#!/usr/bin/env bash
set -euo pipefail

# ---------- CayVPN Complete Installation Script ----------
# This script combines the original WireGuard/AdGuard setup with the Flask management app

echo "🚀 CayVPN Complete Installation"
echo "==============================="

# ---------- Configurable ----------
WG_PORT="${WG_PORT:-43210}"
WG_IFACE="${WG_IFACE:-wg0}"
WG_SUBNET_V4="${WG_SUBNET_V4:-10.8.0.1/24}"
ENABLE_IPV6="${ENABLE_IPV6:-1}"

ADGH_ADMIN_PORT="${ADGH_ADMIN_PORT:-3000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-ChangeThisNow_!#}"

OUT_IFACE="${OUT_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)}"
if [[ -z "${OUT_IFACE}" ]]; then echo "Could not auto-detect OUT_IFACE"; exit 1; fi

export DEBIAN_FRONTEND=noninteractive

# ---------- Location Detection ----------
echo "🔍 Detecting server location..."

# Function to get public IP
get_public_ip() {
    local services=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://checkip.amazonaws.com" "https://ipinfo.io/ip")
    for service in "${services[@]}"; do
        local ip=$(curl -s --max-time 5 "$service" 2>/dev/null | tr -d '\n\r')
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# Function to get location details
get_location() {
    local ip="$1"
    if [[ -z "$ip" || "$ip" == "127.0.0.1" ]]; then
        echo "Local Network"
        return
    fi
    
    local apis=(
        "https://ipapi.co/${ip}/json/"
        "https://ipinfo.io/${ip}/json"
        "http://ip-api.com/json/${ip}"
    )
    
    for api in "${apis[@]}"; do
        local response=$(curl -s --max-time 10 "$api" 2>/dev/null)
        if [[ $? -eq 0 && -n "$response" ]]; then
            # Parse JSON response
            local city region country
            if echo "$response" | jq -e '.city' >/dev/null 2>&1; then
                # ipapi.co format
                city=$(echo "$response" | jq -r '.city // empty')
                region=$(echo "$response" | jq -r '.region // empty')
                country=$(echo "$response" | jq -r '.country_name // empty')
            elif echo "$response" | jq -e '.region' >/dev/null 2>&1; then
                # ipinfo.io format
                city=$(echo "$response" | jq -r '.city // empty')
                region=$(echo "$response" | jq -r '.region // empty')
                country=$(echo "$response" | jq -r '.country // empty')
            elif echo "$response" | jq -e '.regionName' >/dev/null 2>&1; then
                # ip-api.com format
                city=$(echo "$response" | jq -r '.city // empty')
                region=$(echo "$response" | jq -r '.regionName // empty')
                country=$(echo "$response" | jq -r '.country // empty')
            fi
            
            local location_parts=()
            [[ -n "$city" && "$city" != "null" ]] && location_parts+=("$city")
            [[ -n "$region" && "$region" != "null" ]] && location_parts+=("$region")
            [[ -n "$country" && "$country" != "null" ]] && location_parts+=("$country")
            
            if [[ ${#location_parts[@]} -gt 0 ]]; then
                local location=$(IFS=', '; echo "${location_parts[*]}")
                echo "$location"
                return 0
            fi
        fi
    done
    
    echo "Server Location (IP: $ip)"
}

# Detect IP and location
PUB_IP=$(get_public_ip)
if [[ -z "$PUB_IP" ]]; then
    echo "⚠ Could not detect public IP, using interface IP"
    PUB_IP="$(ip -4 addr show dev ${OUT_IFACE} | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
fi

SERVER_REGION=$(get_location "$PUB_IP")
echo "📡 Public IP: $PUB_IP"
echo "📍 Detected Region: $SERVER_REGION"

# Export for use by other scripts/apps
export SERVER_REGION="$SERVER_REGION"
export SERVER_IP="$PUB_IP"

# Save to a config file for the Flask app to read
mkdir -p /etc/wireguard
cat >/etc/wireguard/server_info.conf <<EOF
SERVER_IP=$PUB_IP
SERVER_REGION=$SERVER_REGION
EOF

echo "💾 Server info saved to /etc/wireguard/server_info.conf"

# ---------- Packages ----------
echo "📦 Installing system packages..."
apt update
apt install -y --no-install-recommends \
  wireguard wireguard-tools iptables-persistent netfilter-persistent \
  curl wget ca-certificates jq tar python3 python3-pip python3-venv \
  python3-yaml python3-bcrypt apache2-utils git

# ---------- resolv.conf ----------
if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
  systemctl disable --now systemd-resolved || true
fi
rm -f /etc/resolv.conf
echo -e "nameserver 1.1.1.1\noptions edns0" > /etc/resolv.conf

# ---------- WireGuard ----------
echo "🔐 Setting up WireGuard..."
umask 077
mkdir -p /etc/wireguard
if [[ ! -f /etc/wireguard/server.key ]]; then
  wg genkey | tee /etc/wireguard/server.key >/dev/null
  cat /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
fi

cat >/etc/wireguard/${WG_IFACE}.conf <<EOF
[Interface]
Address = ${WG_SUBNET_V4}
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/server.key)
SaveConfig = true
EOF
chmod 600 /etc/wireguard/server.key /etc/wireguard/${WG_IFACE}.conf

cat >/etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward=1
$( [[ "${ENABLE_IPV6}" = "1" ]] && echo "net.ipv6.conf.all.forwarding=1" )
EOF
sysctl --system

iptables -t nat -C POSTROUTING -o "${OUT_IFACE}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "${OUT_IFACE}" -j MASQUERADE
iptables -C FORWARD -i "${WG_IFACE}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${WG_IFACE}" -j ACCEPT
iptables -C FORWARD -o "${WG_IFACE}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "${WG_IFACE}" -j ACCEPT
netfilter-persistent save
systemctl enable --now netfilter-persistent
systemctl enable --now "wg-quick@${WG_IFACE}" || true

# ---------- cloudflared (DNS over HTTPS) ----------
echo "☁️ Installing cloudflared..."
tmpdir="$(mktemp -d)"
pushd "$tmpdir" >/dev/null
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i cloudflared-linux-amd64.deb || true
id -u cloudflared &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared

cat >/etc/systemd/system/cloudflared-dns.service <<'EOF'
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=network-online.target
Wants=network-online.target

[Service]
User=cloudflared
ExecStart=/usr/bin/cloudflared proxy-dns --address 127.0.0.1 --port 5053 \
  --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/cloudflared-dns.service
systemctl daemon-reload
systemctl enable --now cloudflared-dns
popd >/dev/null

# ---------- AdGuard Home ----------
echo "🛡️ Installing AdGuard Home..."
pushd "$tmpdir" >/dev/null
DL_URL="$(curl -s https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | jq -r '.assets[] | select(.name | test("AdGuardHome_linux_amd64\\.tar\\.gz$")) .browser_download_url')"
wget -q "$DL_URL" -O adguard.tar.gz
tar -xzf adguard.tar.gz
install -d /opt/AdGuardHome
cp -r AdGuardHome/* /opt/AdGuardHome/
popd >/dev/null

WG_GW_IP="$(ip -j addr show ${WG_IFACE} | jq -r '.[0].addr_info[] | select(.family=="inet") | .local' | head -n1 || true)"
[[ -z "${WG_GW_IP}" ]] && WG_GW_IP="10.8.0.1"

# ---------- Admin Password ----------
BCRYPT_HASH="$(python3 - <<'PY'
import bcrypt, os
pwd = os.environ.get("ADMIN_PASS","ChangeThisNow_!#").encode()
print(bcrypt.hashpw(pwd, bcrypt.gensalt()).decode())
PY
)"

# ---------- AdGuard Config (with filters) ----------
cat >/opt/AdGuardHome/AdGuardHome.yaml <<EOF
bind_host: 0.0.0.0
bind_port: ${ADGH_ADMIN_PORT}
users:
  - name: ${ADMIN_USER}
    password: ${BCRYPT_HASH}
dns:
  bind_hosts:
    - 127.0.0.1
    - ${WG_GW_IP}
  port: 53
  upstream_dns:
    - 127.0.0.1:5053
  filtering_enabled: true
  cache_size: 1048576
filters_update_interval: 24
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
  - enabled: true
    url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    name: StevenBlack Hosts
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt
    name: HaGeZi’s Ultimate Blocklist
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt
    name: Phishing Army
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt
    name: Malicious URL Blocklist
schema_version: 30
EOF

# ---------- Final AdGuard Setup ----------
/opt/AdGuardHome/AdGuardHome -s install || true
systemctl enable --now AdGuardHome || true

rm -f /etc/resolv.conf
echo -e "nameserver 127.0.0.1\noptions edns0" > /etc/resolv.conf

# ---------- CayVPN Flask App Setup ----------
echo "🐍 Setting up CayVPN Flask application..."

# Clone/update repository (assuming we're running from within it)
if [[ ! -d ".git" ]]; then
    echo "❌ Please run this script from within the cloned CayVPN repository"
    exit 1
fi

# Update repository
git pull origin main

# Set up Python virtual environment
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create systemd service for CayVPN
cat >/etc/systemd/system/cayvpn.service <<EOF
[Unit]
Description=CayVPN Management Interface
After=network.target AdGuardHome.service wg-quick@${WG_IFACE}.service
Wants=AdGuardHome.service wg-quick@${WG_IFACE}.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python app.py
Restart=always
RestartSec=10
Environment=SERVER_IP=${PUB_IP}
Environment=SERVER_REGION=${SERVER_REGION}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cayvpn

# ---------- Firewall Rules ----------
echo "🔥 Setting up firewall rules..."
iptables -C INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
iptables -C INPUT -i lo -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i lo -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -p tcp --dport ${ADGH_ADMIN_PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport ${ADGH_ADMIN_PORT} -j ACCEPT
iptables -C INPUT -p udp --dport 53 ! -i ${WG_IFACE} -j DROP 2>/dev/null || iptables -A INPUT -p udp --dport 53 ! -i ${WG_IFACE} -j DROP
iptables -C INPUT -p tcp --dport 53 ! -i ${WG_IFACE} -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 53 ! -i ${WG_IFACE} -j DROP
netfilter-persistent save

# ---------- Start CayVPN Service ----------
echo "🚀 Starting CayVPN service..."
systemctl start cayvpn

# Clean up
rm -rf "$tmpdir"

# ---------- Summary ----------
echo ""
echo "🎉 CayVPN Installation Complete!"
echo "================================="
echo "🌐 CayVPN Web Interface: http://${PUB_IP}:8888"
echo "🔐 Default Login: admin / ${ADMIN_PASS}"
echo "📊 AdGuard Home UI: http://${PUB_IP}:${ADGH_ADMIN_PORT}"
echo "🔑 AdGuard Admin: ${ADMIN_USER} / ${ADMIN_PASS}"
echo ""
echo "📡 WireGuard: ${WG_IFACE} UDP ${WG_PORT} (${WG_SUBNET_V4})"
echo "🛡️ DNS Server: ${WG_GW_IP}:53"
echo "📍 Server Region: ${SERVER_REGION}"
echo ""
echo "🔧 Services Status:"
echo "  - WireGuard: $(systemctl is-active wg-quick@${WG_IFACE})"
echo "  - AdGuard Home: $(systemctl is-active AdGuardHome)"
echo "  - CayVPN: $(systemctl is-active cayvpn)"
echo "  - Cloudflared: $(systemctl is-active cloudflared-dns)"
echo ""
echo "📝 Next Steps:"
echo "  1. Change the default password in the web interface"
echo "  2. Add WireGuard peers through the CayVPN dashboard"
echo "  3. Configure port forwarding for UDP ${WG_PORT}"
echo ""
echo "🛠️ Management Commands:"
echo "  sudo systemctl status cayvpn    # Check CayVPN status"
echo "  sudo systemctl restart cayvpn   # Restart CayVPN"
echo "  sudo systemctl stop cayvpn      # Stop CayVPN"
echo "  sudo systemctl start cayvpn     # Start CayVPN"