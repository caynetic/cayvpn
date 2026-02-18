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

# HTTPS Configuration
ENABLE_HTTPS="${ENABLE_HTTPS:-1}"
SSL_CERT_PATH="${SSL_CERT_PATH:-/etc/ssl/certs/cayvpn.crt}"
SSL_KEY_PATH="${SSL_KEY_PATH:-/etc/ssl/private/cayvpn.key}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
ENABLE_LOCAL_SYSTEM_DNS="${ENABLE_LOCAL_SYSTEM_DNS:-0}"

OUT_IFACE="${OUT_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)}"
if [[ -z "${OUT_IFACE}" ]]; then echo "Could not auto-detect OUT_IFACE"; exit 1; fi

export DEBIAN_FRONTEND=noninteractive

# ---------- DNS Helpers ----------
write_local_resolv_conf() {
    rm -f /etc/resolv.conf
    cat >/etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
options edns0 timeout:2 attempts:2
EOF
}

validate_dns_resolution() {
    getent hosts github.com >/dev/null 2>&1 || getent hosts cloudflare.com >/dev/null 2>&1
}

configure_system_resolver() {
    if [[ "${ENABLE_LOCAL_SYSTEM_DNS}" != "1" ]]; then
        echo "ℹ️ Leaving server resolver unchanged (set ENABLE_LOCAL_SYSTEM_DNS=1 to point host DNS to AdGuard)"
        return
    fi

    local resolv_backup
    resolv_backup="$(mktemp)"
    cp -L /etc/resolv.conf "${resolv_backup}" 2>/dev/null || true

    write_local_resolv_conf
    if validate_dns_resolution; then
        echo "✓ Local DNS resolver is healthy"
    else
        echo "⚠️ Local DNS validation failed; restoring previous resolver settings"
        if [[ -s "${resolv_backup}" ]]; then
            cat "${resolv_backup}" >/etc/resolv.conf
        fi
    fi

    rm -f "${resolv_backup}"
}

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
            # Initialize variables to prevent "unbound variable" errors
            local city="" region="" country=""
            
            # Parse JSON response
            if echo "$response" | jq -e '.city' >/dev/null 2>&1; then
                # ipapi.co format
                city=$(echo "$response" | jq -r '.city // empty' 2>/dev/null || echo "")
                region=$(echo "$response" | jq -r '.region // empty' 2>/dev/null || echo "")
                country=$(echo "$response" | jq -r '.country_name // empty' 2>/dev/null || echo "")
            elif echo "$response" | jq -e '.region' >/dev/null 2>&1; then
                # ipinfo.io format
                city=$(echo "$response" | jq -r '.city // empty' 2>/dev/null || echo "")
                region=$(echo "$response" | jq -r '.region // empty' 2>/dev/null || echo "")
                country=$(echo "$response" | jq -r '.country // empty' 2>/dev/null || echo "")
            elif echo "$response" | jq -e '.regionName' >/dev/null 2>&1; then
                # ip-api.com format
                city=$(echo "$response" | jq -r '.city // empty' 2>/dev/null || echo "")
                region=$(echo "$response" | jq -r '.regionName // empty' 2>/dev/null || echo "")
                country=$(echo "$response" | jq -r '.country // empty' 2>/dev/null || echo "")
            fi
            
            local location_parts=()
            [[ -n "$city" && "$city" != "null" && "$city" != "" ]] && location_parts+=("$city")
            [[ -n "$region" && "$region" != "null" && "$region" != "" ]] && location_parts+=("$region")
            [[ -n "$country" && "$country" != "null" && "$country" != "" ]] && location_parts+=("$country")
            
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

# ---------- WireGuard ----------
echo "🔐 Setting up WireGuard..."
umask 077
mkdir -p /etc/wireguard
if [[ ! -f /etc/wireguard/server.key ]]; then
  wg genkey | tee /etc/wireguard/server.key >/dev/null
  cat /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
fi

# Preserve existing peers if config exists
PRESERVED_PEERS=""
if [[ -f /etc/wireguard/${WG_IFACE}.conf ]]; then
    echo "🔄 Preserving existing WireGuard peers..."
    # Extract all content from the first [Peer] section onwards
    PRESERVED_PEERS=$(sed -n '/^\[Peer\]/,$p' /etc/wireguard/${WG_IFACE}.conf)
fi

cat >/etc/wireguard/${WG_IFACE}.conf <<EOF
[Interface]
Address = ${WG_SUBNET_V4}
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/server.key)
SaveConfig = true
EOF

# Append preserved peers if any
if [[ -n "$PRESERVED_PEERS" ]]; then
    echo "" >> /etc/wireguard/${WG_IFACE}.conf
    echo "$PRESERVED_PEERS" >> /etc/wireguard/${WG_IFACE}.conf
    echo "✓ Preserved $(echo "$PRESERVED_PEERS" | grep -c "\[Peer\]") peer(s)"
fi

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

# ---------- AdGuard Home ----------
echo "🛡️ Installing AdGuard Home..."
tmpdir="$(mktemp -d)"
pushd "$tmpdir" >/dev/null
DL_URL="$(curl -s https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | jq -r '.assets[] | select(.name | test("AdGuardHome_linux_amd64\\.tar\\.gz$")) .browser_download_url')"
wget -q "$DL_URL" -O adguard.tar.gz
tar -xzf adguard.tar.gz
systemctl stop AdGuardHome >/dev/null 2>&1 || true
pkill -f '/opt/AdGuardHome/AdGuardHome' >/dev/null 2>&1 || true
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
ADGUARD_TLS_CONFIG=""
if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    ADGUARD_TLS_CONFIG="
tls:
  enabled: true
  server_name: ${PUB_IP}
  force_https: true
  port_https: 8444
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: \"\"
  allow_unencrypted_doh: false
  certificate_chain: \"\"
  private_key: \"\"
  certificate_path: ${SSL_CERT_PATH}
  private_key_path: ${SSL_KEY_PATH}
  strict_sni_check: false"
fi

cat >/opt/AdGuardHome/AdGuardHome.yaml <<EOF
bind_host: 0.0.0.0
bind_port: ${ADGH_ADMIN_PORT}
${ADGUARD_TLS_CONFIG}
users:
  - name: ${ADMIN_USER}
    password: ${BCRYPT_HASH}
dns:
  bind_hosts:
    - 127.0.0.1
    - ${WG_GW_IP}
  port: 53
  upstream_dns:
    - https://1.1.1.1/dns-query
    - https://1.0.0.1/dns-query
    - https://dns.google/dns-query
  bootstrap_dns:
    - 1.1.1.1
    - 1.0.0.1
    - 8.8.8.8
  filtering_enabled: true
  cache_size: 2097152
filters_update_interval: 24
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
  - enabled: true
    url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    name: StevenBlack Hosts
  - enabled: false
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

configure_system_resolver

# ---------- CayVPN Flask App Setup ----------
echo "🐍 Setting up CayVPN Flask application..."

# Clone/update repository (assuming we're running from within it)
if [[ ! -d ".git" ]]; then
    echo "❌ Please run this script from within the cloned CayVPN repository"
    exit 1
fi

# Backup existing settings if DB exists
if [[ -f "wg.db" ]]; then
    echo "💾 Backing up existing settings..."
    sqlite3 wg.db "SELECT 'INSERT OR IGNORE INTO settings (key, value) VALUES (''' || key || ''', ''' || value || ''');' FROM settings;" > settings_backup.sql
fi

# Update repository
if ! git pull origin main; then
    echo "⚠️ Unable to pull latest changes from origin/main; continuing with current checkout"
fi

# Set up Python virtual environment
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create sessions directory for secure session storage
mkdir -p sessions
chmod 700 sessions

# Create systemd service for CayVPN
if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    EXEC_START="$(pwd)/venv/bin/gunicorn --workers 1 --bind 0.0.0.0:${HTTPS_PORT} --certfile ${SSL_CERT_PATH} --keyfile ${SSL_KEY_PATH} app:app"
else
    EXEC_START="$(pwd)/venv/bin/gunicorn --workers 1 --bind 0.0.0.0:8888 app:app"
fi

cat >/etc/systemd/system/cayvpn.service <<EOF
[Unit]
Description=CayVPN Management Interface
After=network.target AdGuardHome.service wg-quick@${WG_IFACE}.service
Wants=AdGuardHome.service wg-quick@${WG_IFACE}.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=${EXEC_START}
Restart=always
RestartSec=10
Environment=SERVER_IP=${PUB_IP}
Environment=SERVER_REGION=${SERVER_REGION}
Environment=ENABLE_HTTPS=${ENABLE_HTTPS}
Environment=SSL_CERT_PATH=${SSL_CERT_PATH}
Environment=SSL_KEY_PATH=${SSL_KEY_PATH}
Environment=HTTPS_PORT=${HTTPS_PORT}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cayvpn

# ---------- Firewall Rules ----------
echo "🔥 Setting up firewall rules..."
iptables -C INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport ${WG_PORT} -j ACCEPT
iptables -C INPUT -i lo -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i lo -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -p tcp --dport ${ADGH_ADMIN_PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport ${ADGH_ADMIN_PORT} -j ACCEPT
if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    iptables -C INPUT -p tcp --dport 8444 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 8444 -j ACCEPT
fi
iptables -C INPUT -p udp --dport 53 ! -i ${WG_IFACE} -j DROP 2>/dev/null || iptables -A INPUT -p udp --dport 53 ! -i ${WG_IFACE} -j DROP
iptables -C INPUT -p tcp --dport 53 ! -i ${WG_IFACE} -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 53 ! -i ${WG_IFACE} -j DROP
netfilter-persistent save

# ---------- HTTPS Setup ----------
if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    echo "🔒 Setting up HTTPS with self-signed certificate..."
    
    # Install OpenSSL if not present
    if ! command -v openssl &> /dev/null; then
        echo "Installing OpenSSL..."
        apt update && apt install -y openssl
    fi
    
    # Create SSL directory if it doesn't exist
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
    # Generate self-signed certificate with SANs
    if [[ ! -f "${SSL_CERT_PATH}" ]] || [[ ! -f "${SSL_KEY_PATH}" ]]; then
        echo "Generating self-signed SSL certificate with SANs..."
        
        # Create OpenSSL config for SANs
        cat > /etc/ssl/openssl-san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = CayVPN
CN = ${PUB_IP}

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = ${PUB_IP}
EOF
        
        openssl req -x509 -newkey rsa:4096 \
            -keyout "${SSL_KEY_PATH}" \
            -out "${SSL_CERT_PATH}" \
            -days 365 \
            -nodes \
            -config /etc/ssl/openssl-san.cnf \
            -extensions v3_req
        
        # Set proper permissions
        chmod 600 "${SSL_KEY_PATH}"
        chmod 644 "${SSL_CERT_PATH}"
        
        echo "✓ SSL certificate with SANs generated"
        echo "  Certificate: ${SSL_CERT_PATH}"
        echo "  Private Key: ${SSL_KEY_PATH}"
    else
        echo "✓ SSL certificate already exists"
    fi
    
    # Add HTTPS port to firewall
    iptables -C INPUT -p tcp --dport ${HTTPS_PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport ${HTTPS_PORT} -j ACCEPT
    netfilter-persistent save
    
    echo "✓ HTTPS configured on port ${HTTPS_PORT}"
else
    echo "⚠ HTTPS disabled (set ENABLE_HTTPS=1 to enable)"
fi

# ---------- Start CayVPN Service ----------
echo "🚀 Starting CayVPN service..."
systemctl start cayvpn

# Restore settings if backup exists
if [[ -f "settings_backup.sql" ]]; then
    echo "🔄 Restoring settings..."
    sleep 5  # Wait for DB to be created
    sqlite3 wg.db < settings_backup.sql
    rm settings_backup.sql
    echo "✓ Settings restored"
fi

# Clean up
rm -rf "$tmpdir"

# ---------- Summary ----------
echo ""
echo "🎉 CayVPN Installation Complete!"
echo "================================="

if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    echo "🔒 CayVPN Web Interface: https://${PUB_IP}:${HTTPS_PORT}"
    echo "🔓 HTTP Fallback: http://${PUB_IP}:8888 (only if enabled)"
else
    echo "🌐 CayVPN Web Interface: http://${PUB_IP}:8888 (only if enabled)"
fi

echo "🔐 Initial Setup: Visit the web interface to set your admin password"
echo ""
echo "📡 WireGuard: ${WG_IFACE} UDP ${WG_PORT} (${WG_SUBNET_V4})"
echo "🛡️ DNS Server: ${WG_GW_IP}:53"
echo "📍 Server Region: ${SERVER_REGION}"

if [[ -n "$PRESERVED_PEERS" ]]; then
    echo ""
    echo "⚠️  NOTICE: Existing WireGuard peers were preserved in the config."
    echo "   To manage them via the web interface, you may need to re-add them manually"
    echo "   or run the app to sync the database."
fi

echo ""
echo "🔧 Services Status:"
echo "  - WireGuard: $(systemctl is-active wg-quick@${WG_IFACE})"
echo "  - AdGuard Home: $(systemctl is-active AdGuardHome)"
if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    echo "    - AdGuard HTTPS: https://${PUB_IP}:8444"
    echo "    - AdGuard HTTP: http://${PUB_IP}:${ADGH_ADMIN_PORT}"
else
    echo "    - AdGuard HTTP: http://${PUB_IP}:${ADGH_ADMIN_PORT}"
fi
echo "  - CayVPN: $(systemctl is-active cayvpn)"
echo ""
echo "📝 Next Steps:"
echo "  1. Visit the web interface and set your initial admin password"

if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    echo "  2. Accept the self-signed certificate warning in your browser"
    echo "  3. Consider getting a proper certificate from Let's Encrypt"
else
    echo "  2. Consider enabling HTTPS for better security"
fi

echo "  4. Add WireGuard peers through the CayVPN dashboard"
echo "  5. Configure port forwarding for UDP ${WG_PORT}"
echo ""
echo "🛠️ Management Commands:"
echo "  sudo systemctl status cayvpn    # Check CayVPN status"
echo "  sudo systemctl restart cayvpn   # Restart CayVPN"
echo "  sudo systemctl stop cayvpn      # Stop CayVPN"
echo "  sudo systemctl start cayvpn     # Start CayVPN"
