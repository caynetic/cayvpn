from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
import os, sqlite3, subprocess, qrcode, io, re, base64, tempfile, json, bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "ChangeThisNow_!#"  # 🔐 Change this in production

# WireGuard Configuration (can be overridden with environment variables)
# WG_INTERFACE=wg0                    # Interface name
# WG_PORT=43210                       # UDP port
# WG_SERVER_ADDRESS=10.8.0.1/24       # Server IP/mask
# WG_CLIENT_DNS=10.8.0.1              # DNS server for clients (AdGuard)
# WG_CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0  # IPs to route through VPN
# WG_PERSISTENT_KEEPALIVE=25          # Keepalive interval
# WG_POSTUP=""                        # PostUp command for iptables
# WG_POSTDOWN=""                      # PostDown command for iptables

DB_PATH = "wg.db"
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_DIR = "/etc/wireguard"
WG_CONF = os.path.join(WG_DIR, f"{WG_INTERFACE}.conf")
WG_PORT = int(os.environ.get("WG_PORT", "43210"))
WG_SERVER_ADDRESS = os.environ.get("WG_SERVER_ADDRESS", "10.8.0.1/24")
WG_CLIENT_DNS = os.environ.get("WG_CLIENT_DNS", "10.8.0.1")
WG_CLIENT_ALLOWED_IPS = os.environ.get("WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0")
WG_PERSISTENT_KEEPALIVE = os.environ.get("WG_PERSISTENT_KEEPALIVE", "25")
WG_CLIENT_ADDRESS_PREFIX = os.environ.get("WG_CLIENT_ADDRESS_PREFIX", "32")
WG_POSTUP = os.environ.get("WG_POSTUP", "")
WG_POSTDOWN = os.environ.get("WG_POSTDOWN", "")
SERVER_PRIV = os.path.join(WG_DIR, "server.key")
SERVER_PUB = os.path.join(WG_DIR, "server.pub")
ADGUARD_CONFIG = "/opt/AdGuardHome/AdGuardHome.yaml"

ADMIN_USER = "admin"
ADMIN_PASS = "password"  # 🔐 Change this too!

# Detect server IP and region
SERVER_IP = "Unknown"
SERVER_REGION = "Unknown"

def get_server_info():
    """Get server info from config file or detect automatically"""
    config_file = "/etc/wireguard/server_info.conf"
    
    # Try to read from config file first
    if os.path.exists(config_file):
        try:
            server_ip = None
            server_region = None
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('SERVER_IP='):
                        server_ip = line.split('=', 1)[1]
                    elif line.startswith('SERVER_REGION='):
                        server_region = line.split('=', 1)[1]
            
            return server_ip, server_region
        except Exception as e:
            print(f"⚠ Could not read server config file: {e}")
    
    # Fall back to automatic detection
    return None, None

def get_public_ip():
    """Try multiple services to get public IP"""
    services = [
        'https://api.ipify.org',
        'https://ipv4.icanhazip.com',
        'https://checkip.amazonaws.com',
        'https://ipinfo.io/ip'
    ]
    
    for service in services:
        try:
            result = subprocess.run(['curl', '-s', '--max-time', '5', service], capture_output=True, text=True)
            ip = result.stdout.strip()
            if ip and len(ip.split('.')) == 4:  # Basic IPv4 validation
                return ip
        except:
            continue
    return None

def fetch_location_details(ip_address: str) -> str:
    """Fetch location details for an IP address using multiple APIs"""
    if not ip_address or ip_address in ['127.0.0.1', 'localhost']:
        return "Local Network"
    
    apis = [
        {
            'url': f'https://ipapi.co/{ip_address}/json/',
            'fields': ['city', 'region', 'country_name'],
            'country_field': 'country_name'
        },
        {
            'url': f'https://ipinfo.io/{ip_address}/json',
            'fields': ['city', 'region', 'country'],
            'country_field': 'country'
        },
        {
            'url': f'http://ip-api.com/json/{ip_address}',
            'fields': ['city', 'regionName', 'country'],
            'country_field': 'country'
        }
    ]
    
    for api in apis:
        try:
            result = subprocess.run(['curl', '-s', '--max-time', '10', api['url']], 
                                  capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            if 'error' in data or data.get('status') == 'fail':
                continue
                
            location_parts = []
            for field in api['fields']:
                value = data.get(field)
                if value and value != 'Unknown':
                    location_parts.append(value)
            
            if location_parts:
                location = ', '.join(location_parts)
                print(f"✓ Detected location: {location}")
                return location
                
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            print(f"⚠ API {api['url']} failed: {e}")
            continue
    
    print("⚠ All location APIs failed, using default")
    return f"Server Location (IP: {ip_address})"

try:
    # Try to get server info from config file first
    config_ip, config_region = get_server_info()
    
    if config_ip:
        SERVER_IP = config_ip
        print(f"✓ Server IP loaded from config: {SERVER_IP}")
    else:
        SERVER_IP = get_public_ip()
        if not SERVER_IP:
            # Fallback to local IP detection
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            SERVER_IP = s.getsockname()[0]
            s.close()
            print(f"✓ Using local IP: {SERVER_IP}")
        else:
            print(f"✓ Detected Public IP: {SERVER_IP}")
    
    if config_region:
        SERVER_REGION = config_region
        print(f"✓ Server region loaded from config: {SERVER_REGION}")
    else:
        # Detect region if not in config
        SERVER_REGION = fetch_location_details(SERVER_IP)
        print(f"✓ Detected region: {SERVER_REGION}")
            
except Exception as e:
    print(f"✗ IP detection failed: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    SERVER_IP = "127.0.0.1"
    SERVER_REGION = "Localhost"

print(f"\n{'='*50}")
print(f"Server IP: {SERVER_IP}")
print(f"Region Info:\n{SERVER_REGION}")
print(f"{'='*50}\n")

# === Database Setup ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            public_key TEXT UNIQUE,
            ip TEXT
        )
    """)
    # Add privkey column if not exists
    try:
        cur.execute("ALTER TABLE peers ADD COLUMN privkey TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create settings table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    # Create dns_blocklists table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dns_blocklists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Set default settings if not exist
    default_settings = [
        ('server_region', SERVER_REGION),
        ('adguard_ip', '10.8.0.1'),
        ('adguard_port', '53')
    ]
    
    for key, value in default_settings:
        cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
    
    conn.commit()
    conn.close()

init_db()

# Generate server keys if not exist
if not os.path.exists(WG_DIR):
    os.makedirs(WG_DIR)
if not os.path.exists(SERVER_PRIV):
    server_priv = subprocess.getoutput("wg genkey")
    with open(SERVER_PRIV, "w") as f:
        f.write(server_priv)
if not os.path.exists(SERVER_PUB):
    server_priv = open(SERVER_PRIV).read().strip()
    server_pub = subprocess.getoutput(f"echo {server_priv} | wg pubkey")
    with open(SERVER_PUB, "w") as f:
        f.write(server_pub)

# === Auth decorator ===
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for("login"))
    return wrap

# === Helpers ===
def get_peers():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, public_key, privkey, ip FROM peers")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_next_ip():
    peers = get_peers()
    existing_ips = [int(ip.split('.')[-1]) for _, _, _, _, ip in peers if ip.startswith('10.8.0.')]
    if not existing_ips:
        return "10.8.0.2"
    next_num = max(existing_ips) + 1
    return f"10.8.0.{next_num}"

def get_setting(key, default=None):
    """Get a setting value from database"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else default

def set_setting(key, value):
    """Set a setting value in database"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def load_admin_password():
    """Load admin password from settings on startup"""
    global ADMIN_PASS
    stored_pass = get_setting('admin_password')
    if stored_pass:
        ADMIN_PASS = stored_pass
        print("✓ Admin password loaded from database")

# Load admin password from database if exists
load_admin_password()

def get_dns_blocklists():
    """Get all DNS blocklists"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, url, enabled FROM dns_blocklists ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_dns_blocklist(name, url):
    """Add a DNS blocklist"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO dns_blocklists (name, url) VALUES (?, ?)", (name, url))
    blocklist_id = cur.lastrowid
    conn.commit()
    conn.close()
    return blocklist_id

def remove_dns_blocklist(blocklist_id):
    """Remove a DNS blocklist"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM dns_blocklists WHERE id = ?", (blocklist_id,))
    conn.commit()
    conn.close()

def toggle_dns_blocklist(blocklist_id):
    """Toggle enabled/disabled status of a DNS blocklist"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE dns_blocklists SET enabled = NOT enabled WHERE id = ?", (blocklist_id,))
    conn.commit()
    conn.close()

def get_peer_stats():
    """Get peer statistics from WireGuard"""
    try:
        result = subprocess.run(["wg", "show", WG_INTERFACE, "dump"], 
                              capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')
        if not lines:
            return {}
        
        stats = {}
        for line in lines[1:]:  # Skip header
            parts = line.split('\t')
            if len(parts) >= 7:
                pubkey = parts[0]
                # wg show dump format:
                # 0:public_key 1:preshared_key 2:endpoint 3:allowed_ips 4:latest_handshake 5:transfer_rx 6:transfer_tx 7:persistent_keepalive
                handshake_time = parts[4]
                rx_bytes = parts[5]
                tx_bytes = parts[6]
                
                # Convert values, handling '(none)' and invalid formats
                try:
                    last_handshake = int(handshake_time) if handshake_time != '(none)' else 0
                except ValueError:
                    last_handshake = 0
                
                try:
                    rx = int(rx_bytes) if rx_bytes.isdigit() else 0
                except ValueError:
                    rx = 0
                
                try:
                    tx = int(tx_bytes) if tx_bytes.isdigit() else 0
                except ValueError:
                    tx = 0
                
                stats[pubkey] = {
                    'rx_bytes': rx,
                    'tx_bytes': tx,
                    'last_handshake': last_handshake
                }
        return stats
    except Exception as e:
        print(f"Error getting peer stats: {e}")
        return {}

def update_adguard_password(new_password):
    """Update AdGuard Home password using bcrypt"""
    try:
        # Generate bcrypt hash for AdGuard Home
        # AdGuard Home uses bcrypt hashes with $2a$ prefix
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Convert $2b$ to $2a$ for AdGuard compatibility
        password_hash = password_hash.replace('$2b$', '$2a$')
        
        # Read current AdGuard config
        if not os.path.exists(ADGUARD_CONFIG):
            print(f"⚠ AdGuard config not found at {ADGUARD_CONFIG}")
            return False
        
        # Use sed to replace the password hash in the config file
        # AdGuard config format: password: $2a$10$...
        subprocess.run([
            "sed", "-i.bak",
            f"s|password: \\$2[ay]\\$[^\"']*|password: {password_hash}|g",
            ADGUARD_CONFIG
        ], check=True)
        
        # Restart AdGuard Home
        subprocess.run(["systemctl", "restart", "AdGuardHome"], check=True)
        print("✓ AdGuard Home password updated")
        return True
            
    except subprocess.CalledProcessError as e:
        print(f"✗ Error updating AdGuard password: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error updating AdGuard password: {e}")
        return False

def update_admin_password(new_password):
    """Update admin panel password"""
    global ADMIN_PASS
    ADMIN_PASS = new_password
    
    # Store in settings database for persistence
    set_setting('admin_password', new_password)
    print("✓ Admin panel password updated")
    return True

def write_wg_conf():
    """Write WireGuard configuration file and apply changes instantly"""
    try:
        peers = get_peers()
        if not os.path.exists(SERVER_PUB):
            print(f"✗ Server public key not found at {SERVER_PUB}")
            return False
        
        with open(SERVER_PUB) as f:
            server_pub = f.read().strip()
        
        with open(SERVER_PRIV) as f:
            server_priv = f.read().strip()
        
        # Build config
        config_lines = [
            "[Interface]",
            f"PrivateKey = {server_priv}",
            f"Address = {WG_SERVER_ADDRESS}",
            f"ListenPort = {WG_PORT}",
            "SaveConfig = true",
        ]
        
        # Add PostUp/PostDown if configured
        if WG_POSTUP:
            config_lines.append(f"PostUp = {WG_POSTUP}")
        if WG_POSTDOWN:
            config_lines.append(f"PostDown = {WG_POSTDOWN}")
        
        config_lines.append("")
        
        for _, name, pubkey, _, ip in peers:
            peer_block = [
                "[Peer]",
                f"# {name}",
                f"PublicKey = {pubkey}",
                f"AllowedIPs = {ip}/{WG_CLIENT_ADDRESS_PREFIX}",
            ]
            if WG_PERSISTENT_KEEPALIVE:
                peer_block.append(f"PersistentKeepalive = {WG_PERSISTENT_KEEPALIVE}")
            peer_block.append("")
            config_lines.extend(peer_block)
        
        config_content = "\n".join(config_lines)
        
        # Write config file
        try:
            with open(WG_CONF, "w") as f:
                f.write(config_content)
            print(f"✓ WireGuard config written to {WG_CONF}")
        except PermissionError:
            print(f"⚠ Permission denied writing to {WG_CONF}, trying with sudo...")
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as tmp:
                tmp.write(config_content)
                tmp_path = tmp.name
            subprocess.run(["sudo", "cp", tmp_path, WG_CONF], check=True)
            subprocess.run(["sudo", "chmod", "600", WG_CONF], check=True)
            os.unlink(tmp_path)
            print(f"✓ WireGuard config written to {WG_CONF} (with sudo)")
        
        # Apply changes instantly using wg commands
        sync_success = apply_wg_changes(peers)
        
        if not sync_success:
            print("⚠ Instant sync failed, trying service restart...")
            try:
                subprocess.run(["systemctl", "restart", f"wg-quick@{WG_INTERFACE}"], 
                             check=True, timeout=10)
                print(f"✓ WireGuard service restarted")
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as svc_err:
                print(f"✗ Failed to restart wg-quick@{WG_INTERFACE}: {svc_err}")
                return False
        
        return sync_success
        
    except Exception as e:
        print(f"✗ Error writing WireGuard config: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def apply_wg_changes(peers):
    """Apply WireGuard configuration changes instantly using wg commands"""
    try:
        # Get current peers from running interface
        try:
            current_output = subprocess.run(["wg", "show", WG_INTERFACE, "peers"], 
                                          capture_output=True, text=True, check=True)
            current_peers = set(current_output.stdout.strip().split('\n')) if current_output.stdout.strip() else set()
        except subprocess.CalledProcessError:
            print(f"⚠ Could not get current peers for {WG_INTERFACE}")
            current_peers = set()
        
        # Expected peers from our config
        expected_peers = set(pubkey for _, _, pubkey, _, _ in peers)
        
        # Remove peers that shouldn't be there
        to_remove = current_peers - expected_peers
        for pubkey in to_remove:
            try:
                subprocess.run(["wg", "set", WG_INTERFACE, "peer", pubkey, "remove"], 
                             check=True, timeout=5)
                print(f"✓ Removed peer {pubkey[:8]}...")
            except subprocess.CalledProcessError as e:
                print(f"⚠ Failed to remove peer {pubkey[:8]}: {e}")
        
        # Add or update peers
        for _, name, pubkey, privkey, ip in peers:
            try:
                # Check if peer exists
                peer_exists = pubkey in current_peers
                
                if peer_exists:
                    # Update existing peer
                    subprocess.run([
                        "wg", "set", WG_INTERFACE, 
                        "peer", pubkey, 
                        "allowed-ips", f"{ip}/{WG_CLIENT_ADDRESS_PREFIX}",
                        "persistent-keepalive", WG_PERSISTENT_KEEPALIVE if WG_PERSISTENT_KEEPALIVE else "0"
                    ], check=True, timeout=5)
                    print(f"✓ Updated peer {name}")
                else:
                    # Add new peer
                    cmd = [
                        "wg", "set", WG_INTERFACE, 
                        "peer", pubkey, 
                        "allowed-ips", f"{ip}/{WG_CLIENT_ADDRESS_PREFIX}"
                    ]
                    if WG_PERSISTENT_KEEPALIVE:
                        cmd.extend(["persistent-keepalive", WG_PERSISTENT_KEEPALIVE])
                    subprocess.run(cmd, check=True, timeout=5)
                    print(f"✓ Added peer {name}")
                    
            except subprocess.CalledProcessError as e:
                print(f"⚠ Failed to configure peer {name}: {e}")
                return False
        
        # Save the configuration
        try:
            subprocess.run(["wg-quick", "save", WG_INTERFACE], 
                         check=True, timeout=5, capture_output=True)
            print(f"✓ Configuration saved to {WG_CONF}")
        except subprocess.CalledProcessError as e:
            print(f"⚠ Failed to save config: {e}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error applying WireGuard changes: {type(e).__name__}: {e}")
        return False

def import_from_config():
    """Import peers from existing WireGuard config if database is empty"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM peers")
    count = cur.fetchone()[0]
    if count > 0 or not os.path.exists(WG_CONF):
        conn.close()
        return

    with open(WG_CONF) as f:
        content = f.read()
    peers = re.findall(r"\[Peer\]\n# (.*?)\nPublicKey = (.*?)\nAllowedIPs = ([0-9\.]+)/(\d+)", content)
    for name, pubkey, ip, _ in peers:
        cur.execute("INSERT OR IGNORE INTO peers (name, public_key, ip) VALUES (?, ?, ?)", (name, pubkey, ip))
    conn.commit()
    conn.close()

import_from_config()

# Add mock data if database is empty
# def add_mock_data():
#     conn = sqlite3.connect(DB_PATH)
#     cur = conn.cursor()
#     cur.execute("SELECT COUNT(*) FROM peers")
#     count = cur.fetchone()[0]
#     if count == 0:
#         # Mock peers with generated keys (replace with real wg genkey outputs)
#         mock_peers = [
#             ("Alice", "WG1PublicKeyHere", "WG1PrivateKeyHere", "10.8.0.2"),
#             ("Bob", "WG2PublicKeyHere", "WG2PrivateKeyHere", "10.8.0.3"),
#             ("Charlie", "WG3PublicKeyHere", "WG3PrivateKeyHere", "10.8.0.4"),
#         ]
#         for name, pub, priv, ip in mock_peers:
#             cur.execute("INSERT INTO peers (name, public_key, privkey, ip) VALUES (?, ?, ?, ?)", (name, pub, priv, ip))
#         conn.commit()
#     conn.close()

# add_mock_data()

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "update_settings":
            # Update settings
            server_region = request.form.get("server_region", "").strip()
            
            if server_region:
                set_setting('server_region', server_region)
            
            flash("Settings updated successfully!", "success")
            return redirect(url_for("settings"))
        
        elif action == "change_password":
            # Change admin password
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            
            # Validate current password
            if current_password != ADMIN_PASS:
                flash("Current password is incorrect!", "error")
                return redirect(url_for("settings"))
            
            # Validate new password
            if len(new_password) < 8:
                flash("New password must be at least 8 characters!", "error")
                return redirect(url_for("settings"))
            
            if new_password != confirm_password:
                flash("New passwords do not match!", "error")
                return redirect(url_for("settings"))
            
            # Update both admin panel and AdGuard Home passwords
            admin_success = update_admin_password(new_password)
            adguard_success = update_adguard_password(new_password)
            
            if admin_success and adguard_success:
                flash("Password updated successfully for both Admin Panel and AdGuard Home!", "success")
            elif admin_success:
                flash("Admin Panel password updated. AdGuard Home update failed - please update manually.", "warning")
            else:
                flash("Password update failed!", "error")
            
            return redirect(url_for("settings"))
        
        elif action == "detect_region":
            # Auto-detect region
            try:
                current_ip = get_public_ip()
                if current_ip:
                    detected_region = fetch_location_details(current_ip)
                    set_setting('server_region', detected_region)
                    flash(f"Region auto-detected: {detected_region}", "success")
                else:
                    flash("Could not detect public IP for region detection", "warning")
            except Exception as e:
                flash(f"Region detection failed: {str(e)}", "error")
            
            return redirect(url_for("settings"))
    
    # Get current settings
    server_region = get_setting('server_region', SERVER_REGION)
    
    return render_template("settings.html", 
                         server_region=server_region,
                         server_ip=SERVER_IP)

@app.route("/dns", methods=["GET", "POST"])
@login_required
def dns_management():
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add":
            name = request.form.get("name", "").strip()
            url = request.form.get("url", "").strip()
            if name and url:
                add_dns_blocklist(name, url)
                flash(f"DNS blocklist '{name}' added successfully!", "success")
        
        elif action == "remove":
            blocklist_id = request.form.get("blocklist_id")
            if blocklist_id:
                remove_dns_blocklist(int(blocklist_id))
                flash("DNS blocklist removed successfully!", "success")
        
        elif action == "toggle":
            blocklist_id = request.form.get("blocklist_id")
            if blocklist_id:
                toggle_dns_blocklist(int(blocklist_id))
                flash("DNS blocklist status updated!", "success")
        
        return redirect(url_for("dns_management"))
    
    blocklists = get_dns_blocklists()
    return render_template("dns.html", blocklists=blocklists)

# === Routes ===
@app.route("/login", methods=["GET", "POST"])
def login():
    if "logged_in" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USER and password == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    peers = get_peers()
    peer_stats = get_peer_stats()
    server_region = get_setting('server_region', SERVER_REGION)
    
    # Add stats to peers
    peers_with_stats = []
    for peer in peers:
        peer_id, name, pubkey, privkey, ip = peer
        stats = peer_stats.get(pubkey, {'rx_bytes': 0, 'tx_bytes': 0, 'last_handshake': 0})
        peers_with_stats.append((peer_id, name, pubkey, privkey, ip, stats))
    
    return render_template("index.html", 
                         peers=peers_with_stats, 
                         server_ip=SERVER_IP, 
                         server_region=server_region)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_peer():
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            if not name:
                return render_template("add_peer.html", error="Peer name is required")
            
            ip = get_next_ip()
            print(f"Adding new peer '{name}' with IP {ip}")
            
            # Generate keys
            priv_key = subprocess.getoutput("wg genkey")
            pub_key = subprocess.getoutput(f"echo '{priv_key}' | wg pubkey")
            
            print(f"Generated keys for {name}")

            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO peers (name, public_key, privkey, ip) VALUES (?, ?, ?, ?)", 
                       (name, pub_key, priv_key, ip))
            conn.commit()
            peer_id = cur.lastrowid
            conn.close()
            
            print(f"✓ Peer '{name}' added to database (ID: {peer_id})")

            if write_wg_conf():
                print(f"✓ WireGuard config updated successfully")
                flash(f"Peer '{name}' added successfully!", "success")
                return redirect(url_for("index"))
            else:
                # Config update failed, remove the peer from DB
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.execute("DELETE FROM peers WHERE id=?", (peer_id,))
                conn.commit()
                conn.close()
                print(f"✗ Config update failed, removed peer from database")
                flash("Failed to update WireGuard configuration", "error")
                return redirect(url_for("index"))
        except Exception as e:
            print(f"✗ Error adding peer: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return render_template("add_peer.html", error=f"Failed to add peer: {str(e)}")
    
    return render_template("add_peer.html")

@app.route("/remove/<int:peer_id>")
@login_required
def remove_peer(peer_id):
    try:
        # Get peer info before deletion
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT name FROM peers WHERE id=?", (peer_id,))
        peer = cur.fetchone()
        peer_name = peer[0] if peer else "Unknown"
        
        # Remove from database
        cur.execute("DELETE FROM peers WHERE id=?", (peer_id,))
        conn.commit()
        conn.close()
        
        print(f"✓ Peer '{peer_name}' removed from database")
        
        # Apply WireGuard changes instantly
        if write_wg_conf():
            print(f"✓ WireGuard config updated - peer '{peer_name}' removed")
            flash(f"Peer '{peer_name}' removed successfully!", "success")
        else:
            print(f"⚠ WireGuard config update failed for peer removal")
            flash(f"Peer '{peer_name}' removed from database but WireGuard update failed", "warning")
        
        return redirect(url_for("index"))
    except Exception as e:
        print(f"✗ Error removing peer: {type(e).__name__}: {e}")
        return redirect(url_for("index"))

@app.route("/config/<int:peer_id>")
@login_required
def download_config(peer_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name, public_key, privkey, ip FROM peers WHERE id=?", (peer_id,))
    peer = cur.fetchone()
    conn.close()

    if not peer:
        return "Peer not found", 404

    name, pubkey, privkey, ip = peer
    server_pub = open(SERVER_PUB).read().strip()
    config_lines = [
        "[Interface]",
        f"PrivateKey = {privkey}",
        f"Address = {ip}/{WG_CLIENT_ADDRESS_PREFIX}",
    ]

    # Always include DNS since it's always enabled
    if WG_CLIENT_DNS:
        config_lines.append(f"DNS = {WG_CLIENT_DNS}")

    config_lines.append("")
    config_lines.extend([
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"Endpoint = {SERVER_IP}:{WG_PORT}",
        f"AllowedIPs = {WG_CLIENT_ALLOWED_IPS}",
    ])

    if WG_PERSISTENT_KEEPALIVE:
        config_lines.append(f"PersistentKeepalive = {WG_PERSISTENT_KEEPALIVE}")

    config_lines.append("")
    config = "\n".join(config_lines)
    buf = io.BytesIO()
    buf.write(config.encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"{name}.conf")

@app.route("/qr/<int:peer_id>")
@login_required
def show_qr(peer_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name, public_key, privkey, ip FROM peers WHERE id=?", (peer_id,))
    peer = cur.fetchone()
    conn.close()

    if not peer:
        return "Peer not found", 404

    name, pubkey, privkey, ip = peer
    server_pub = open(SERVER_PUB).read().strip()
    qr_lines = [
        "[Interface]",
        f"PrivateKey = {privkey}",
        f"Address = {ip}/{WG_CLIENT_ADDRESS_PREFIX}",
    ]

    # Always include DNS since it's always enabled
    if WG_CLIENT_DNS:
        qr_lines.append(f"DNS = {WG_CLIENT_DNS}")

    qr_lines.append("")
    qr_lines.extend([
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"Endpoint = {SERVER_IP}:{WG_PORT}",
        f"AllowedIPs = {WG_CLIENT_ALLOWED_IPS}",
    ])

    if WG_PERSISTENT_KEEPALIVE:
        qr_lines.append(f"PersistentKeepalive = {WG_PERSISTENT_KEEPALIVE}")

    qr_lines.append("")
    qr_text = "\n".join(qr_lines)
    qr = qrcode.make(qr_text)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    qr_b64 = base64.b64encode(img_io.getvalue()).decode()
    return render_template("qr.html", qr_b64=qr_b64, name=name)

@app.route("/server")
@login_required
def server():
    # Get WG status
    try:
        wg_status = subprocess.getoutput(f"wg show {WG_INTERFACE}")
        if not wg_status.strip():
            wg_status = f"Interface {WG_INTERFACE} appears to be down or not configured"
    except:
        wg_status = f"Error: WireGuard not available or {WG_INTERFACE} not up"
    
    # Get interface info
    try:
        ip_info = subprocess.getoutput(f"ip addr show {WG_INTERFACE}")
    except:
        ip_info = f"Could not get IP info for {WG_INTERFACE}"
    
    # Get AdGuard status
    try:
        adg_status = subprocess.getoutput("systemctl status AdGuardHome --no-pager -l")
    except:
        adg_status = "Error: AdGuard Home not installed or service not found"
    
    # Get current config
    try:
        with open(WG_CONF, 'r') as f:
            wg_config = f.read()
    except:
        wg_config = f"Could not read config file {WG_CONF}"
    
    return render_template("server.html", 
                         wg_status=wg_status, 
                         adg_status=adg_status, 
                         wg_interface=WG_INTERFACE, 
                         wg_port=WG_PORT,
                         ip_info=ip_info,
                         wg_config=wg_config)

@app.route("/restart_wg", methods=["POST"])
@login_required
def restart_wg():
    try:
        subprocess.run(["systemctl", "restart", f"wg-quick@{WG_INTERFACE}"], check=True)
    except:
        pass  # Ignore errors for now
    return redirect(url_for("server"))

@app.route("/restart_adg", methods=["POST"])
@login_required
def restart_adg():
    try:
        subprocess.run(["systemctl", "restart", "AdGuardHome"], check=True)
    except:
        pass
    return redirect(url_for("server"))

@app.route("/start_adg", methods=["POST"])
@login_required
def start_adg():
    try:
        subprocess.run(["systemctl", "start", "AdGuardHome"], check=True)
    except:
        pass
    return redirect(url_for("server"))

@app.route("/test_dns")
@login_required
def test_dns():
    """Test DNS connectivity to AdGuard"""
    results = {}
    
    try:
        # Test local DNS
        result = subprocess.run(["dig", "@10.8.0.1", "google.com", "+short"], 
                              capture_output=True, text=True, timeout=5)
        results['local_dns'] = {
            'success': result.returncode == 0,
            'output': result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        }
    except Exception as e:
        results['local_dns'] = {'success': False, 'output': str(e)}
    
    try:
        # Test if AdGuard is listening
        result = subprocess.run(["ss", "-tuln", "|", "grep", ":53"], 
                              shell=True, capture_output=True, text=True, timeout=5)
        results['dns_ports'] = {
            'success': result.returncode == 0 and '10.8.0.1:53' in result.stdout,
            'output': result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        }
    except Exception as e:
        results['dns_ports'] = {'success': False, 'output': str(e)}
    
    try:
        # Test AdGuard Home service status
        result = subprocess.run(["systemctl", "is-active", "AdGuardHome"], 
                              capture_output=True, text=True, timeout=5)
        results['adguard_status'] = {
            'success': result.returncode == 0 and result.stdout.strip() == 'active',
            'output': result.stdout.strip()
        }
    except Exception as e:
        results['adguard_status'] = {'success': False, 'output': str(e)}
    
    try:
        # Test external DNS resolution
        result = subprocess.run(["dig", "google.com", "+short"], 
                              capture_output=True, text=True, timeout=5)
        results['external_dns'] = {
            'success': result.returncode == 0 and result.stdout.strip(),
            'output': result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        }
    except Exception as e:
        results['external_dns'] = {'success': False, 'output': str(e)}
    
    return render_template("test_dns.html", results=results)

@app.route("/api/peer_stats")
@login_required
def api_peer_stats():
    """API endpoint to get peer statistics as JSON"""
    peers = get_peers()
    peer_stats = get_peer_stats()
    
    # Build stats data
    stats_data = []
    for peer in peers:
        peer_id, name, pubkey, privkey, ip = peer
        stats = peer_stats.get(pubkey, {'rx_bytes': 0, 'tx_bytes': 0, 'last_handshake': 0})
        
        # Format data usage
        rx_mb = round(stats['rx_bytes'] / 1024 / 1024, 2) if stats['rx_bytes'] else 0
        tx_mb = round(stats['tx_bytes'] / 1024 / 1024, 2) if stats['tx_bytes'] else 0
        
        # Format last seen
        last_seen = "Never"
        if stats['last_handshake'] and stats['last_handshake'] > 0:
            seconds_ago = stats['last_handshake']
            if seconds_ago < 60:
                last_seen = f"{seconds_ago}s ago"
            elif seconds_ago < 3600:
                last_seen = f"{round(seconds_ago / 60)}m ago"
            elif seconds_ago < 86400:
                last_seen = f"{round(seconds_ago / 3600)}h ago"
            else:
                last_seen = f"{round(seconds_ago / 86400)}d ago"
        
        stats_data.append({
            'id': peer_id,
            'name': name,
            'ip': ip,
            'rx_bytes': rx_mb,
            'tx_bytes': tx_mb,
            'last_seen': last_seen
        })
    
    return jsonify(stats_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)