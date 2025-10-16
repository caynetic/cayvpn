from flask import Flask, render_template, request, redirect, url_for, session, send_file
import os, sqlite3, subprocess, qrcode, io, re, base64
from functools import wraps

app = Flask(__name__)
app.secret_key = "ChangeThisNow_!#"  # 🔐 Change this in production

DB_PATH = "wg.db"
WG_DIR = "/etc/wireguard"
WG_CONF = os.path.join(WG_DIR, "wg0.conf")
SERVER_PRIV = os.path.join(WG_DIR, "server.key")
SERVER_PUB = os.path.join(WG_DIR, "server.pub")

ADMIN_USER = "admin"
ADMIN_PASS = "password"  # 🔐 Change this too!

# Detect server IP and region
SERVER_IP = "Unknown"
SERVER_REGION = "Unknown"

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
    """Detect location using multiple free APIs"""
    services = [
        {
            "name": "ip-api.com",
            "url": f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as",
            "parser": "ip_api"
        },
        {
            "name": "ipwho.is",
            "url": f"https://ipwho.is/{ip_address}",
            "parser": "ipwho"
        },
        {
            "name": "geojs.io",
            "url": f"https://get.geojs.io/v1/ip/geo/{ip_address}.json",
            "parser": "geojs"
        },
        {
            "name": "ipinfo.io",
            "url": f"https://ipinfo.io/{ip_address}/json",
            "parser": "ipinfo"
        }
    ]

    for service in services:
        name = service["name"]
        url = service["url"]
        parser = service["parser"]
        print(f"[Location] Trying {name} ...")

        try:
            cmd = ['curl', '-s', '--max-time', '8', url]
            result = subprocess.run(cmd, capture_output=True, text=True)
            payload = result.stdout.strip()

            if not payload or len(payload) < 3:
                print(f"[Location] {name} returned empty response")
                continue

            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                print(f"[Location] {name} response not JSON")
                continue

            details = []

            if parser == "ip_api":
                if data.get("status") == "success":
                    if data.get("as"):
                        as_value = data["as"]
                        if as_value.startswith("AS"):
                            as_parts = as_value.split(' ', 1)
                            if len(as_parts) == 2:
                                details.append(f"ASN: {as_parts[0].replace('AS', '')}")
                                details.append(f"ISP: {as_parts[1]}")
                        else:
                            details.append(f"ISP: {as_value}")
                    if data.get("isp") and not any(row.startswith("ISP:") for row in details):
                        details.append(f"ISP: {data['isp']}")
                    if data.get("city"):
                        details.append(f"City: {data['city']}")
                    if data.get("regionName"):
                        details.append(f"State/Region: {data['regionName']}")
                    if data.get("country"):
                        details.append(f"Country: {data['country']}")
                    if data.get("lat") and data.get("lon"):
                        details.append(f"Coordinates: {data['lat']}, {data['lon']}")
                else:
                    print(f"[Location] {name} error: {data.get('message', 'Unknown error')}")

            elif parser == "ipwho":
                if data.get("success") is True:
                    if data.get("connection", {}).get("asn"):
                        details.append(f"ASN: {data['connection']['asn']}")
                    if data.get("connection", {}).get("org"):
                        details.append(f"ISP: {data['connection']['org']}")
                    if data.get("city"):
                        details.append(f"City: {data['city']}")
                    if data.get("region"):
                        details.append(f"State/Region: {data['region']}")
                    if data.get("country"):
                        details.append(f"Country: {data['country']}")
                    if data.get("latitude") and data.get("longitude"):
                        details.append(f"Coordinates: {data['latitude']}, {data['longitude']}")
                else:
                    print(f"[Location] {name} error: {data.get('message', 'Unknown error')}")

            elif parser == "geojs":
                if data.get("latitude") and data.get("longitude"):
                    if data.get("asn"):
                        details.append(f"ASN: {data['asn']}")
                    if data.get("organization"):
                        details.append(f"ISP: {data['organization']}")
                    if data.get("city"):
                        details.append(f"City: {data['city']}")
                    if data.get("region"):
                        details.append(f"State/Region: {data['region']}")
                    if data.get("country"):
                        details.append(f"Country: {data['country']}")
                    details.append(f"Coordinates: {data['latitude']}, {data['longitude']}")
                else:
                    print(f"[Location] {name} missing coordinates")

            elif parser == "ipinfo":
                if 'error' not in data:
                    if data.get("org"):
                        org_val = data['org']
                        if org_val.startswith("AS"):
                            org_parts = org_val.split(' ', 1)
                            if len(org_parts) == 2:
                                details.append(f"ASN: {org_parts[0].replace('AS', '')}")
                                details.append(f"ISP: {org_parts[1]}")
                        else:
                            details.append(f"ISP: {org_val}")
                    if data.get("city"):
                        details.append(f"City: {data['city']}")
                    if data.get("region"):
                        details.append(f"State/Region: {data['region']}")
                    if data.get("country"):
                        details.append(f"Country: {data['country']}")
                    if data.get("loc"):
                        try:
                            lat, lon = data['loc'].split(',')
                            details.append(f"Coordinates: {lat}, {lon}")
                        except ValueError:
                            pass
                else:
                    print(f"[Location] {name} error: {data.get('error', {}).get('message', 'Unknown error')}")

            if details:
                print(f"[Location] ✓ {name} succeeded with {len(details)} fields")
                return '\n'.join(details)

        except Exception as exc:
            print(f"[Location] {name} request failed: {type(exc).__name__}: {exc}")

    print("[Location] All services failed")
    return f"IP: {ip_address}\nLocation services unavailable"

import json

try:
    SERVER_IP = get_public_ip()
    if not SERVER_IP:
        # Fallback to local IP detection
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        SERVER_IP = s.getsockname()[0]
        s.close()
        SERVER_REGION = "Local Network"
    else:
        print(f"✓ Detected Public IP: {SERVER_IP}")
        SERVER_REGION = fetch_location_details(SERVER_IP)
            
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

def write_wg_conf():
    """Write WireGuard configuration file with all peers"""
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
            "Address = 10.8.0.1/24",
            "ListenPort = 43210",
            ""
        ]
        
        for _, name, pubkey, _, ip in peers:
            config_lines.extend([
                "[Peer]",
                f"# {name}",
                f"PublicKey = {pubkey}",
                f"AllowedIPs = {ip}/32",
                ""
            ])
        
        config_content = "\n".join(config_lines)
        
        # Write config
        try:
            with open(WG_CONF, "w") as f:
                f.write(config_content)
            print(f"✓ WireGuard config written to {WG_CONF}")
        except PermissionError:
            print(f"⚠ Permission denied writing to {WG_CONF}, trying with sudo...")
            # Write to temp file first
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as tmp:
                tmp.write(config_content)
                tmp_path = tmp.name
            # Copy with sudo
            subprocess.run(["sudo", "cp", tmp_path, WG_CONF], check=True)
            subprocess.run(["sudo", "chmod", "600", WG_CONF], check=True)
            os.unlink(tmp_path)
            print(f"✓ WireGuard config written to {WG_CONF} (with sudo)")
        
        # Try to reload WireGuard
        result = subprocess.run(["wg-quick", "save", "wg0"], 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.PIPE,
                              text=True)
        if result.returncode != 0:
            print(f"⚠ wg-quick save failed: {result.stderr}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error writing WireGuard config: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def import_from_config():
    """Import peers from existing wg0.conf if database is empty"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM peers")
    count = cur.fetchone()[0]
    if count > 0 or not os.path.exists(WG_CONF):
        conn.close()
        return

    with open(WG_CONF) as f:
        content = f.read()
    peers = re.findall(r"\[Peer\]\n# (.*?)\nPublicKey = (.*?)\nAllowedIPs = (.*?)/32", content)
    for name, pubkey, ip in peers:
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
    return render_template("index.html", peers=peers, server_ip=SERVER_IP, server_region=SERVER_REGION)

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

            write_wg_conf()
            print(f"✓ WireGuard config updated")
            
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
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM peers WHERE id=?", (peer_id,))
    conn.commit()
    conn.close()
    write_wg_conf()
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
    config = f"""[Interface]
PrivateKey = {privkey}
Address = {ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = {SERVER_IP}:43210
AllowedIPs = 0.0.0.0/0, ::/0
"""
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
    qr_text = f"""[Interface]
PrivateKey = {privkey}
Address = {ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = {SERVER_IP}:43210
AllowedIPs = 0.0.0.0/0, ::/0
"""
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
        wg_status = subprocess.getoutput("wg show wg0")
    except:
        wg_status = "Error: WireGuard not available or wg0 not up"
    
    # Get AdGuard status
    try:
        adg_status = subprocess.getoutput("systemctl status AdGuardHome --no-pager -l")
    except:
        adg_status = "Error: AdGuard Home not installed or service not found"
    
    return render_template("server.html", wg_status=wg_status, adg_status=adg_status)

@app.route("/restart_wg", methods=["POST"])
@login_required
def restart_wg():
    try:
        subprocess.run(["systemctl", "restart", "wg-quick@wg0"], check=True)
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

@app.route("/stop_adg", methods=["POST"])
@login_required
def stop_adg():
    try:
        subprocess.run(["systemctl", "stop", "AdGuardHome"], check=True)
    except:
        pass
    return redirect(url_for("server"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)