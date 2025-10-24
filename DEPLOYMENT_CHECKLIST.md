# CayVPN Deployment Checklist

Complete deployment guide for CayVPN - a secure WireGuard VPN management system with AdGuard Home DNS filtering, HTTPS encryption, password hashing, CSRF protection, and real-time monitoring.

Before deploying to your server, verify these items:

## ✅ Pre-Deployment Verification

### 1. Server Requirements
- [ ] Ubuntu 20.04+ or Debian 11+
- [ ] Root or sudo access
- [ ] At least 512MB RAM (1GB+ recommended for multiple users)
- [ ] 10GB+ disk space
- [ ] Public IP address

### 2. Network Requirements
- [ ] Ports to be opened:
  - `43210/UDP` - WireGuard VPN
  - `8888/TCP` - HTTP web interface (fallback)
  - `8443/TCP` - HTTPS web interface (primary)
  - `8444/TCP` - AdGuard Home UI HTTPS (primary)
  - `3000/TCP` - AdGuard Home UI HTTP (fallback)
  - `53/TCP+UDP` - DNS (internal only, via WireGuard - 10.8.0.1)

### 3. Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/caynetic/cayvpn.git
cd cayvpn

# 2. (Optional) Customize configuration
export WG_PORT=43210              # WireGuard UDP port
export ENABLE_HTTPS=1             # Enable HTTPS (default: 1)
export HTTPS_PORT=8443            # HTTPS port (default: 8443)

# 3. Run installation script
sudo ./install.sh

# 4. Wait for installation to complete (~5-10 minutes)
```

### 4. Post-Installation Checks

```bash
# Check service status
sudo systemctl status wg-quick@wg0
sudo systemctl status AdGuardHome
sudo systemctl status cayvpn

# All services should show "active (running)"

# Check firewall rules
sudo iptables -L -n | grep 8443
sudo iptables -L -n | grep 43210

# Check certificate generation (if HTTPS enabled)
ls -la /etc/ssl/certs/cayvpn.crt
ls -la /etc/ssl/private/cayvpn.key

# Verify AdGuard Home certificates
ls -la /opt/AdGuardHome/cayvpn.crt
ls -la /opt/AdGuardHome/cayvpn.key

# Test web interfaces
curl -k https://localhost:8443  # CayVPN - Should return HTML
curl -k https://localhost:8444  # AdGuard - Should return HTML
curl http://localhost:8888      # CayVPN HTTP fallback
curl http://localhost:3000      # AdGuard HTTP fallback
```

### 5. First Access

1. **Open your browser** and navigate to:
   - **CayVPN Primary**: `https://YOUR_SERVER_IP:8443`
   - **CayVPN Fallback**: `http://YOUR_SERVER_IP:8888`
   - **AdGuard Home Primary**: `https://YOUR_SERVER_IP:8444`
   - **AdGuard Home Fallback**: `http://YOUR_SERVER_IP:3000`

2. **Accept SSL warning** (self-signed certificate)
   - Click "Advanced" → "Proceed to site"
   - This is normal for self-signed certificates

3. **Set admin password** (First-time setup on CayVPN login page)
   - Username: `admin` (fixed)
   - Password: Set your own (minimum 8 characters)
   - This password will be used for both CayVPN and AdGuard Home

4. **Verify installation**
   - CayVPN dashboard should load
   - No peers should be listed yet
   - Server info should be displayed
   - AdGuard Home should be accessible with the same password

## 🔧 Troubleshooting

### Services not starting

```bash
# Check logs
sudo journalctl -u cayvpn -f
sudo journalctl -u wg-quick@wg0 -f
sudo journalctl -u AdGuardHome -f

# Restart services
sudo systemctl restart cayvpn
sudo systemctl restart wg-quick@wg0
sudo systemctl restart AdGuardHome
```

### Cannot access web interface

```bash
# Check if Flask is running
sudo netstat -tlnp | grep python

# Check firewall
sudo iptables -L -n

# Check service logs
sudo journalctl -u cayvpn --no-pager -n 50
```

### HTTPS certificate issues

```bash
# Regenerate certificates for both services
sudo rm /etc/ssl/certs/cayvpn.crt /etc/ssl/private/cayvpn.key
sudo rm /opt/AdGuardHome/cayvpn.crt /opt/AdGuardHome/cayvpn.key
sudo systemctl restart cayvpn
sudo systemctl restart AdGuardHome

# Or disable HTTPS temporarily
sudo systemctl stop cayvpn
sudo systemctl edit cayvpn
# Add: Environment=ENABLE_HTTPS=0
sudo systemctl start cayvpn
```

### Permission errors

```bash
# Ensure proper permissions
sudo chown -R $USER:$USER /path/to/vpn
chmod 700 /path/to/vpn/sessions
chmod 600 /etc/ssl/private/cayvpn.key
```

## 🔒 Security Recommendations

### After Installation

1. **Change admin password immediately**
   - Default first-time setup forces this
   - Use a strong password (16+ characters)

2. **Configure firewall properly**
   ```bash
   # Only allow necessary ports
   sudo ufw enable
   sudo ufw allow 43210/udp    # WireGuard
   sudo ufw allow 8443/tcp     # HTTPS
   sudo ufw allow 22/tcp       # SSH
   ```

3. **Upgrade to Let's Encrypt** (if you have a domain)
   ```bash
   sudo apt install certbot
   sudo certbot certonly --standalone -d your-domain.com
   
   # Update systemd service
   sudo systemctl edit cayvpn
   # Add:
   Environment=SSL_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
   Environment=SSL_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem
   Environment=HTTPS_PORT=443
   
   sudo systemctl restart cayvpn
   ```

4. **Regular updates**

   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade -y
   
   # Update CayVPN from GitHub
   cd /root/cayvpn
   git pull origin main
   
   # Update Python dependencies (if needed)
   source venv/bin/activate
   pip install --upgrade -r requirements.txt
   sudo systemctl restart cayvpn
   ```

5. **Backup configuration**

   ```bash
   # Backup database and configs
   sudo cp wg.db wg.db.backup
   sudo tar czf cayvpn-backup-$(date +%F).tar.gz \
       wg.db \
       /etc/wireguard/ \
       /etc/ssl/certs/cayvpn.crt \
       /etc/ssl/private/cayvpn.key \
       /opt/AdGuardHome/AdGuardHome.yaml \
       /opt/AdGuardHome/cayvpn.crt \
       /opt/AdGuardHome/cayvpn.key
   ```

## 📊 Expected Behavior

### After Successful Installation

- ✅ 3 services running (WireGuard, AdGuard Home, CayVPN)
- ✅ Web interfaces accessible via HTTPS on ports 8443 and 8444
- ✅ Self-signed certificates generated and shared between services
- ✅ Session storage directory created
- ✅ Firewall rules configured
- ✅ First-time password setup required
- ✅ Bcrypt password hashing enabled
- ✅ CSRF protection active on all forms
- ✅ Rate limiting on login attempts

### Known Behavior

- ⚠️ Browser shows SSL warning (expected for self-signed cert)
- ⚠️ HTTP fallback available on ports 8888 (CayVPN) and 3000 (AdGuard)
- ⚠️ AdGuard Home uses same admin password as CayVPN
- ✅ Rate limiting: Max 5 login attempts per minute
- ✅ CSRF tokens on all forms
- ✅ Secure session cookies (HttpOnly, SameSite, 1-hour timeout)
- ✅ Password hashing with bcrypt (cost factor 10)
- ✅ Server-side session storage in `sessions/` directory

## 🎯 Success Criteria

Your installation is successful when:

1. ✅ You can access `https://YOUR_IP:8443` (CayVPN)
2. ✅ You can access `https://YOUR_IP:8444` (AdGuard Home)
3. ✅ You can set an admin password on first login
4. ✅ You can login to both interfaces with that password
5. ✅ CayVPN dashboard displays server information
6. ✅ You can add a WireGuard peer
7. ✅ You can download/view QR code for the peer
8. ✅ Peer statistics show up after connection
9. ✅ DNS queries are filtered through AdGuard Home
10. ✅ All security features are active (HTTPS, CSRF, rate limiting)

## 🆘 Getting Help

If you encounter issues:

1. Check logs: `sudo journalctl -u cayvpn -f`
2. Verify services: `sudo systemctl status cayvpn`
3. Review this checklist
4. Check GitHub issues: https://github.com/caynetic/cayvpn/issues
5. Get paid support: Visit https://vpn.caynetic.com for $3 lifetime support

## 📝 Configuration Variables

Default values (can be changed before installation):

```bash
# WireGuard Configuration
WG_PORT=43210                           # WireGuard UDP port
WG_IFACE=wg0                           # WireGuard interface
WG_SUBNET_V4=10.8.0.1/24              # VPN subnet

# HTTPS Configuration
ENABLE_HTTPS=1                         # Enable HTTPS (1=yes, 0=no)
HTTPS_PORT=8443                        # CayVPN HTTPS port
SSL_CERT_PATH=/etc/ssl/certs/cayvpn.crt
SSL_KEY_PATH=/etc/ssl/private/cayvpn.key

# AdGuard Home Configuration
ADGUARD_HTTPS_PORT=8444                # AdGuard Home HTTPS port
ADGUARD_HTTP_PORT=3000                 # AdGuard Home HTTP fallback
ADGUARD_CONFIG=/opt/AdGuardHome/AdGuardHome.yaml

# Security Configuration
WTF_CSRF_ENABLED=True                  # CSRF protection
PERMANENT_SESSION_LIFETIME=3600        # Session timeout (1 hour)
SESSION_COOKIE_SECURE=True             # Secure cookies (HTTPS only)
SESSION_COOKIE_HTTPONLY=True           # HttpOnly cookies
SESSION_COOKIE_SAMESITE=Lax            # SameSite policy
```

To customize before installation:

```bash
export ENABLE_HTTPS=0  # Disable HTTPS
export HTTPS_PORT=443  # Use standard HTTPS port
export WG_PORT=51820   # Custom WireGuard port
./install.sh
```
