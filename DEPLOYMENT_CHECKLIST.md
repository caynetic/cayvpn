# CayVPN Deployment Checklist

Before deploying to your server, verify these items:

## ✅ Pre-Deployment Verification

### 1. Server Requirements
- [ ] Ubuntu 20.04+ or Debian 11+
- [ ] Root or sudo access
- [ ] At least 1GB RAM
- [ ] 10GB+ disk space
- [ ] Public IP address

### 2. Network Requirements
- [ ] Ports to be opened:
  - `43210/UDP` - WireGuard VPN
  - `8888/TCP` - HTTP web interface (fallback)
  - `8443/TCP` - HTTPS web interface (primary)
  - `3000/TCP` - AdGuard Home UI (optional)
  - `53/TCP+UDP` - DNS (internal only, via WireGuard)

### 3. Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/KleinFrom242/vpn.git
cd vpn

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
sudo systemctl status cloudflared-dns

# All services should show "active (running)"

# Check firewall rules
sudo iptables -L -n | grep 8443
sudo iptables -L -n | grep 43210

# Check certificate generation (if HTTPS enabled)
ls -la /etc/ssl/certs/cayvpn.crt
ls -la /etc/ssl/private/cayvpn.key

# Test web interface
curl -k https://localhost:8443  # Should return HTML
curl http://localhost:8888      # Should also work
```

### 5. First Access

1. **Open your browser** and navigate to:
   - Primary: `https://YOUR_SERVER_IP:8443`
   - Fallback: `http://YOUR_SERVER_IP:8888`

2. **Accept SSL warning** (self-signed certificate)
   - Click "Advanced" → "Proceed to site"
   - This is normal for self-signed certificates

3. **Set admin password**
   - Username: `admin` (fixed)
   - Password: Set your own (minimum 8 characters)

4. **Verify installation**
   - Dashboard should load
   - No peers should be listed yet
   - Server info should be displayed

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
# Regenerate certificates
sudo rm /etc/ssl/certs/cayvpn.crt /etc/ssl/private/cayvpn.key
sudo systemctl restart cayvpn

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
   
   # Update Python dependencies
   cd /path/to/vpn
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
       /opt/AdGuardHome/AdGuardHome.yaml
   ```

## 📊 Expected Behavior

### After Successful Installation

- ✅ All 4 services running (WireGuard, AdGuard, CayVPN, Cloudflared)
- ✅ Web interface accessible via HTTPS
- ✅ Self-signed certificate generated
- ✅ Session storage directory created
- ✅ Firewall rules configured
- ✅ First-time password setup required

### Known Behavior

- ⚠️ Browser shows SSL warning (expected for self-signed cert)
- ⚠️ HTTP fallback available on port 8888 (for debugging)
- ⚠️ AdGuard Home accessible on port 3000 (same password as admin)
- ✅ Rate limiting: Max 5 login attempts per minute
- ✅ CSRF tokens on all forms
- ✅ Secure session cookies (HttpOnly, SameSite)

## 🎯 Success Criteria

Your installation is successful when:

1. ✅ You can access `https://YOUR_IP:8443`
2. ✅ You can set an admin password
3. ✅ You can login with that password
4. ✅ Dashboard displays server information
5. ✅ You can add a WireGuard peer
6. ✅ You can download/view QR code for the peer
7. ✅ Peer statistics show up after connection

## 🆘 Getting Help

If you encounter issues:

1. Check logs: `sudo journalctl -u cayvpn -f`
2. Verify services: `sudo systemctl status cayvpn`
3. Review this checklist
4. Check GitHub issues: https://github.com/KleinFrom242/vpn/issues

## 📝 Configuration Variables

Default values (can be changed before installation):

```bash
WG_PORT=43210                           # WireGuard UDP port
WG_IFACE=wg0                           # WireGuard interface
WG_SUBNET_V4=10.8.0.1/24              # VPN subnet
ENABLE_HTTPS=1                         # Enable HTTPS (1=yes, 0=no)
HTTPS_PORT=8443                        # HTTPS port
SSL_CERT_PATH=/etc/ssl/certs/cayvpn.crt
SSL_KEY_PATH=/etc/ssl/private/cayvpn.key
ADGH_ADMIN_PORT=3000                   # AdGuard Home UI port
```

To customize:
```bash
export ENABLE_HTTPS=0  # Disable HTTPS
export HTTPS_PORT=443  # Use standard HTTPS port
./install.sh
```
