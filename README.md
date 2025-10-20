# CayVPN - Easy WireGuard VPN Management

A simple, secure VPN management system with WireGuard, DNS filtering, and a web interface. Get your VPN server running in minutes!

## 🚀 Quick Start

1. **Get a server** (Ubuntu 20.04+ or Debian 11+ recommended):
   - We recommend DigitalOcean for easy setup: [Get $200 free credit for 2 months](https://m.do.co/c/eb6e30467a3e)

2. **Clone and install**:
   ```bash
   git clone https://github.com/caynetic/cayvpn.git
   cd cayvpn
   sudo ./install.sh
   ```

3. **Access your VPN dashboard**:
   - Open `https://your-server-ip:8443` in your browser
   - Accept the security warning (self-signed certificate)
   - Set your admin password

That's it! Your VPN server is ready.

## 🔧 Features

- ✅ WireGuard VPN with easy peer management
- ✅ QR codes for mobile device setup
- ✅ Real-time bandwidth monitoring
- ✅ Built-in DNS filtering (AdGuard Home)
- ✅ Secure web interface with HTTPS
- ✅ Automatic firewall setup

## 🛠️ Troubleshooting

If something doesn't work:
- **Reboot your server**: `sudo reboot`
- Check service status: `sudo systemctl status cayvpn`
- View logs: `sudo journalctl -u cayvpn -f`

For detailed help, see [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md).

- Get paid support: Visit https://vpn.caynetic.com for $3 lifetime support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤖 Development

This project was developed with the assistance of AI tools, but all code has been reviewed and verified by a professional software engineer.
