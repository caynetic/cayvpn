# Flask WireGuard Manager

A web-based interface for managing WireGuard peers and monitoring server services (WireGuard + AdGuard Home).

## Features
- Add/remove WireGuard peers with auto-generated keys
- Download peer configs and QR codes
- Monitor WireGuard and AdGuard Home status
- Restart services via web UI
- Bootstrap-based modern UI

## Installation

### Prerequisites
- Ubuntu/Debian server
- Run your WireGuard + AdGuard setup script first

### Steps
1. **Clone the repo:**
   ```bash
   git clone https://github.com/KleinFrom242/vpn.git
   cd vpn
   ```

2. **Install dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv
   python3 -m venv venv
   source venv/bin/activate
   pip install flask qrcode[pil]
   ```

3. **Run the app:**
   ```bash
   sudo venv/bin/python app.py
   ```

4. **Access:**
   - URL: `http://your-server-ip:8888`
   - Login: `admin` / `password`
   - Change credentials in `app.py`

## Usage
- **Peers:** Add peers, download configs, scan QR codes
- **Server:** View status, restart services
- **AdGuard:** Access UI at `http://your-server-ip:3000`

## Security
- Change `ADMIN_USER` and `ADMIN_PASS` in `app.py`
- Run behind reverse proxy for production
- Use HTTPS

## Production Deployment
Use Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8888 app:app
```

## License
MIT