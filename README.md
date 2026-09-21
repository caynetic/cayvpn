# CayVPN

**A self-hosted VPN manager for your own Ubuntu server.**

CayVPN turns a clean Ubuntu 24.04 VPS into a private VPN appliance. You bring
the server; CayVPN provides the management panel, device configurations,
routing, DNS controls, backups, recovery tools, and signed updates.

CayVPN is open source and MIT-licensed. It does not require a Caynetic account,
a hosted relay, telemetry, or access to your hosting-provider account.

Current release: **CayVPN 2.0.1** · [Read the release notes](docs/release-2.0.1.md)

## CayVPN or CayneticVPN?

Choose the option that matches how much you want to manage yourself:

| If you want to… | Use |
| --- | --- |
| Run and control a VPN on your own VPS | **CayVPN** — the open-source project in this repository |
| Download an app and let us manage the VPN service | [**CayneticVPN**](https://cayneticvpn.com/) — our managed SaaS product |

CayVPN and CayneticVPN are separate products. The instructions below are for
people who want to self-host CayVPN.

## What CayVPN gives you

- A private web panel for managing your VPN.
- WireGuard and optional AmneziaWG device configurations.
- QR codes and downloadable configuration files for phones and computers.
- Direct server-IP exits, attached additional IPs, provider tunnels, and
  validated SOCKS5 exits.
- Standard or ad-blocking DNS that follows the selected Location.
- IPv6 leak protection when an exit does not support working IPv6.
- Per-device Location, DNS, and IPv6 settings.
- Health checks, encrypted backups, recovery tools, and signed updates.
- Fail-closed routing: a broken exit is blocked instead of silently sending
  traffic through the server's normal Internet connection.

Hosting-provider setup and billing stay in your hands. CayVPN does not create,
resize, or pay for servers, and it never asks for provider API keys or SSH
credentials.

## Before you install

You need:

- a **clean, dedicated Ubuntu 24.04** VPS;
- an x86_64 or ARM64 processor;
- SSH access with `sudo` or root permissions;
- a public IPv4 address;
- at least 5 GiB of free disk space; and
- a WireGuard-compatible app on the devices you want to connect.

A usable public IPv6 address is optional and is only needed for dual-stack
Internet access. The installer checks the server first and stops without making
changes if it finds conflicting VPN, firewall, or service configuration.

> [!IMPORTANT]
> CayVPN 2.0 requires a clean server. CayVPN 1.x cannot be upgraded or imported
> in place. Keep the old server as a reference or backup and install 2.0 on a
> new VPS.

## Quick start

### 1. Connect to your server

Use your hosting provider's console or SSH:

```bash
ssh your-user@your-server-ip
```

### 2. Run the signed installer

```bash
curl -fsSL https://raw.githubusercontent.com/caynetic/cayvpn/v2.0.1/bootstrap.sh | sudo bash
```

The bootstrap downloads the published v2.0.1 release and verifies its signed
file list before running any release code. The installer then checks the server
and guides you through setup.

### 3. Save the owner kit

The installer asks you to create an offline recovery passphrase. Keep it safe;
CayVPN cannot recover it for you.

When setup finishes, download the private owner kit using the exact `scp`
command shown by the installer. The kit contains:

- `admin.conf`, your private management connection;
- `cayvpn-ca.crt`, which lets your browser trust the private panel;
- encrypted recovery material; and
- a short first-login guide.

Do not share the owner kit, recovery passphrase, or any device configuration.

### 4. Open the private panel

Import `admin.conf` into a WireGuard app, connect it, and open:

```text
https://admin.cayvpn.home.arpa:8443
```

Follow the first-login guide in the owner kit to trust the CayVPN certificate.
The panel will then guide you through creating your first client and Location.

## How administration works

The separate `admin.conf` connection is the default recovery and management
path. Each admin device has its own key and can be revoked individually.

You can optionally enable an owner password and authenticator, then choose one
of two additional access methods:

- **While connected to CayVPN:** use `https://10.255.0.1:8443` from an ordinary
  CayVPN client. Public web ports stay closed.
- **From anywhere:** explicitly enable public HTTPS at your VPS IPv4 address.
  CayVPN then manages a short-lived public certificate and fixed TCP 80/443
  rules. Public access is off by default.

Turn off any other full-tunnel VPN before starting the separate admin tunnel.
Some devices can show two VPNs as connected even though only one is routing
traffic.

## DNS and IPv6 protection

Each device can use standard DNS or ad-blocking DNS. DNS stays inside the
selected Location. If its resolver fails, CayVPN blocks DNS instead of falling
back to the VPS resolver.

Each device also has one IPv6 policy:

- **Smart IPv6** keeps IPv4 connected and blocks IPv6 when the selected
  Location has not passed live IPv6 checks.
- **Require IPv6** connects only through a verified dual-stack Location. If
  IPv6 fails, both IPv4 and IPv6 are blocked or the device moves to another
  owner-approved dual-stack Location.

Both address families always use the same Location. IPv6-only exits and NAT64
are not currently supported. See [IPv6 behavior](docs/ipv6.md) and
[client settings](docs/client-settings.md) for the complete rules.

## Updates and recovery

CayVPN never installs an application update silently. In **Settings → CayVPN
updates**, the owner chooses when to:

1. check the official GitHub repository for a stable release;
2. download and verify the signed release without changing the running VPN; and
3. install the verified update after CayVPN creates a rollback snapshot.

If installation or verification fails, CayVPN restores the previous verified
release. Ubuntu security updates are separate, and automatic reboots remain
disabled. See [the update and release model](docs/updates.md) for details.

Useful SSH commands:

```bash
cayvpnctl status
cayvpnctl verify
cayvpnctl repair
cayvpnctl diagnostics
cayvpnctl capacity
cayvpnctl backup
cayvpnctl restore /path/to/cayvpn-*.backup --confirm
cayvpnctl admin-device list
cayvpnctl recovery approve
cayvpnctl upgrade --release 2.0.1 --confirm
cayvpnctl rollback --confirm
cayvpnctl uninstall --confirm
```

Restore, upgrade, rollback, and uninstall require explicit owner confirmation.

## Privacy and practical limits

CayVPN keeps its configuration, operational records, counters, and recovery
data on your server. It sends no application telemetry. Your hosting provider,
DNS or upstream provider, and any external service you use have their own
privacy policies. Self-hosting does not make a server or public IP anonymous.

Release checks cover the supported server platforms and controlled routing
scenarios, but they do not certify every provider, device, or workload. Test
your own device imports, sleep and wake behavior, Wi-Fi and mobile transitions,
provider capabilities, and expected load before depending on the server.

## Development

For local development, create a virtual environment and run the test suite:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q app.py cayvpn tests migrations
```

To run the source installer on a development server, you must explicitly allow
the unverified local build:

```bash
sudo CAYVPN_ALLOW_UNVERIFIED_LOCAL=1 \
  CAYVPN_ALLOW_MISSING_COMPONENTS=1 \
  ./install.sh
```

The Flask web service runs without root privileges. It sends typed networking
operations to a root-owned agent through a private Unix socket. Database
migrations live in `migrations/`.

## Documentation

- [CayVPN 2.0.1 release notes](docs/release-2.0.1.md)
- [Client DNS and IPv6 settings](docs/client-settings.md)
- [IPv6 behavior](docs/ipv6.md)
- [Updates, rollback, and release trust](docs/updates.md)
- [Provisioning design and current boundaries](docs/provisioning.md)
- [Deployment and release acceptance checklist](DEPLOYMENT_CHECKLIST.md)
- [Release dependency locks](release-locks/README.md)

## For release maintainers

Prepare complete Python 3.12 wheel bundles for both supported architectures:

```bash
./scripts/prepare-wheelhouse.sh /secure/staging/cayvpn-wheelhouse
```

Build and review the optional native-component bundle, record the approved
digests in the matching file under `release-locks/`, and build the release on
an offline Ubuntu 24.04 signer:

```bash
CAYVPN_RELEASE_PYTHON=/opt/python3.12/bin/python3.12 \
CAYVPN_COMPONENT_BUNDLE=/offline/path/cayvpn-components \
./scripts/build-release.sh \
  2.0.1 \
  /offline/path/cayvpn-release-signing.key \
  /offline/path/cayvpn-wheelhouse
```

The canonical preflight must run on Linux. Before publishing, follow the full
[deployment checklist](DEPLOYMENT_CHECKLIST.md) and verify the public installer
on clean native x86_64 and ARM64 Ubuntu 24.04 systems.

## Help and support

Use [GitHub Issues](https://github.com/caynetic/cayvpn/issues) for bugs and
community support. Never attach private keys, client profiles, owner kits,
recovery files, or passphrases.

CayVPN is donationware.
[Support the open-source project](https://www.buymeacoffee.com/caynetic) if it
is useful to you. Donations never unlock features or change the license.

If you would rather use a managed service, visit
[CayneticVPN](https://cayneticvpn.com/).

## License

CayVPN is available under the [MIT License](LICENSE). Bundled third-party
components keep their own licenses and notices.
