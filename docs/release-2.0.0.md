# CayVPN 2.0.0

CayVPN 2.0 replaces the original setup script with a self-hosted VPN management
application for one dedicated Ubuntu 24.04 server. The source remains MIT
licensed. Bundled third-party components retain their own licenses and notices.

## What changed

- A private web panel reached through a separate, individually revocable owner
  WireGuard connection. Optional owner login supports access from an ordinary
  CayVPN connection or explicitly enabled public HTTPS.
- WireGuard and AmneziaWG client profiles, with guided setup and editable DNS
  and IPv6 policies. DNS changes produce an updated profile; keys, addresses,
  and the selected Location are preserved.
- Direct server IP, attached additional IP, imported provider tunnel, and
  SOCKS5 Locations. Each client has its own routing policy. Approved backup
  groups can fail over automatically; returning to a recovered primary is
  an explicit owner action.
- Standard or ad-blocking DNS follows the selected Location. IPv6 capability
  is verified separately. Smart mode blocks unavailable IPv6 while retaining
  IPv4; Require IPv6 blocks the connection when dual-stack service is lost.
- Signed, immutable release downloads with pinned offline Python and native
  components; owner-approved updates, rollback, encrypted backups and SSH
  recovery. An upstream failure must not silently send traffic through the
  server's ordinary connection.

## Installation and compatibility

Use a **clean, dedicated Ubuntu 24.04 x86_64 or ARM64 server** with SSH access,
a public IPv4 address, and at least 5 GiB free disk space. Configure a usable
public IPv6 address with your host if you want dual-stack Internet access.
The installer checks resources and refuses conflicting VPN, firewall or
service configuration before installation. Plan capacity for your actual load;
the installation minimum is not a throughput or client-count guarantee.

```bash
curl -fsSL https://raw.githubusercontent.com/caynetic/cayvpn/v2.0.0/bootstrap.sh | sudo bash
```

Keep the downloaded owner kit and your recovery passphrase private. Start with
its admin profile and certificate, then create ordinary client profiles in the
panel. Use a compatible WireGuard or Amnezia client application on your device.

**CayVPN 1.x cannot be upgraded in place.** Keep its server and configuration
available, install 2.0 on a clean server, and create and import new profiles.
Internal 2.0.x acceptance builds used a disposable trust key and are not an
upgrade source for this public release.

## Verification scope

The release candidate passed 325 automated tests on native Ubuntu ARM64 and
x86_64. Real WireGuard and AmneziaWG traffic on the dedicated test servers
covered standard/ad-blocking DNS, Smart/Require IPv6, existing-client changes,
profile reimport, route and backup-group changes, upstream failure, reconnection,
revocation, and second-client isolation. Earlier native acceptance exercised
signed installation, upgrade, rollback, reboot recovery, encrypted restore and
uninstall, including injected failures.

These checks do not certify every provider, device, or workload. Controlled
same-server upstream fixtures establish routing behavior; they are not proof
for an independent commercial provider. Additional IP routing, provider UDP,
and provider IPv6 depend on the supplied configuration and live capability
checks. Physical-device import, sleep/wake, Wi-Fi/mobile transitions, optional
passkey compatibility, and sustained-load limits need acceptance in the owner's
environment. There is no independent security-audit certification.

IPv6-only servers, NAT64, automatic provider provisioning, and migration from
1.x are not supported. SOCKS5 UDP stays blocked until its end-to-end relay checks
pass. Remote public administration starts disabled.

## Privacy and support

CayVPN requires no Caynetic account or hosted relay and sends no application
telemetry. Configuration, operational records, counters and recovery data stay
on your server. Your host, chosen DNS/upstream services, and external update or
capability-check endpoints have their own policies. Self-hosting does not make
the server or its public address anonymous.

Use [GitHub issues](https://github.com/caynetic/cayvpn/issues) for community
support without attaching private keys, profiles, owner kits or passphrases.
Optional [project support](https://www.buymeacoffee.com/caynetic) never unlocks
features or gates installation.
