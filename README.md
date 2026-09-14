# CayVPN 2.0

CayVPN is an MIT-licensed, self-hosted VPN management appliance for one
owner-supplied Ubuntu 24.04 VPS. It keeps the management panel, routing state,
client configurations, and recovery path on the node; no Caynetic account,
hosted relay, telemetry, or provider API credentials are required.

**CayVPN 2.0.0** brings private administration, per-device connection settings,
verified routing, encrypted recovery, and signed updates to a clean Ubuntu
24.04 server. Read the [release notes](docs/release-2.0.0.md) for compatibility
and validation limits. CayVPN 1.x requires a new server and new client profiles;
there is no in-place upgrade or automatic import.

## What it manages

- Standard WireGuard client ingress by default, with optional AmneziaWG ingress
  after a pinned, checksum-verified component is staged.
- A dedicated `wg-admin` tunnel for passwordless private administration and
  individually revocable admin devices. Owners may optionally add a
  password login, with an authenticator as extra security, and choose either
  private access from an ordinary CayVPN client or opt-in access from anywhere
  at the VPS public IPv4 address. Internet access is off by default and uses a
  fixed, root-controlled TCP 80/443 configuration with a short-lived publicly
  trusted IP certificate; the private admin tunnel remains the recovery path.
- Direct VPS IP and additional/reserved IP exits through isolated namespaces and
  typed policy routing.
- Per-install RFC 4193 client addressing with separate IPv6 networks for
  standard WireGuard, AmneziaWG, exit transport, and internal DNS. Client
  configurations carry both full-tunnel families while the public connection
  endpoint and private admin tunnel remain IPv4-only in this phase.
- Per-exit DNS runs in the selected namespace. Standard mode uses the local
  resolver's encrypted DoH upstream; ad-blocking mode has its own stable DNS
  address and a checksum-verified, commit-pinned filter list plus any
  owner-managed blocklists. Missing or empty filtering data is rejected
  instead of silently behaving like standard DNS. Resolver failure blocks DNS
  rather than falling back to the VPS resolver.
- Edit an existing device's DNS mode and IPv6 protection from **Edit connection**
  or the owner API, preserving its keys, addresses, and selected Location.
  DNS changes require importing an updated configuration; IPv6 policy is
  enforced on the server after verification. See [client settings](docs/client-settings.md).
- Validated SOCKS5 and provider WireGuard/AmneziaWG profiles. SOCKS5 TCP, DNS,
  and the routed exit are verified automatically; UDP is enabled only after
  repeated end-to-end relay checks pass for that provider. IPv4 and IPv6 are
  measured independently; unsupported UDP, QUIC, DNS, or IPv6 paths remain
  blocked instead of falling back to the VPS connection.
- Switchable client routes or configurations pinned to one exit/failover pool;
  new and unassigned clients start behind a prohibit route rather than using an
  implicit direct fallback.
- Health state, per-client policy tables, additional-IP source mappings,
  restart reconciliation, capacity estimates, encrypted backups, signed
  release updates, and SSH recovery through `cayvpnctl`.
- Resumable, server-rendered setup wizards for clients, exits, and failover
  pools, with review pages, accessible error summaries, browser-Back support,
  24-hour drafts, and secret material kept outside draft JSON.

Provider-side VPS creation, resizing, billing, and IP attachment remain manual
in this release phase. CayVPN never asks for SSH passwords or private keys and
never stores DigitalOcean, Cloudzy, or another provider's API keys.

## Guided setup and IPv6 protection

The private panel breaks longer tasks into short pages and saves unfinished
non-secret answers for 24 hours. Imported tunnel configurations and proxy
passwords go directly to the encrypted root-owned secret store; Back and review
pages show only **Configuration supplied**. Cancel, completion, or expiration
removes temporary secret material, and a deletion failure retains the draft for
a safe retry.

Every client chooses one IPv6 behavior:

- **Smart IPv6** keeps IPv4 working when the selected exit has not passed live
  IPv6 TCP, DNS, and public-address checks, while installing an explicit IPv6
  prohibit route so traffic cannot leak.
- **Require IPv6** permits only verified dual-stack exits. An IPv6 failure
  blocks both families and may move to the next verified dual-stack exit in an
  owner-approved pool.

Both families always use the same selected exit. IPv6-only exits and NAT64 are
not supported in this phase. Existing clients keep their keys and IPv4
addresses and receive a one-time configuration-refresh action for their stable
IPv6 address. See [docs/ipv6.md](docs/ipv6.md) for the implemented contract and
[docs/provisioning.md](docs/provisioning.md) for the gated future setup design.

## Installation

The owner-facing install is one version-pinned command on an Ubuntu 24.04
x86_64 or ARM64 VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/caynetic/cayvpn/v2.0.0/bootstrap.sh | sudo bash
```

The command downloads the signed `v2.0.0` GitHub release. The bootstrap verifies
the Ed25519-signed file manifest before it
runs any release code. Before changing the VPS, the guided installer validates
the signed native-component lock and every bundled helper, confirms that the
dedicated server has no firewall or service state CayVPN would overwrite, and
asks only for an offline recovery passphrase. CayVPN 2.0 is a clean-install appliance;
it does not import CayVPN 1.x state, ask for provider API credentials, or
modify an old installation.

At the end, the installer offers an optional admin WireGuard QR and prints one
exact `scp` command for the private owner kit. The QR is off by default because
provider consoles may retain what was displayed. The kit contains:

- `admin.conf` for the private management tunnel;
- `cayvpn-ca.crt` for the trusted private panel certificate;
- encrypted TLS recovery material; and
- a short first-login guide.

The panel then shows a one-time welcome prompt for owner access, client, and
exit setup. The trusted owner tunnel needs no password, authenticator, or
passkey. Those methods are optional and never block normal setup. The
one-time Caynetic support prompt appears only after onboarding has
started and the owner has created a client. Neither prompt repeats after it is
dismissed.

For local development only, run the source installer explicitly in
non-production mode:

```bash
sudo CAYVPN_ALLOW_UNVERIFIED_LOCAL=1 \
  CAYVPN_ALLOW_MISSING_COMPONENTS=1 \
  ./install.sh
```

After the clean-VPS preflight passes, the installer creates a recovery snapshot
of the permitted system configuration, installs a versioned release under
`/opt/cayvpn`, and switches the `/opt/cayvpn/current` symlink atomically. The
TLS CA signing key is placed in an age-encrypted recovery file and removed from
the live TLS directory. A fresh installation also generates and persists one
random RFC 4193 `/48`; it does not reuse a universal private IPv6 prefix.

The private panel is served at:

```text
https://admin.cayvpn.home.arpa:8443
```

The hostname resolves through the admin tunnel. On a fresh installation, nginx
is bound only to the admin-tunnel address and the public web ports are closed.
Each registered `admin.conf` is a revocable owner key: while that tunnel is
connected, it can manage CayVPN directly without another password or code.

Security also offers an optional three-step owner-login wizard for people who
want access from a normal CayVPN connection or from anywhere. It uses a
bcrypt-protected password. Password-only is the easy default; a rotating
authenticator code stored behind the encrypted root secret store is optional
extra security. The owner chooses:

- **While connected to CayVPN:** open the certificate-covered private address
  `https://10.255.0.1:8443` without switching tunnels. This avoids
  platform-specific handling of `home.arpa` and keeps the public web ports
  closed.
- **From anywhere:** opt in to `https://<VPS-public-IPv4>` with a short-lived
  Let's Encrypt IP certificate. CayVPN uses TCP 80 for certificate challenges
  and TCP 443 for HTTPS; these are separate from the WireGuard UDP port. The
  fixed listener and firewall rules are applied by the root agent, roll back on
  failure, and close again when internet access is disabled.

The public choice requires the owner to accept the certificate subscriber
agreement. The connected trusted owner tunnel can make management changes
directly. Other owner-login sessions confirm changes that could disconnect users
or expose private configuration with the owner password and, when enabled, an
authenticator code. A private passkey is another optional confirmation method,
and one-time SSH recovery approval remains available through the private path.

Before starting the dedicated admin tunnel, turn off any other active
full-tunnel VPN. Some platforms, including macOS, may keep the second tunnel
shown as active while routing no private panel traffic through it. After owner
login is enabled, leave the admin tunnel off and use the ordinary CayVPN client
with the private panel address above.

Generated WireGuard and Amnezia configurations also include CayVPN's private
DNS search scope. This keeps `admin.cayvpn.home.arpa` on the CayVPN resolver on
platforms that otherwise reserve `home.arpa` for the local network. Existing
clients receive a one-time connection-configuration update without changing
their keys or IPv4/IPv6 addresses.

### Legacy versions

CayVPN 1.x is legacy and is not upgraded in place. The 2.0 installer detects
the old service, database, or WireGuard state and exits before installing
packages, taking snapshots, or changing files. Keep the old VPS available as
your own reference or backup, then provision CayVPN 2.0 on a clean Ubuntu
24.04 VPS and manually create new client configurations. There is no supported
1.x import or public-panel cutover path.

Filtered DNS is kept in the selected Location namespace. CayVPN installs a
verified filter list for its isolated dnsmasq resolvers; it does not install or
start a host-wide AdGuard Home service that could conflict with the private
admin resolver.

### Release maintainers

First prepare the complete Python 3.12 wheel bundles on a connected build
machine. The command resolves every pinned direct and transitive dependency for
both supported VPS architectures:

```bash
./scripts/prepare-wheelhouse.sh /secure/staging/cayvpn-wheelhouse
```

Build the native component bundle for both architectures with the manually
dispatched `Build optional component bundle` workflow, then independently
review its pinned sources, provenance, licenses, and binaries.

Before transfer, record the exact reviewed wheel and component digests in
`release-locks/2.0.0.json`. Review and commit that lock separately from the
artifact transfer; adjacent `SHA256SUMS` files detect transfer damage but are
not signing authority. See [release-locks/README.md](release-locks/README.md).

Transfer both directories to an offline Ubuntu 24.04 signer. Use an explicit
Python 3.12 interpreter and build from the clean commit containing the reviewed
lock. The canonical preflight installs Linux wheels, so it must run on Linux;
a macOS Python environment cannot substitute for this check:

```bash
CAYVPN_RELEASE_PYTHON=/opt/python3.12/bin/python3.12 \
CAYVPN_COMPONENT_BUNDLE=/offline/path/cayvpn-components \
./scripts/build-release.sh \
  2.0.0 \
  /offline/path/cayvpn-release-signing.key \
  /offline/path/cayvpn-wheelhouse
```

Optionally provide a fifth argument containing the owner-facing impact fields
(`summary`, `migration_notes`, `component_changes`, `compatibility_notes`,
`expected_interruption_seconds`, `requires_reboot`, and `security_fixes`). The
builder validates and signs those fields into the release metadata so the
panel can explain what will happen before installation.
Before signing, the canonical preflight verifies the reviewed wheel and native
component lock, runs the complete suite with resource warnings fatal, and checks
Python, shell, JavaScript, and whitespace using Python 3.12. The installer and
in-panel update staging repeat the source and component checks before schema
migration, so malformed code or a changed helper leaves the current VPN
untouched. The four assets appear in one new release directory only after every
signature, archive, inventory, and fingerprint check passes.

The build refuses to run until `PINNED_RELEASE_KEY_SHA256` in `bootstrap.sh`
matches that key. Enable GitHub release immutability before creating the first
2.0 release. Create `v2.0.0` as a draft, attach the archive, signed manifest,
signature, and public key, then publish it only after all four assets are
present. Verify the exact public command on clean x86_64 and ARM64 fixtures
before promoting it, and record the supported scope and remaining acceptance
limits for each release.

### Owner-approved updates

Updates live under **Settings → CayVPN updates** and use four plain steps:

1. **Check for updates** reads the latest stable release from the official
   GitHub repository only when the owner asks.
2. **Download and verify** stages the immutable release, verifies the original
   offline Ed25519 trust key, exact signed file inventory, compatibility, and
   architecture-specific offline dependencies. The running VPN is unchanged.
3. **Install verified update** requires a connected trusted owner tunnel or a
   recent optional owner-login, passkey, or one-time SSH recovery confirmation.
   If the owner enabled authenticator codes, that login confirmation includes
   one. CayVPN creates a consistent rollback snapshot, pauses its services,
   applies the schema migration, atomically synchronizes every signed native
   helper, switches the active release, and verifies services, WireGuard,
   firewall state, and private HTTPS access. Any partial helper rotation is
   restored from the same snapshot.
4. If verification fails or the VPS restarts mid-install, CayVPN restores the
   previous verified release. The owner may also remove an inactive downloaded
   package without installing it.

CayVPN never silently installs an application release, never trusts a website
redirect as update metadata, never contacts PyPI from an installed production
release, and never sends update telemetry. Ubuntu security updates remain a
separate unattended-upgrades flow with automatic reboots disabled.

See [docs/updates.md](docs/updates.md) for the trust model, edge-case behavior,
and remaining release gates.

## SSH maintenance

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

`restore`, `upgrade`, `rollback`, and uninstall require explicit owner
confirmation. Restore decrypts and validates the backup before pausing CayVPN,
keeps a root-only pre-restore recovery snapshot, migrates the restored database,
reconciles routes and DNS, and returns to the previous state automatically if a
required check fails. Uninstall asks for a backup passphrase before disabling
CayVPN services.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q app.py cayvpn tests migrations
```

The Flask application is a WSGI shim over the modular package in `cayvpn/`.
The web service is unprivileged; networking changes are sent as typed JSON to
the root-owned Unix-socket agent. Alembic migrations live under `migrations/`.

## Support

CayVPN is donationware. After the one-time welcome flow has started and the
owner has created a client, the panel shows one non-blocking Caynetic support
prompt and keeps a quiet support link in the footer. It links to
[Buy Me a Coffee](https://www.buymeacoffee.com/caynetic) without third-party
scripts or tracking.

## License

MIT. See [LICENSE](LICENSE).
