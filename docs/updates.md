# CayVPN update and release design

This document records the implemented CayVPN 2.0 application-update model and
the acceptance boundaries that still require disposable Ubuntu VPS fixtures.

## Owner experience

The private panel exposes a manual flow: **Check → Download and verify → Install**.
Checking never installs anything. Downloading prepares an inactive release in
the background while the VPN keeps running. Installation requires a connected
trusted owner tunnel or a recent optional owner-login, passkey, or one-time SSH
recovery confirmation. Authenticator codes are included only when the owner
enabled that extra layer. A staged download can be removed without changing the
active VPN.

The panel polls only the local CayVPN agent while work is active. There is no
scheduled application-update check, silent application update, hosted Caynetic
control plane, telemetry, tracking script, or recurring update pop-up.

Pasting the same version-pinned bootstrap command again does not reinstall or
create a duplicate release. It verifies the existing signed release and node
health, then exits without changing files. Pasting an installer for a different
2.x version is refused; normal upgrades go through the reviewed panel flow, and
deliberate rollback remains SSH-only.

CayVPN 1.x is legacy and is not upgraded in place. A 2.0 installer refuses
known 1.x service, database, and WireGuard state before package installation,
snapshots, or other writes. Owners should keep the old VPS as their own
reference or backup, provision 2.0 on a clean Ubuntu 24.04 VPS, and recreate
client configurations manually. The supported update path begins with 2.0
and uses the signed release flow described below.

Each signed release may also include bounded owner-facing impact metadata. The
panel can show a summary, migration and compatibility notes, changed
components, an expected reconnect window, a reboot requirement, and whether
the release contains security fixes. These fields are informational and never
override signature, compatibility, or health checks.

## Trust and distribution

- Bootstrap and later discovery are restricted to stable releases from
  `caynetic/cayvpn` through the GitHub Releases API. Before downloading release
  code, the bootstrap confirms the matching tag, canonical page and assets,
  uploaded state, size, available digest, and immutable-release status. The
  updater also disables environment proxies, validates redirects, and rejects
  hosts that resolve to non-public addresses.
- Each version-pinned bootstrap hard-codes its release number, canonical
  repository, asset origin, and signing-key fingerprint. Environment variables
  cannot replace those trust roots. Development installs use `install.sh`
  directly and cannot silently weaken the public bootstrap.
- The GitHub release must be immutable. Immutable tags and assets provide a
  useful second integrity layer, but GitHub is not the CayVPN code-signing root.
- Every release contains an exact SHA-256 file inventory signed by an offline
  Ed25519 key. The original public key is pinned by the bootstrap fingerprint,
  persisted root-owned on the VPS, and compared byte-for-byte during every
  stage, install, rollback, and boot recovery.
- Each stable version has a separately reviewed, committed artifact lock that
  pins `requirements.lock`, both complete wheelhouses, every native file, and
  native build metadata. Adjacent `SHA256SUMS` files detect transfer damage;
  they cannot authorize a repacked artifact or rewritten provenance record.
- The offline builder requires an explicit Python 3.12 interpreter and runs one
  canonical full-suite, source, shell, JavaScript, and whitespace preflight
  before signing. Its four output assets appear atomically only after local
  signature, archive, inventory, and public-key fingerprint verification.
- The archive extractor rejects absolute paths, traversal, links, special files,
  duplicate files, unsigned files, oversized archives, and unexpected layouts.
- Before signing, the release builder parses every packaged Python source file
  without importing it or writing bytecode. Fresh installation and update
  staging repeat the same check before any schema migration can begin, so a
  malformed module or migration leaves the current VPN state untouched.
- Production releases contain pinned Python 3.12 wheels for Ubuntu 24.04 on
  both x86_64 and ARM64. Installation uses `--no-index --no-deps`; PyPI is not
  contacted by a production VPS during installation or update.
- Production releases also contain native x86_64 and ARM64 builds of
  AmneziaWG Go, AmneziaWG tools, hev-socks5-tunnel, and the `lego` certificate
  helper. A signed runtime lock ties every executable hash to that release.
  Fresh installation validates the complete bundle before changing the server
  and then copies all five helpers atomically into root-owned directories.
  Update activation repeats that synchronization after taking the rollback
  snapshot and while services are stopped.

  A missing, changed, or stale helper is unavailable rather than accepted from
  an older release. A VPS never downloads or builds optional networking code
  from the panel. The manually dispatched `Build optional component bundle`
  workflow builds both architectures on native Ubuntu 24.04 runners, checks
  pinned source commits and official asset digests, exercises the binaries,
  includes all license notices and the corresponding GPL-2.0 AmneziaWG tools
  source, and produces the bundle required by `scripts/build-release.sh`
  through `CAYVPN_COMPONENT_BUNDLE`.
- CayVPN records the highest release already seen or staged and refuses an
  older update through the panel. A deliberate downgrade remains an explicit
  SSH rollback operation.

The release body is presentation data, not trusted instructions. Jinja escapes
it before display, and the panel links only to the canonical matching GitHub
release page.

The root agent also hardens its local Unix-socket boundary at runtime: the
socket directory is root-owned and private to the CayVPN service group, stale
non-socket paths are refused, and each connection is checked with Linux kernel
peer credentials before a typed request is parsed. This is defense in depth;
the connected, individually revocable owner tunnel remains the simple
owner-facing management gate. Optional password login, authenticator, passkey,
and SSH recovery methods provide additional access or protection.

## Installation transaction

1. Verify the release signature, exact inventory, compatibility, architecture,
   reviewed native-component lock, complete helper bundle, and offline runtime
   import before changing active state. The currently active release is
   independently re-verified against the original trust key first.
2. Create a consistent SQLite backup through SQLite's backup API, then copy
   CayVPN configuration, installed native helpers, and WireGuard state. An
   atomic manifest marks a complete
   snapshot; restore refuses a partial or damaged snapshot before deleting any
   live path. While services are stopped, database restore removes only the
   replaced database's exact `-journal`, `-wal`, and `-shm` sidecars so journals
   from a newer database cannot be applied to the standalone snapshot. The
   copied destination must pass a fresh SQLite integrity check before services
   restart.
3. Pause the web, worker, and root agent, run schema migrations, then atomically
   synchronize every native helper from the target release's signed lock.
4. Atomically replace `/opt/cayvpn/current`, restart the services, and verify the
   root agent, all persistent services, standard/admin WireGuard interfaces,
   nftables policy, and trusted private HTTPS response.
5. Record success only after those checks pass. Otherwise restore the snapshot,
   previous active symlink, previous native helpers, and services.

After a successful upgrade or rollback, CayVPN keeps the active release, the
last known-good release, any staged release, and a small recent recovery
history. Old versioned releases and complete snapshots are pruned only after
the new state is verified; unknown files and incomplete snapshots are left for
SSH inspection. Retention cleanup is best-effort and can never make a healthy
update fail.

The update journal records each phase before a mutation begins. A boot-time
recovery service runs before the agent, worker, or web service. An interruption
before schema migration leaves the working state untouched; an interruption
after schema migration starts verifies and restores the previous signed release
and complete snapshot. Invalid recovery paths or manifests stop automatic
recovery and require SSH repair.

An SSH rollback is also journaled and requires the exact complete snapshot made
before that version was replaced. CayVPN refuses a code-only rollback because
older application code may not understand a newer database schema.

## Failure behavior

| Condition | Result |
| --- | --- |
| GitHub unavailable or rate limited | Check or download fails; active release is unchanged. |
| Mutable, draft, pre-release, missing, or malformed release | Rejected before download or installation. |
| Changed signing key, signature, checksum, or file inventory | Rejected; original pinned trust remains. |
| Missing, changed, or stale native-component lock or helper | Rejected before activation; a partial rotation restores the previous helpers. |
| Wrong OS/architecture or bridge version required | Rejected with a compatibility message. |
| Not enough disk space | Staging stops before the active release changes. |
| Concurrent update or rollback | The second operation is rejected by the filesystem lock. |
| Power loss during download | Temporary files are removed at boot; active release is unchanged. |
| Power loss before schema migration | Working release and state remain unchanged. |
| Power loss during or after schema migration | Previous signed release and complete state snapshot are restored before services start. |
| Schema migration, restart, or post-change probe fails | Automatic rollback; the panel reports whether recovery succeeded. |
| Matching database snapshot is unavailable | SSH rollback is refused before services or state change. |
| Owner changes their mind after download | Inactive staged release can be removed from Settings. |
| Owner pastes the same bootstrap command again | Existing signed installation is health-checked; no files are changed. |
| Owner pastes a different 2.x bootstrap version | Refused with directions to use the panel or explicit SSH rollback. |

## Release verification requirements

The code and local tests do not prove signer, provider, VPS, or physical-device
behavior. Before promoting the public command:

- independently review and commit the version-specific artifact lock;
- pass the canonical Python 3.12 preflight from a clean reviewed commit;
- confirm the pinned bootstrap signing key and independently verify all
  four immutable signed assets; and
- complete the x86_64 and ARM64 matrix in `DEPLOYMENT_CHECKLIST.md`, including
  real interruption, SQLite WAL load, native-component rotation, live VPN/DNS
  routing, failed-update rollback, and private-panel reconnection tests.

The 2.0 design intentionally begins with one offline release-signing key. Before
long-term key rotation or multiple release operators are needed, migrate the
metadata layer to a standard threshold-signature system such as The Update
Framework (TUF), which adds expiry, freeze protection, delegated roles, and
safe root-key rotation. Do not invent an unsigned website-based key-rotation
shortcut.

Primary references:

- [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [GitHub Releases REST API](https://docs.github.com/en/rest/releases/releases?apiVersion=latest)
- [pip repeatable installs and wheelhouses](https://pip.pypa.io/en/latest/topics/repeatable-installs/)
- [The Update Framework specification](https://theupdateframework.github.io/specification/v1.0.26/)
- [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)
