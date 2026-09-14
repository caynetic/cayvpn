# CayVPN 2.0 deployment checklist

This is an operator checklist, not a provider automation guide. The VPS owner
creates, resizes, pays for, and attaches addresses through the provider portal.

## Before installation

- [ ] Ubuntu 24.04 on x86_64 or ARM64.
- [ ] SSH key access works and an offline recovery path is available.
- [ ] The intended public IPv4, public IPv6 for dual-stack acceptance, outbound
      interface, plan name, transfer limit, and port speed are recorded.
- [ ] The server's ED25519 SSH fingerprint is independently confirmed through
      the provider console before a rebuilt host key is accepted locally.
- [ ] The release directory contains the pinned CayVPN bundle.
- [ ] The Ed25519 release public key, signed manifest, and checksum manifest are
      available.
- [ ] The reviewed native-component bundle and committed version-specific
      artifact lock are available for both architectures.
- [ ] No provider API key is placed in CayVPN configuration.

## Public one-command release

- [ ] Enable immutable releases for the `caynetic/cayvpn` repository before
      creating any 2.0 release; this setting applies only to future releases.
- [ ] Generate both Python 3.12 wheelhouses with
      `scripts/prepare-wheelhouse.sh`; verify that each locked requirement has
      an x86_64 and ARM64 wheel and that `SHA256SUMS` passes from its directory.
- [ ] Build both architecture-native helper bundles with the pinned workflow;
      inspect their source commits, licenses, provenance, and executable tests.
- [ ] Independently review and commit `release-locks/<version>.json` before
      transferring artifacts. Confirm it exactly pins both wheelhouses, every
      component file, component build metadata, and `requirements.lock`.
- [ ] Run `scripts/build-release.sh` from that clean commit with an explicit
      Python 3.12 interpreter. Confirm its canonical preflight passes before the
      signing command is reached.
- [ ] Confirm the builder and installer reject deliberately malformed Python
      source, including files hidden in nested `venv` or `wheelhouse`
      directories, before signing or schema migration.
- [ ] Confirm repacked wheels or components remain rejected even when their
      adjacent transport checksums and provenance files are rewritten.
- [ ] Confirm the build rejects a bootstrap whose hard-coded version does not
      exactly match the release being built.
- [ ] Keep the Ed25519 private signing key outside the repository and CI logs.
- [ ] Pin the release public-key SHA-256 in `bootstrap.sh`; confirm the release
      build rejects a different signing key.
- [ ] Confirm the builder publishes no partial output: one new directory with
      exactly four assets appears only after every local verification passes.
- [ ] Upload `cayvpn-<version>.tar.gz`, its `.sha256` manifest, the `.sig`, and
      `cayvpn-release.pub` to a draft matching GitHub release tag, then publish
      it only after all assets are present.
- [ ] Confirm the release API reports `immutable: true`, all four assets report
      `state: uploaded`, and every available GitHub asset digest matches.
- [ ] Exercise bootstrap verification against a safe signed pre-publication
      fixture. Immediately after immutable publication, run the exact
      version-pinned command on clean x86_64 and ARM64 fixtures before promotion.
- [ ] Confirm the bootstrap rejects a changed archive, manifest, signature,
      unlisted file, symbolic link, unsafe archive path, mutable release, or
      canonical-asset mismatch before release code runs.
- [ ] Confirm the installer rejects a missing, changed, or incomplete signed
      native-component lock before server changes and installs all five helpers
      with hashes bound to the active release on both architectures.
- [ ] Paste the exact command a second time and confirm it performs a signed
      health check without creating another release directory or changing
      state; confirm a different 2.x bootstrap version directs the owner to the
      panel instead of bypassing upgrade or rollback controls.

## Installer gates

- [ ] `install.sh` passes platform and resource checks.
- [ ] Before package installation, the clean-VPS preflight refuses existing
      firewall rules, Nginx sites, dnsmasq configuration, AdGuard Home, VPN
      services, or non-empty CayVPN paths without changing them.
- [ ] A root-private snapshot under `/var/backups/cayvpn/` records exact file,
      interface, and service-state inventory and verifies before `apt-get` runs.
- [ ] Force failures after package installation and after migration. Confirm all
      restorable files and service states match the snapshot, the result is
      `restored_and_verified`, and any remaining packages are reported candidly.
- [ ] The release is installed under a versioned directory and `/opt/cayvpn/current`
      is switched atomically.
- [ ] All five native helpers match the hashes in the active signed component
      lock; a partial helper rotation restores the previous verified copies.
- [ ] Alembic reaches the current migration head.
- [ ] `wg0` and `wg-admin` keys are preserved or created with mode `0600`.
- [ ] One random RFC 4193 `/48` is generated and persisted, with distinct `/64`
      networks for standard clients, Amnezia clients, exit transport, and DNS.
- [ ] Re-running installation preserves the existing ULA layout rather than
      changing client addresses.
- [ ] The admin panel is bound only to `10.255.0.1:8443` on a fresh install.
- [ ] Public input exposes SSH and the configured client UDP ports; TCP 80/443
      remain closed until the owner explicitly enables From anywhere access.
- [ ] The initial admin configuration and trust certificate are copied to an
      offline owner device.
- [ ] The owner kit is created with mode `0600`, the displayed QR imports, and
      the printed `scp` command works for the invoking SSH user.
- [ ] `cayvpnctl verify` passes before provisioning is called complete.
- [ ] The agent socket directory is root-owned with mode `0750`, the socket is
      `0660`, and an unauthorized local credential is rejected.
- [ ] A CayVPN 1.x service, known `wg.db`, or existing CayVPN WireGuard state is
      detected before packages, snapshots, or files are changed.
- [ ] The installer exits with a clear clean-VPS message and leaves the legacy
      service, panel, keys, firewall, and database untouched.
- [ ] A clean 2.0 install never opens a public password panel, TCP 80/443, or a
      temporary migration port before the owner completes the gated remote
      access wizard.

## First private-panel session

- [ ] Import the initial admin tunnel.
- [ ] Open the owner-kit URL through that tunnel at `8443`.
- [ ] Confirm the registered admin tunnel can use protected controls directly
      without a password, authenticator code, or passkey.
- [ ] Confirm the same controls remain blocked for an unregistered admin-network
      address and for an ordinary client without optional owner login.
- [ ] Confirm optional owner-login setup defaults to password-only, creates no
      authenticator secret, and works without registering a passkey.
- [ ] Repeat optional owner-login setup with the authenticator choice enabled;
      confirm its encrypted secret and code verification work.
- [ ] If the optional passkey shortcut ships, register it on at least two owner
      devices and verify it can replace the typing step without becoming an
      onboarding requirement.
- [ ] Confirm the welcome prompt appears once and leads to Security.
- [ ] Confirm the support prompt waits until onboarding starts and a client
      exists, appears once, and never blocks management.
- [ ] Add a named admin device and verify its individual configuration.
- [ ] Revoke a test admin device and verify that its tunnel and session stop
      working.
- [ ] Confirm revocation deletes the admin device's encrypted private key.
      Simulate secret deletion failure and verify the revoked device retains a
      non-secret Finish cleanup action until a successful retry.
- [ ] Navigate through at least 60 authenticated private-panel requests without
      a lockout; separately confirm unauthenticated browsing and password and
      approval attempts retain their configured rate limits.
- [ ] Confirm the public address cannot reach the panel before opt-in remote
      access is enabled.
- [ ] Complete owner-login setup in private-to-CayVPN mode; verify password-only
      sign-in at `https://10.255.0.1:8443`, then repeat with the optional
      authenticator enabled, while TCP 80/443 remain closed publicly.
- [ ] Complete owner-login setup in From anywhere mode only after the owner
      accepts the certificate agreement. Verify the publicly trusted IP
      certificate, TCP 80 challenge/redirect behavior, TCP 443 login, login
      rate limits, API rejection before authentication, and fresh password
      confirmation for sensitive actions, including the optional authenticator
      when enabled.
- [ ] Disable From anywhere access and confirm TCP 80/443 close, remote sessions
      stop, and the private admin tunnel still works.
- [ ] Complete and resume the Add Client, Add Exit, and Failover Pool wizards
      using browser Back, keyboard navigation, and JavaScript disabled.
- [ ] Confirm each wizard shows progress, preserves non-secret answers, and
      removes its 24-hour draft on cancel, completion, or expiration.
- [ ] Confirm imported configurations and passwords never appear in a URL,
      cookie, log, operation API, draft JSON, Back page, or review page.
- [ ] Simulate root-secret deletion failure and confirm the draft and secret
      reference are retained for a safe retry.
- [ ] Remove a temporary client and confirm its peer, policy routes, route
      binding, and encrypted private key are all removed. Simulate private-key
      deletion failure and confirm the disabled client plus blocked binding are
      retained until a successful retry.

## Exits and routing

- [ ] Keep the direct VPS IP as an explicit profile; it is not an implicit
      fallback.
- [ ] For an additional/reserved IP, attach it at the provider first, record
      each address/prefix/gateway/interface, and confirm the observed source and
      exact outbound interface for both enabled families.
- [ ] Confirm the additional-IP wizard rejects the built-in VPS address and an
      address already saved as another exit; neither is an independent backup.
- [ ] Create only owner-approved failover pools.
- [ ] Confirm route changes warn about connection resets and leave a prohibit
      route until the post-change probe passes.
- [ ] Confirm two clients sharing one exit have separate policy tables and that
      blocking or switching one does not block the other.
- [ ] Capture a real packet path through each direct/additional-IP namespace and
      confirm it reaches the provider interface once, without a veth routing
      loop or host-default bypass.
- [ ] Confirm a new or unassigned client cannot use the VPS default route before
      an explicit exit assignment is verified.
- [ ] Confirm an inactive exit blocks traffic rather than falling back directly.
- [ ] Do not activate SOCKS5/provider tunnel profiles until their vetted isolated
      runtime component is installed and capability checks pass.
- [ ] Verify IPv4 and IPv6 TCP, DNS, UDP capability, public identity, route, and
      health independently for every active exit. A and AAAA probes must return
      real answers through that exit.
- [ ] Confirm IPv4 and IPv6 always use the same selected exit and cannot bypass
      its namespace or tunnel through the host default route.
- [ ] Confirm IPv6-only additional and provider exits are rejected before any
      route, interface, firewall, or secret ownership change.
- [ ] Break only IPv6 on each exit. Smart IPv6 must keep IPv4 active and install
      an explicit IPv6 prohibit route; it must not switch the whole exit.
- [ ] Repeat with Require IPv6. Both families must block or move in order to a
      different verified dual-stack exit, with no automatic return to primary.
- [ ] Confirm three failures and two successes are applied independently per
      family, and that UDP remains independently reported and blocked.
- [ ] Confirm the client DNS address is the stable CayVPN resolver address and
      that standard queries use encrypted upstream transport inside the exit
      namespace; resolver failure must return failure, not the VPS resolver.
- [ ] Confirm a newly created client retains working DNS without silently using
      the host resolver.

## Backup and recovery

- [ ] Create a passphrase-encrypted backup after installation and after each
      material configuration change.
- [ ] Store a copy off the VPS and verify its SHA-256 record.
- [ ] Test restore on a disposable Ubuntu 24.04 fixture.
- [ ] Confirm `cayvpnctl restore /path/to/backup --confirm` validates before
      pausing services, preserves service ownership and executable components,
      reconciles routes and DNS, and restores its pre-restore snapshot after a
      deliberate migration or verification failure.
- [ ] Confirm restore reports when the public endpoint changed.
- [ ] Keep SSH and admin-tunnel recovery available; do not rely on optional
      public owner login as the only recovery path.
- [ ] Test `cayvpnctl status`, `verify`, `repair`, and `diagnostics`.

## Release acceptance

- [ ] In the private panel, check manually and review the signed release notes,
      schema changes, component changes, compatibility, and expected
      connection interruption.
- [ ] Download and verify without changing the active release; confirm the
      inactive download can be removed cleanly.
- [ ] Install through the connected trusted owner tunnel, a recent optional
      owner-login confirmation (including an authenticator only when enabled),
      an optional passkey, or run
      `cayvpnctl upgrade --release <version> --confirm` over SSH.
- [ ] Verify service health, private panel access, client connectivity, and
      route/DNS behavior.
- [ ] Confirm a failed verification automatically restores the previous release.
- [ ] Confirm `cayvpnctl rollback --confirm` restores a known-good release only
      with its matching complete pre-upgrade database snapshot, and refuses a
      code-only rollback before stopping services.
- [ ] Enable Ubuntu security updates without automatic reboot and record reboot
      requirements.
- [ ] Confirm an older-than-known release, changed trust key, mutable release,
      wrong architecture, unsupported OS, unsigned extra file, unsafe archive
      path, low-disk condition, concurrent update, and GitHub outage all fail
      without changing the active release.
- [ ] Interrupt staging, installation before schema migration, schema migration,
      symlink switching, and service verification; reboot after each interruption
      and confirm recovery restores the previous signed release deterministically
      and fail-closed.
- [ ] Fill the disk during snapshot creation and confirm the incomplete snapshot
      is refused without deleting the live database, configuration, or keys.
- [ ] Exercise SQLite WAL writes during snapshot creation and confirm the
      restored database contains every committed record and passes quick-check.
- [ ] Confirm the update panel escapes untrusted release-note markup and is
      reachable only through an authenticated, owner-approved admin path.
- [ ] Confirm a legacy 1.x fixture is refused before any package install,
      snapshot, service stop, firewall change, or database write.

## Required test matrix

Run the full matrix on clean Ubuntu 24.04 x86_64 and ARM64 fixtures:

- fresh install, repair, upgrade, failed-upgrade rollback, uninstall;
- legacy 1.x refusal with existing client keys and addresses left untouched;
- standard WireGuard and AmneziaWG ingress;
- direct IP, additional IP, provider WireGuard/AmneziaWG, and SOCKS5 exits;
- IPv4-only and dual-stack forms of every supported exit; IPv6-only rejection;
- external IPv4/IPv6 identity, A/AAAA DNS, TCP, UDP, and explicit leak checks;
- TCP-only SOCKS5 fail-closed behavior for UDP/QUIC, IPv6, and DNS, plus
  repeated SOCKS5 IPv6 TCP/DNS/UDP checks before the IPv6 TUN is enabled;
- exit failure, ordered failover, deliberate failback, and atomic route switch;
- deliberate IPv6 breakage proving Smart and Require IPv6 behavior;
- reboot and desired/observed-state reconciliation with both families;
- malicious imported config fields, hooks, metadata endpoints, private targets,
  DNS rebinding, and command injection;
- closed-by-default public-panel rejection, opt-in remote HTTPS
  enable/renew/disable rollback, admin-peer revocation, owner-confirmation and
  recovery gates, optional passkeys,
  capacity recalculation, backup restoration, and one-time support prompt;
- macOS, iOS, and Android client acceptance where applicable.

Do not publish provisioning instructions, the public installer command, or
signed packages until this matrix passes, the signing-key placeholder is
replaced, immutable assets are independently verified, and every first-use VPS
fingerprint is confirmed through its provider.
