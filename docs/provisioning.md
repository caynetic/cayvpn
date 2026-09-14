# Future user-owned provisioning design

This is a gated design record, not published setup instructions and not an
implemented hosted service. Public provisioning work starts only after CayVPN's
dual-stack live acceptance and signed-release gates pass.

## Safety boundary

CayVPN must never ask an owner to upload an SSH password, SSH private key,
provider API token, WireGuard configuration, or owner kit to a Caynetic website.
The installation server remains user-owned, and privileged setup runs either on
that server or locally on the owner's computer.

There is one installer source of truth: the version-pinned bootstrap that
verifies an immutable release, its Ed25519 signature, and its exact file
inventory. Cloud-init, a provider image, and any desktop helper must invoke that
installer instead of copying its installation logic.

## First guided version after release gates

1. Choose DigitalOcean or generic Ubuntu 24.04.
2. Create a VPS with IPv4, IPv6, and the owner's SSH public key.
3. Choose either provider user data or a signed command to paste into the
   owner's own SSH session.
4. Wait for the install and follow non-secret health-check instructions.
5. Retrieve the owner kit locally over SSH and import it on the owner's device.

A static setup page may assemble those choices in the browser, but it sends no
credentials or private configuration to a server. A later open-source desktop
assistant may run SSH locally, verify the server fingerprint independently,
use the operating-system keychain for key access, retrieve the owner kit
locally, and remove temporary access.

Hosted SSH execution, provider-token custody, temporary public owner-kit links,
IPv6-only exits, and NAT64 remain out of scope unless separately threat-modeled
and approved.

## Delivery gates

Do not publish a provisioning flow until all of these are true:

- the bootstrap signing-key placeholder is replaced with the independently
  verified public-key fingerprint;
- immutable signed release assets and attestations are independently verified;
- the full x86_64, ARM64, ingress, exit, dual-stack, failover, reboot,
  reconciliation, update/rollback, and backup/restore matrix passes;
- macOS, iOS, and Android owner/client acceptance passes where applicable; and
- provider-side server fingerprints are independently confirmed before first
  SSH trust is established.

The eventual user interface should use short, resumable pages with progress,
preserved answers, Back/Continue controls, a review page, accessible errors,
keyboard operation, and a non-JavaScript path. See
[W3C multi-page form guidance](https://www.w3.org/WAI/tutorials/forms/multi-page/),
[DigitalOcean user data](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/),
[DigitalOcean IPv6](https://docs.digitalocean.com/products/networking/ipv6/how-to/enable/),
[DigitalOcean Marketplace](https://docs.digitalocean.com/products/marketplace/),
[GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
[Outline advanced setup](https://developer.getoutline.org/vpn/getting-started/server-setup-advanced/),
and [Algo](https://github.com/trailofbits/algo).
