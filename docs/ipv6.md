# CayVPN dual-stack design

This document describes the locally implemented CayVPN 2.0 IPv6 contract. It
does not claim live provider or device acceptance.

## Addressing and compatibility

- A fresh installation generates one random RFC 4193 ULA `/48` and persists it
  in node configuration. Stable, non-overlapping `/64` networks are derived for
  standard WireGuard clients, AmneziaWG clients, exit transport, and internal
  DNS.
- Each client receives one stable IPv6 `/128`. Existing client keys and IPv4
  addresses are preserved by the additive migration. Existing downloaded
  configurations keep working, while the panel offers a one-time IPv6 refresh
  and records generated versus owner-confirmed configuration generations.
- Generated client configurations contain one IPv4 `/32`, one IPv6 `/128`, and
  exactly `0.0.0.0/0, ::/0`. The public client endpoint and `wg-admin` remain
  IPv4-only for this phase.
- IPv4-only and dual-stack exits are supported. IPv6-only exits and NAT64 are
  rejected before networking changes begin.

## One exit for both families

CayVPN never selects one exit for IPv4 and another for IPv6. Policy rules,
routes, firewall state, connection cleanup, namespace links, and NAT are
reconciled together for the selected exit.

- Direct and additional-address exits require the configured source address,
  exact outbound interface when known, live TCP and DNS, and a matching public
  address for each enabled family.
- Provider WireGuard and AmneziaWG require an IPv4 interface address and
  `0.0.0.0/0`. IPv6 is enabled only when the provider configuration also has an
  IPv6 interface address, `::/0`, the exact tunnel route, and successful live
  family checks.
- SOCKS5 enables its IPv6 TUN only after repeated IPv6 CONNECT and DNS checks.
  IPv4 and IPv6 UDP are measured independently and remain blocked unless the
  corresponding repeated relay checks pass.
- DNS probes require actual A and AAAA answers through the selected exit.
  Intentional ad-blocking NXDOMAIN remains valid only for the local resolver
  path, not as evidence that an exit can resolve public names.

The API retains the previous flat `tcp`, `udp`, `dns`, and observed-IP fields as
IPv4-compatible aliases. New callers use `families.ipv4`, `families.ipv6`,
`observed_exit_ipv4`, `observed_exit_ipv6`, and per-family health data.

## Smart IPv6 and Require IPv6

**Smart IPv6** is the default. IPv4 remains active if the selected exit loses
IPv6, but the client's IPv6 policy table receives an explicit prohibit route.
IPv6 failure alone does not change the selected exit.

**Require IPv6** allows only verified dual-stack candidates. IPv6 failure
blocks both families and triggers ordered failover when another verified
dual-stack exit is present. If every approved candidate fails, both families
remain blocked. Returning to the preferred exit is manual.

IPv4 and IPv6 retain independent three-failure and two-success health
thresholds. UDP remains separately reported and cannot make an otherwise
unverified family usable.

## Live acceptance still required

Local tests cover migration, deterministic addressing, malformed imports,
family-specific capabilities, typed route actions, NAT/firewall construction,
Smart/Require behavior, wizard refresh, and rollback-oriented failure paths.
Release acceptance still requires an owner-approved disposable VPS with public
IPv6 and the complete matrix in `DEPLOYMENT_CHECKLIST.md`.

References: [RFC 4193](https://www.rfc-editor.org/info/rfc4193),
[wg-quick](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg-quick.8),
[SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928), and
[hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel).
