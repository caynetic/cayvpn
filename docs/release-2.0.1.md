# CayVPN 2.0.1

This patch fixes the public bootstrap on Ubuntu 24.04. Reading the operating
system identity previously replaced CayVPN's release version, causing 2.0.0
to reject its correctly signed archive before running the installer. The
platform check now runs in an isolated shell environment.

Four process-level regression checks cover the real bootstrap flow: a valid
signed archive on Ubuntu, mutable release rejection, invalid signature
rejection even when transport digests match, and unsupported OS rejection.

Use 2.0.1 for new installations. Version 2.0.0 is superseded; its immutable
release remains available for traceability. No keys or server configuration
need recovery from the failed 2.0.0 bootstrap because installation never began.

```bash
curl -fsSL https://raw.githubusercontent.com/caynetic/cayvpn/v2.0.1/bootstrap.sh | sudo bash
```

The [2.0 release notes](release-2.0.0.md) describe the management panel, routing,
DNS and IPv6 controls, signing, backup and recovery, installation requirements,
and acceptance limits. Dependencies and VPN runtime behavior are unchanged
by this patch. Use a clean dedicated Ubuntu 24.04 x86_64 or ARM64 server;
CayVPN 1.x and private acceptance builds are not upgraded in place.
