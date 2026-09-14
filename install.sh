#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

log() { printf '[cayvpn] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; return 1; }
[[ "${EUID}" -eq 0 ]] || die "Run this installer as root."

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RELEASE_VERSION="${CAYVPN_RELEASE_VERSION:-2.0.0-dev}"
INSTALL_ROOT="${CAYVPN_INSTALL_ROOT:-/opt/cayvpn}"
RELEASE_DIR="${INSTALL_ROOT}/releases/${RELEASE_VERSION}"
RELEASE_STAGING_DIR=""
ACTIVE_RELEASE="${INSTALL_ROOT}/current"
STATE_DIR="${CAYVPN_STATE_DIR:-/var/lib/cayvpn}"
CONFIG_DIR="${CAYVPN_CONFIG_DIR:-/etc/cayvpn}"
SNAPSHOT_ROOT="${CAYVPN_SNAPSHOT_ROOT:-/var/backups/cayvpn}"
ENV_FILE="${CONFIG_DIR}/cayvpn.env"
WG_DIR="${CAYVPN_WG_DIR:-/etc/wireguard}"
WG_IFACE="${CAYVPN_USER_INTERFACE:-wg0}"
WG_PORT="${CAYVPN_USER_PORT:-43210}"
WG_ADDRESS="${CAYVPN_USER_ADDRESS:-10.8.0.1/24}"
WG_NETWORK="${CAYVPN_USER_NETWORK:-10.8.0.0/24}"
ULA_PREFIX="${CAYVPN_ULA_PREFIX:-}"
WG_NETWORK_V6="${CAYVPN_USER_NETWORK_V6:-}"
WG_ADDRESS_V6="${CAYVPN_USER_ADDRESS_V6:-}"
AWG_IFACE="${CAYVPN_AMNEZIA_INTERFACE:-awg0}"
AWG_PORT="${CAYVPN_AMNEZIA_PORT:-43211}"
AWG_ADDRESS="${CAYVPN_AMNEZIA_ADDRESS:-10.9.0.1/24}"
AWG_NETWORK="${CAYVPN_AMNEZIA_NETWORK:-10.9.0.0/24}"
AWG_NETWORK_V6="${CAYVPN_AMNEZIA_NETWORK_V6:-}"
AWG_ADDRESS_V6="${CAYVPN_AMNEZIA_ADDRESS_V6:-}"
EGRESS_NETWORK_V4="${CAYVPN_EGRESS_NETWORK_V4:-100.64.0.0/10}"
EGRESS_NETWORK_V6="${CAYVPN_EGRESS_NETWORK_V6:-}"
CLIENT_DNS_V6="${CAYVPN_CLIENT_DNS_ADDRESS_V6:-}"
CLIENT_ADBLOCK_DNS_V6="${CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS_V6:-}"
PUBLIC_IPV6="${CAYVPN_PUBLIC_IPV6:-}"
ADMIN_IFACE="${CAYVPN_ADMIN_INTERFACE:-wg-admin}"
ADMIN_PORT="${CAYVPN_ADMIN_PORT:-51821}"
ADMIN_ADDRESS="${CAYVPN_ADMIN_ADDRESS:-10.255.0.1/24}"
ADMIN_NETWORK="${CAYVPN_ADMIN_NETWORK:-10.255.0.0/24}"
ADMIN_HOSTNAME="${CAYVPN_ADMIN_HOSTNAME:-admin.cayvpn.home.arpa}"
ADMIN_SEARCH_DOMAIN="${ADMIN_HOSTNAME#*.}"
if [[ "${ADMIN_SEARCH_DOMAIN}" == "${ADMIN_HOSTNAME}" ]]; then
  ADMIN_SEARCH_DOMAIN="${ADMIN_HOSTNAME}"
fi
ADMIN_HTTPS_PORT="${CAYVPN_ADMIN_HTTPS_PORT:-8443}"
REMOTE_ADMIN_PORT="${CAYVPN_REMOTE_ADMIN_PORT:-443}"
REMOTE_ADMIN_ACME_SERVER="${CAYVPN_REMOTE_ADMIN_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
REMOTE_ADMIN_ACME_PROFILE="${CAYVPN_REMOTE_ADMIN_ACME_PROFILE:-shortlived}"
ADMIN_IP=""
ADMIN_CLIENT_IP=""
ADMIN_CLIENT_ADDRESS=""
OUT_IFACE="${CAYVPN_OUT_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk 'match($0,/ dev [^ ]+/){print substr($0,RSTART+5,RLENGTH-5); exit}')}"
SNAPSHOT_PATH=""
PREVIOUS_RELEASE=""
OWNER_KIT_PATH=""
OWNER_KIT_USER=""
RECOVERY_PASSPHRASE=""
PROXY_TOKEN=""
INITIAL_ADMIN_CREATED=0
NEW_RELEASE_INSTALLED=0
ADBLOCK_FILTER_COMMIT="38b5bef725cfef567a74774e82de1fd9b4ec7672"
ADBLOCK_FILTER_SHA256="abdad412469538086bfe828dc881e74bf9cffbc5d07b543f45f337977827e687"
ADBLOCK_FILTER_URL="https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/${ADBLOCK_FILTER_COMMIT}/assets/filter_1.txt"

[[ "${OUT_IFACE}" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || die "Set CAYVPN_OUT_IFACE; the outbound interface could not be detected."

run_release_python() {
  (
    cd -- "${ACTIVE_RELEASE}"
    PYTHONDONTWRITEBYTECODE=1 "${ACTIVE_RELEASE}/.venv/bin/python" "$@"
  )
}

check_platform() {
  [[ -r /etc/os-release ]] || die "Ubuntu 24.04 is required."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || die "CayVPN 2.0 supports Ubuntu 24.04 only."
  case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) die "Only amd64 and arm64 are supported." ;; esac
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)' \
    || die "CayVPN releases require Ubuntu 24.04's Python 3.12 runtime."
}

check_release() {
  [[ "${RELEASE_VERSION}" =~ ^[-A-Za-z0-9._]+$ ]] || die "Invalid release identifier."
  [[ -f "${SOURCE_DIR}/requirements.txt" ]] || die "Run from a CayVPN source or release directory."
  if [[ -n "${CAYVPN_RELEASE_MANIFEST:-}" && -n "${CAYVPN_RELEASE_SIGNATURE:-}" && -n "${CAYVPN_RELEASE_PUBLIC_KEY:-}" ]]; then
    local digest manifest_path content_dir manifest_files content_files manifest_line filename
    manifest_path="$(readlink -f -- "${CAYVPN_RELEASE_MANIFEST}")"
    digest="$(sha256sum "${CAYVPN_RELEASE_MANIFEST}" | awk '{print $1}')"
    [[ -z "${CAYVPN_RELEASE_DIGEST:-}" || "${digest}" == "${CAYVPN_RELEASE_DIGEST}" ]] || die "Release manifest digest mismatch."
    openssl pkeyutl -verify -rawin -pubin -inkey "${CAYVPN_RELEASE_PUBLIC_KEY}" -sigfile "${CAYVPN_RELEASE_SIGNATURE}" -in "${CAYVPN_RELEASE_MANIFEST}" >/dev/null || die "Release manifest signature failed."
    content_dir="${CAYVPN_RELEASE_CONTENT_DIR:-$(dirname -- "${manifest_path}")}"
    [[ -d "${content_dir}" ]] || die "Release content directory was not found."

    # A valid checksum list is not enough by itself: an archive could contain
    # an additional unsigned Python module, migration, or installer helper.
    # Require the signed manifest and the complete regular-file inventory to
    # match exactly, and reject links or special files before executing any
    # release code.
    [[ -z "$(find "${content_dir}" -type l -print -quit)" ]] || die "Release content contains a symbolic link."
    [[ -z "$(find "${content_dir}" -mindepth 1 ! -type d ! -type f -print -quit)" ]] || die "Release content contains an unsupported file type."
    manifest_files="$(mktemp)"
    content_files="$(mktemp)"
    while IFS= read -r manifest_line; do
      if [[ "${manifest_line}" =~ ^([0-9a-fA-F]{64})[[:space:]]+\*?([A-Za-z0-9._/-]+)$ ]]; then
        filename="${BASH_REMATCH[2]}"
      else
        rm -f -- "${manifest_files}" "${content_files}"
        die "Release manifest contains an unsafe entry."
      fi
      if [[ "${filename}" == /* || "${filename}" == ".." || "${filename}" == ../* || "${filename}" == */../* ]]; then
        rm -f -- "${manifest_files}" "${content_files}"
        die "Release manifest contains an unsafe entry."
      fi
      printf '%s\n' "${filename#./}" >> "${manifest_files}"
    done < "${CAYVPN_RELEASE_MANIFEST}"
    LC_ALL=C sort -o "${manifest_files}" "${manifest_files}"
    (cd "${content_dir}" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort) > "${content_files}"
    if ! cmp -s "${manifest_files}" "${content_files}"; then
      rm -f -- "${manifest_files}" "${content_files}"
      die "Release content contains missing or unlisted files."
    fi
    rm -f -- "${manifest_files}" "${content_files}"
    (cd "${content_dir}" && sha256sum --check --strict "${manifest_path}" >/dev/null) || die "Release checksum verification failed."
  else
    [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" ]] || die "A signed release manifest is required. Set CAYVPN_ALLOW_UNVERIFIED_LOCAL=1 only for local development."
    log "Unverified local development mode enabled."
  fi
}

validate_release_source() {
  [[ -f "${SOURCE_DIR}/scripts/validate-python-source.py" ]] \
    || die "The release source validator is missing."
  if ! PYTHONDONTWRITEBYTECODE=1 python3 \
    "${SOURCE_DIR}/scripts/validate-python-source.py" "${SOURCE_DIR}"; then
    die "Release Python source validation failed before any server changes."
  fi
  if [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" != "1" ]]; then
    [[ -f "${SOURCE_DIR}/components.lock.json" ]] \
      || die "The signed release is missing its native-component lock."
    if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${SOURCE_DIR}" python3 - "${SOURCE_DIR}" <<'PY'
import sys
from pathlib import Path

from cayvpn.components import validate_release_components
from cayvpn.config import Settings

source = Path(sys.argv[1])
validate_release_components(Settings.from_env(source), source)
PY
    then
      die "The signed native-component bundle failed validation before any server changes."
    fi
  fi
}

handle_existing_v2_install() {
  local active_path release_root
  [[ -e "${ACTIVE_RELEASE}" || -L "${ACTIVE_RELEASE}" ]] || return 0
  [[ -L "${ACTIVE_RELEASE}" ]] || die "An existing CayVPN 2.0 active path is not a safe symbolic link. Use SSH recovery before reinstalling."
  active_path="$(readlink -f -- "${ACTIVE_RELEASE}" 2>/dev/null || true)"
  release_root="$(readlink -f -- "${INSTALL_ROOT}/releases" 2>/dev/null || printf '%s' "${INSTALL_ROOT}/releases")"
  [[ -n "${active_path}" && "${active_path}" == "${release_root}/"* && -d "${active_path}" ]] \
    || die "The existing CayVPN active release is outside the versioned release directory. Use SSH recovery before reinstalling."
  if [[ "${active_path}" != "${RELEASE_DIR}" ]]; then
    die "CayVPN $(basename -- "${active_path}") is already installed. Use Settings > CayVPN updates for a new version, or cayvpnctl rollback over SSH for a deliberate rollback."
  fi
  [[ -x /usr/local/bin/cayvpnctl ]] || die "CayVPN ${RELEASE_VERSION} is already present but its maintenance command is missing. Use SSH recovery instead of overwriting it."
  log "CayVPN ${RELEASE_VERSION} is already installed. Running its signed health check instead of reinstalling it."
  /usr/local/bin/cayvpnctl verify \
    || die "The existing installation needs attention. Run sudo cayvpnctl diagnostics over SSH; no files were changed."
  log "The existing CayVPN ${RELEASE_VERSION} installation passed verification. No files were changed."
  exit 0
}

refuse_legacy_install() {
  local legacy_unit candidate
  if [[ -n "${CAYVPN_LEGACY_DB:-}" || -n "${CAYVPN_LEGACY_SECRET_KEY_FILE:-}" ]]; then
    die "CayVPN 1.x migration variables are no longer supported. Provision a clean Ubuntu 24.04 VPS for CayVPN 2.0; no files were changed."
  fi

  legacy_unit="$(systemctl show -p FragmentPath --value cayvpn.service 2>/dev/null || true)"
  if [[ -n "${legacy_unit}" && "${legacy_unit}" != "/dev/null" && -f "${legacy_unit}" ]]; then
    die "CayVPN 1.x is legacy and is not upgraded in place. No files were changed. Keep the old VPS as-is and provision a clean Ubuntu 24.04 VPS for CayVPN 2.0."
  fi

  for candidate in "${SOURCE_DIR}/wg.db" /root/cayvpn/wg.db /opt/cayvpn/wg.db /var/lib/cayvpn/wg.db /var/lib/cayvpn/legacy-wg.db; do
    if [[ -f "${candidate}" ]]; then
      die "CayVPN 1.x state was detected at ${candidate}. It is legacy and is not imported or upgraded. No files were changed; provision a clean Ubuntu 24.04 VPS for CayVPN 2.0."
    fi
  done

  if [[ -d "${WG_DIR}" && -n "$(find "${WG_DIR}" -maxdepth 1 -type f -print -quit 2>/dev/null)" ]]; then
    die "An existing WireGuard installation was detected. CayVPN 2.0 requires a clean VPS and will not overwrite existing VPN state; no files were changed."
  fi
  if [[ -f "${ENV_FILE}" ]]; then
    die "Existing CayVPN configuration was detected at ${ENV_FILE}. CayVPN 2.0 does not reinstall over an incomplete or legacy node; use SSH recovery or provision a clean VPS. No files were changed."
  fi
}

check_resources_and_conflicts() {
  local memory_mb disk_kb listening conflicts unit port managed existing awg_tool
  memory_mb="$(awk '/^MemTotal:/{print int($2/1024); exit}' /proc/meminfo 2>/dev/null || printf '0')"
  disk_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
  [[ "${memory_mb}" -ge 512 ]] || die "At least 512 MiB of memory is required for the installer preflight."
  [[ "${disk_kb}" -ge 5242880 ]] || die "At least 5 GiB of free disk space is required for CayVPN and recovery snapshots."
  command -v ip >/dev/null || die "iproute2 is required before platform setup can continue."
  command -v ss >/dev/null || die "ss is required before port checks can continue."
  listening="$(ss -H -lntup 2>/dev/null || true)"
  # Public HTTPS is optional and starts closed.  Do not make an unrelated
  # service on port 443 block the private, admin-tunnel-only installation.
  # The remote-access wizard performs its own preflight before opening 443.
  for port in "${WG_PORT}" "${AWG_PORT}" "${ADMIN_PORT}" "${ADMIN_HTTPS_PORT}"; do
    if grep -Eq "[:.]${port}[[:space:]]" <<<"${listening}"; then
      managed=0
      if [[ "${port}" == "${WG_PORT}" ]] && command -v wg >/dev/null 2>&1; then
        existing="$(wg show "${WG_IFACE}" listen-port 2>/dev/null || true)"
        [[ "${existing}" == "${port}" ]] && managed=1
      fi
      if [[ "${port}" == "${ADMIN_PORT}" ]] && command -v wg >/dev/null 2>&1; then
        existing="$(wg show "${ADMIN_IFACE}" listen-port 2>/dev/null || true)"
        [[ "${existing}" == "${port}" ]] && managed=1
      fi
      if [[ "${port}" == "${AWG_PORT}" ]]; then
        existing="$(wg show "${AWG_IFACE}" listen-port 2>/dev/null || true)"
        [[ "${existing}" == "${port}" ]] && managed=1
        for awg_tool in "${CONFIG_DIR}"/components/amneziawg/*/awg; do
          [[ -x "${awg_tool}" ]] || continue
          existing="$("${awg_tool}" show "${AWG_IFACE}" listen-port 2>/dev/null || true)"
          [[ "${existing}" == "${port}" ]] && managed=1
        done
      fi
      if [[ "${port}" == "${ADMIN_HTTPS_PORT}" && -f /etc/nginx/sites-available/cayvpn ]]; then
        if grep -Fq "listen ${ADMIN_IP}:${ADMIN_HTTPS_PORT} ssl;" /etc/nginx/sites-available/cayvpn && grep -Eq "${ADMIN_IP}:${port}[[:space:]].*nginx" <<<"${listening}"; then
          managed=1
        fi
      fi
      [[ "${managed}" == "1" ]] || die "Port ${port} is already in use by a service outside CayVPN."
    fi
  done
  conflicts="openvpn|strongswan|tailscaled|pritunl|outline-server"
  while IFS= read -r unit; do
    [[ -n "${unit}" ]] || continue
    if systemctl is-active --quiet "${unit}" || systemctl is-enabled --quiet "${unit}"; then
      die "Conflicting VPN service is active or enabled: ${unit}"
    fi
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^(${conflicts})" || true)
  ip route get 1.1.1.1 >/dev/null 2>&1 || die "The server does not have a usable internet route."
}

is_unmodified_packaged_nftables_config() {
  local path="${1:-/etc/nftables.conf}" recorded actual
  command -v dpkg-query >/dev/null 2>&1 || return 1
  command -v md5sum >/dev/null 2>&1 || return 1
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  recorded="$(dpkg-query -W -f='${Conffiles}\n' nftables 2>/dev/null | awk -v target="${path}" '$1 == target {print $2; exit}')"
  [[ "${recorded}" =~ ^[0-9a-fA-F]{32}$ ]] || return 1
  actual="$(md5sum -- "${path}" | awk '{print $1}')"
  [[ "${actual,,}" == "${recorded,,}" ]]
}

clean_vps_conflict() {
  die "CayVPN needs a fresh, dedicated VPS because it safely owns the server firewall and VPN services. Found ${1}. No files were changed."
}

check_clean_vps_boundary() {
  local path unit rules policies

  for path in "${INSTALL_ROOT}" "${STATE_DIR}" "${CONFIG_DIR}"; do
    if [[ -e "${path}" || -L "${path}" ]]; then
      [[ -d "${path}" && ! -L "${path}" ]] \
        || clean_vps_conflict "an existing managed path at ${path}"
      [[ -z "$(find "${path}" -mindepth 1 -print -quit 2>/dev/null)" ]] \
        || clean_vps_conflict "existing files at ${path}"
    fi
  done

  [[ ! -e /opt/AdGuardHome && ! -L /opt/AdGuardHome ]] \
    || clean_vps_conflict "a pre-existing AdGuard Home installation"
  [[ -z "$(find /etc/systemd/system -maxdepth 1 -name 'cayvpn-*' -print -quit 2>/dev/null)" ]] \
    || clean_vps_conflict "an incomplete CayVPN service installation"
  [[ -z "$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] \
    || clean_vps_conflict "an existing Nginx website"
  [[ -z "$(find /etc/dnsmasq.d -maxdepth 1 -type f -name '*.conf' -print -quit 2>/dev/null)" ]] \
    || clean_vps_conflict "an existing dnsmasq configuration"

  for unit in nginx.service dnsmasq.service AdGuardHome.service; do
    if systemctl is-active --quiet "${unit}" || systemctl is-enabled --quiet "${unit}"; then
      clean_vps_conflict "the existing ${unit} service"
    fi
  done
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -Fqi 'Status: active'; then
    clean_vps_conflict "an active UFW firewall"
  fi

  if systemctl is-active --quiet nftables.service || systemctl is-enabled --quiet nftables.service; then
    clean_vps_conflict "the existing nftables.service service"
  fi
  if command -v nft >/dev/null 2>&1; then
    rules="$(nft list ruleset 2>/dev/null || true)"
    [[ -z "${rules//[[:space:]]/}" ]] \
      || clean_vps_conflict "existing nftables firewall rules"
  fi
  if [[ -e /etc/nftables.conf || -L /etc/nftables.conf ]]; then
    [[ -f /etc/nftables.conf && ! -L /etc/nftables.conf ]] \
      || clean_vps_conflict "an unsafe nftables configuration path"
    rules="$(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*flush[[:space:]]\+ruleset[[:space:]]*$/d' /etc/nftables.conf)"
    if [[ -n "${rules}" ]] && ! is_unmodified_packaged_nftables_config /etc/nftables.conf; then
      clean_vps_conflict "an existing nftables configuration"
    fi
  fi
  for path in iptables-save ip6tables-save; do
    command -v "${path}" >/dev/null 2>&1 || continue
    policies="$("${path}" 2>/dev/null || true)"
    if grep -Eq '^-A |^:[^ ]+ (DROP|REJECT) ' <<<"${policies}"; then
      clean_vps_conflict "existing ${path%-save} firewall rules"
    fi
  done
}

validate_install_inputs() {
  local name port value derived_admin
  python3 - "${INSTALL_ROOT}" "${STATE_DIR}" "${CONFIG_DIR}" "${WG_DIR}" "${SNAPSHOT_ROOT}" <<'PY'
import pathlib
import sys

protected = {"/", "/etc", "/opt", "/usr", "/var", "/var/lib", "/var/backups"}
for raw in sys.argv[1:]:
    if not raw.startswith("/") or "\n" in raw or "\r" in raw or "\0" in raw:
        raise SystemExit("CayVPN installation paths must be absolute and contain no control characters")
    path = pathlib.Path(raw)
    resolved = path.resolve(strict=False)
    if str(resolved) != raw.rstrip("/") or str(resolved) in protected or len(resolved.parts) < 3:
        raise SystemExit(f"CayVPN installation path is too broad or is not normalized: {raw}")
PY
  for name in WG_IFACE AWG_IFACE ADMIN_IFACE; do
    value="${!name}"
    [[ "${value}" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || die "${name} contains an invalid interface name."
  done
  for port in "${WG_PORT}" "${AWG_PORT}" "${ADMIN_PORT}" "${ADMIN_HTTPS_PORT}" "${REMOTE_ADMIN_PORT}"; do
    if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      die "CayVPN ports must be between 1 and 65535."
    fi
  done
  [[ "${REMOTE_ADMIN_PORT}" == "443" ]] || die "Remote owner access must use the standard HTTPS port 443."
  [[ "${REMOTE_ADMIN_ACME_SERVER}" == "https://acme-v02.api.letsencrypt.org/directory" ]] || die "Remote owner access must use CayVPN's fixed Let's Encrypt certificate service."
  [[ "${REMOTE_ADMIN_ACME_PROFILE}" == "shortlived" ]] || die "Remote owner access must use short-lived HTTPS certificates."
  [[ "${ADMIN_HOSTNAME}" =~ ^[A-Za-z0-9.-]{1,253}$ && "${ADMIN_HOSTNAME}" != .* && "${ADMIN_HOSTNAME}" != *. ]] || die "CAYVPN_ADMIN_HOSTNAME contains invalid characters."
  derived_admin="$(python3 - "${WG_ADDRESS}" "${WG_NETWORK}" "${AWG_ADDRESS}" "${AWG_NETWORK}" "${ADMIN_ADDRESS}" "${ADMIN_NETWORK}" "${EGRESS_NETWORK_V4}" <<'PY'
import ipaddress
import sys

addresses = [ipaddress.ip_interface(value) for value in sys.argv[1:7:2]]
networks = [ipaddress.ip_network(value, strict=False) for value in sys.argv[2:7:2]]
if any(address.version != 4 or address.ip not in network for address, network in zip(addresses, networks)):
    raise SystemExit("CayVPN tunnel addresses and networks must be matching IPv4 values")
egress = ipaddress.ip_network(sys.argv[7], strict=True)
if egress.version != 4:
    raise SystemExit("CayVPN's Location transport network must use IPv4")
if egress.num_addresses <= (999999 * 4) + 3:
    raise SystemExit("CayVPN's Location transport network is too small")
if (
    egress.is_global
    or egress.is_loopback
    or egress.is_link_local
    or egress.is_multicast
    or egress.is_reserved
    or egress.is_unspecified
):
    raise SystemExit("CayVPN's Location transport network must be non-public")
if any(egress.overlaps(network) for network in networks):
    raise SystemExit("CayVPN's Location transport network overlaps a tunnel network")
if any(ipaddress.ip_address(value) in egress for value in ("10.254.0.53", "10.254.0.54")):
    raise SystemExit("CayVPN's Location transport network overlaps its DNS addresses")
admin_ip = addresses[2].ip
admin_client = next((host for host in networks[2].hosts() if host != admin_ip), None)
if admin_client is None:
    raise SystemExit("The CayVPN admin network needs room for an owner device")
print(admin_ip, admin_client)
PY
  )"
  read -r ADMIN_IP ADMIN_CLIENT_IP <<<"${derived_admin}"
  ADMIN_CLIENT_ADDRESS="${ADMIN_CLIENT_IP}/32"
  for value in "${REMOTE_ADMIN_ACME_SERVER}" "${REMOTE_ADMIN_ACME_PROFILE}"; do
    [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || die "Remote access settings may not contain newlines."
  done
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl openssl age nftables nginx dnsmasq conntrack python3 python3-venv python3-pip wireguard wireguard-tools iproute2 util-linux sqlite3 libnss3-tools unattended-upgrades qrencode zip
  cat > /etc/apt/apt.conf.d/52-cayvpn-security-updates <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins {
  "Ubuntu:noble-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
}

public_endpoint() {
  local ip persisted_endpoint
  ip="${CAYVPN_PUBLIC_ENDPOINT:-}"
  # An attached floating/additional address must never silently replace the
  # stable management and client endpoint during an upgrade. Preserve the
  # previously verified endpoint unless the owner explicitly overrides it.
  if [[ -z "${ip}" && -r "${ENV_FILE}" ]]; then
    persisted_endpoint="$(sed -n 's/^CAYVPN_PUBLIC_ENDPOINT=//p' "${ENV_FILE}" | head -n 1)"
    if python3 -c 'import ipaddress,sys; value=ipaddress.ip_address(sys.argv[1]); raise SystemExit(0 if value.version == 4 and value.is_global else 1)' "${persisted_endpoint}" >/dev/null 2>&1; then
      ip="${persisted_endpoint}"
    fi
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (field=1; field<=NF; field++) if ($field == "src") {print $(field+1); exit}}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(ip -4 -j addr show dev "${OUT_IFACE}" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((x["local"] for x in d[0].get("addr_info",[]) if x.get("scope")=="global"),""))' 2>/dev/null || true)"
  fi
  python3 -c 'import ipaddress,sys; value=ipaddress.ip_address(sys.argv[1]); raise SystemExit(0 if value.version == 4 and value.is_global else 1)' "${ip}" >/dev/null 2>&1 || die "Set CAYVPN_PUBLIC_ENDPOINT to this server's public IPv4 address."
  printf '%s' "${ip}"
}

configure_dual_stack() {
  local derived requested_public_ipv6 detected_public_ipv6 public_ipv6_route
  derived="$(python3 - "${ULA_PREFIX}" "${WG_NETWORK_V6}" "${WG_ADDRESS_V6}" "${AWG_NETWORK_V6}" "${AWG_ADDRESS_V6}" "${EGRESS_NETWORK_V6}" "${CLIENT_DNS_V6}" "${CLIENT_ADBLOCK_DNS_V6}" <<'PY'
import ipaddress
import secrets
import sys

prefix_raw, user_network_raw, user_address_raw, amnezia_network_raw, amnezia_address_raw, egress_network_raw, dns_raw, adblock_dns_raw = sys.argv[1:]
if prefix_raw:
    prefix = ipaddress.IPv6Network(prefix_raw, strict=True)
else:
    prefix = ipaddress.IPv6Network((int.from_bytes(b"\xfd" + secrets.token_bytes(5) + b"\0" * 10, "big"), 48))
if prefix.prefixlen != 48 or prefix.network_address.packed[0] != 0xFD:
    raise SystemExit("CAYVPN_ULA_PREFIX must be a locally assigned fd00::/8 /48")

def subnet(identifier):
    return ipaddress.IPv6Network((int(prefix.network_address) | (identifier << 64), 64))

user_network = ipaddress.IPv6Network(user_network_raw, strict=True) if user_network_raw else subnet(1)
amnezia_network = ipaddress.IPv6Network(amnezia_network_raw, strict=True) if amnezia_network_raw else subnet(2)
egress_network = ipaddress.IPv6Network(egress_network_raw, strict=True) if egress_network_raw else subnet(3)
dns_network = subnet(4)
networks = (user_network, amnezia_network, egress_network, dns_network)
if any(item.prefixlen != 64 or not item.subnet_of(prefix) for item in networks) or len(set(networks)) != 4:
    raise SystemExit("CayVPN IPv6 networks must be distinct /64s inside the installation's private /48")

user_address = ipaddress.IPv6Interface(user_address_raw) if user_address_raw else ipaddress.IPv6Interface(f"{user_network.network_address + 1}/64")
amnezia_address = ipaddress.IPv6Interface(amnezia_address_raw) if amnezia_address_raw else ipaddress.IPv6Interface(f"{amnezia_network.network_address + 1}/64")
if user_address.network != user_network or amnezia_address.network != amnezia_network:
    raise SystemExit("CayVPN IPv6 interface addresses must belong to their managed /64s")
dns = ipaddress.IPv6Address(dns_raw) if dns_raw else dns_network.network_address + 0x53
adblock_dns = ipaddress.IPv6Address(adblock_dns_raw) if adblock_dns_raw else dns_network.network_address + 0x54
if dns not in dns_network or adblock_dns not in dns_network or dns == adblock_dns:
    raise SystemExit("CayVPN IPv6 DNS addresses must be distinct addresses in the internal DNS /64")
print("|".join(map(str, (prefix, user_network, user_address, amnezia_network, amnezia_address, egress_network, dns, adblock_dns))))
PY
  )" || die "The private IPv6 configuration is invalid."
  IFS='|' read -r ULA_PREFIX WG_NETWORK_V6 WG_ADDRESS_V6 AWG_NETWORK_V6 AWG_ADDRESS_V6 EGRESS_NETWORK_V6 CLIENT_DNS_V6 CLIENT_ADBLOCK_DNS_V6 <<<"${derived}"

  requested_public_ipv6="${PUBLIC_IPV6}"
  if [[ -z "${PUBLIC_IPV6}" ]]; then
    detected_public_ipv6="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (field=1; field<=NF; field++) if ($field == "src") {print $(field+1); exit}}' || true)"
    PUBLIC_IPV6="${detected_public_ipv6}"
  fi
  if [[ -n "${PUBLIC_IPV6}" ]] && ! python3 -c 'import ipaddress,sys; value=ipaddress.IPv6Address(sys.argv[1]); raise SystemExit(0 if value.is_global else 1)' "${PUBLIC_IPV6}" >/dev/null 2>&1; then
    if [[ -n "${requested_public_ipv6}" ]]; then
      die "CAYVPN_PUBLIC_IPV6 must be a public address already attached to this server."
    fi
    PUBLIC_IPV6=""
  fi
  if [[ -n "${requested_public_ipv6}" ]]; then
    if ! ip -6 -o address show scope global | awk -v expected="${PUBLIC_IPV6}" '{split($4, value, "/"); if (value[1] == expected) found=1} END {exit found ? 0 : 1}'; then
      die "CAYVPN_PUBLIC_IPV6 is not attached to this server. Enable it with the provider first; CayVPN will not change provider networking."
    fi
    public_ipv6_route="$(ip -6 route get 2606:4700:4700::1111 from "${PUBLIC_IPV6}" 2>/dev/null || true)"
    if [[ -z "${public_ipv6_route}" || " ${public_ipv6_route} " != *" ${PUBLIC_IPV6} "* || "${public_ipv6_route,,}" == *"unreachable"* || "${public_ipv6_route,,}" == *"prohibit"* || "${public_ipv6_route,,}" == *"blackhole"* ]]; then
      die "CAYVPN_PUBLIC_IPV6 has no usable public route. Fix it with the provider first; CayVPN made no provider change."
    fi
  fi
}

prepare_paths() {
  install -d -m 0755 "${INSTALL_ROOT}/releases" "${STATE_DIR}" "${CONFIG_DIR}/tls" "${WG_DIR}" /run/cayvpn
  install -d -m 0700 "${CONFIG_DIR}/remote-admin"
  install -d -m 0750 "${CONFIG_DIR}/nginx" "${CONFIG_DIR}/firewall"
  if ! id cayvpn >/dev/null 2>&1; then useradd --system --home-dir "${STATE_DIR}" --create-home --shell /usr/sbin/nologin cayvpn; fi
  # The web process must be able to verify that filtering data is really
  # present before it offers ad blocking. Keep the directory private to root
  # and the CayVPN service group; the service account receives read access but
  # cannot replace the root-owned verified list.
  install -d -m 0750 -o root -g cayvpn "${CONFIG_DIR}/adblock"
  usermod -a -G cayvpn cayvpn >/dev/null 2>&1 || true
  chown -R cayvpn:cayvpn "${STATE_DIR}"
  chmod 0750 "${STATE_DIR}"
}

persist_release_trust() {
  local trust_key="${CONFIG_DIR}/release.pub"
  if [[ -n "${CAYVPN_RELEASE_PUBLIC_KEY:-}" ]]; then
    [[ -f "${CAYVPN_RELEASE_PUBLIC_KEY}" ]] || die "The verified release public key is missing."
    if [[ -f "${trust_key}" ]] && ! cmp -s -- "${trust_key}" "${CAYVPN_RELEASE_PUBLIC_KEY}"; then
      die "The release signing key does not match the key already trusted by this server."
    fi
    install -m 0644 -o root -g root -- "${CAYVPN_RELEASE_PUBLIC_KEY}" "${trust_key}"
  elif [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" != "1" ]]; then
    die "A verified release trust key is required."
  fi
}

cleanup_stale_netns_placeholders() {
  local path name
  [[ -d /run/netns ]] || return 0
  for path in /run/netns/cv-eg-*; do
    [[ -e "${path}" ]] || continue
    name="$(basename -- "${path}")"
    [[ "${name}" =~ ^cv-eg-[0-9a-f]{6}$ ]] || continue
    [[ -f "${path}" && ! -L "${path}" ]] || continue
    # A mounted entry is a live namespace and must never be unlinked. Older
    # private-mount test releases can leave only an unmounted, empty file in
    # the host view; the process-pinned runtime no longer uses these names.
    mountpoint -q -- "${path}" && continue
    rm -f -- "${path}"
  done
}

snapshot_state() {
  local snapshot timestamp
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  snapshot="${SNAPSHOT_ROOT}/install-${timestamp}-$$"
  install -d -m 0700 "${snapshot}"
  SNAPSHOT_PATH="${snapshot}"
  [[ -d "${INSTALL_ROOT}" ]] && : > "${snapshot}/install-root-present"
  getent passwd cayvpn >/dev/null 2>&1 && : > "${snapshot}/cayvpn-user-present"
  getent group cayvpn >/dev/null 2>&1 && : > "${snapshot}/cayvpn-group-present"
  PREVIOUS_RELEASE=""
  if [[ -L "${ACTIVE_RELEASE}" ]]; then
    PREVIOUS_RELEASE="$(readlink -f "${ACTIVE_RELEASE}" 2>/dev/null || true)"
    [[ -n "${PREVIOUS_RELEASE}" && -d "${PREVIOUS_RELEASE}" ]] && printf '%s\n' "${PREVIOUS_RELEASE}" > "${snapshot}/previous-release"
  fi
  if [[ -e "${WG_DIR}" || -L "${WG_DIR}" ]]; then cp -a "${WG_DIR}" "${snapshot}/wireguard"; fi
  if [[ -e "${CONFIG_DIR}" || -L "${CONFIG_DIR}" ]]; then cp -a "${CONFIG_DIR}" "${snapshot}/cayvpn"; fi
  if [[ -e "${STATE_DIR}" || -L "${STATE_DIR}" ]]; then cp -a "${STATE_DIR}" "${snapshot}/state"; fi
  [[ -e /etc/nftables.conf ]] && cp -a /etc/nftables.conf "${snapshot}/nftables.conf"
  if command -v nft >/dev/null 2>&1; then nft list ruleset > "${snapshot}/nftables-live.conf" 2>/dev/null || true; fi
  [[ -e /etc/sysctl.d/99-cayvpn-forwarding.conf ]] && cp -a /etc/sysctl.d/99-cayvpn-forwarding.conf "${snapshot}/99-cayvpn-forwarding.conf"
  for path in /etc/systemd/system/cayvpn-update-recovery.service /etc/systemd/system/cayvpn-agent.service /etc/systemd/system/cayvpn-worker.service /etc/systemd/system/cayvpn-web.service /etc/systemd/system/cayvpn-remote-admin-renew.service /etc/systemd/system/cayvpn-remote-admin-renew.timer; do
    [[ -e "${path}" ]] && cp -a "${path}" "${snapshot}/$(basename "${path}")"
  done
  install -d -m 0700 "${snapshot}/external"
  [[ -e /etc/dnsmasq.d/cayvpn-admin.conf ]] && cp -a /etc/dnsmasq.d/cayvpn-admin.conf "${snapshot}/external/cayvpn-admin.conf"
  [[ -e /etc/nginx/sites-available/cayvpn ]] && cp -a /etc/nginx/sites-available/cayvpn "${snapshot}/external/nginx-cayvpn"
  if [[ -e /etc/nginx/sites-enabled/cayvpn || -L /etc/nginx/sites-enabled/cayvpn ]]; then cp -a /etc/nginx/sites-enabled/cayvpn "${snapshot}/external/nginx-enabled-cayvpn"; fi
  if [[ -e /etc/nginx/sites-enabled/cayvpn-remote || -L /etc/nginx/sites-enabled/cayvpn-remote ]]; then cp -a /etc/nginx/sites-enabled/cayvpn-remote "${snapshot}/external/nginx-enabled-cayvpn-remote"; fi
  if [[ -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ]]; then cp -a /etc/nginx/sites-enabled/default "${snapshot}/external/nginx-enabled-default"; fi
  [[ -e /etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf ]] && cp -a /etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf "${snapshot}/external/nginx-cayvpn-dropin"
  [[ -e /usr/local/bin/cayvpnctl || -L /usr/local/bin/cayvpnctl ]] && cp -a /usr/local/bin/cayvpnctl "${snapshot}/external/cayvpnctl"
  [[ -e /etc/apt/apt.conf.d/52-cayvpn-security-updates ]] && cp -a /etc/apt/apt.conf.d/52-cayvpn-security-updates "${snapshot}/external/52-cayvpn-security-updates"
  for unit in cayvpn-update-recovery.service cayvpn-agent.service cayvpn-worker.service cayvpn-web.service cayvpn-remote-admin-renew.service cayvpn-remote-admin-renew.timer "wg-quick@${WG_IFACE}.service" "wg-quick@${ADMIN_IFACE}.service" dnsmasq.service nftables.service nginx.service unattended-upgrades.service; do
    printf '%s enabled=%s active=%s\n' "${unit}" "$(systemctl is-enabled "${unit}" 2>/dev/null || true)" "$(systemctl is-active "${unit}" 2>/dev/null || true)" >> "${snapshot}/service-state.txt"
  done
  python3 - "${snapshot}" "${INSTALL_ROOT}" "${ACTIVE_RELEASE}" "${STATE_DIR}" "${CONFIG_DIR}" "${WG_DIR}" "${SNAPSHOT_ROOT}" "${WG_IFACE}" "${AWG_IFACE}" "${ADMIN_IFACE}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

snapshot = pathlib.Path(sys.argv[1])

def inventory(root):
    result = {}
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        base = pathlib.Path(directory)
        for name in list(directory_names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                result[relative] = f"symlink:{os.readlink(path)}"
                directory_names.remove(name)
            else:
                result[relative] = "directory"
        for name in file_names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if relative in {"snapshot-manifest.json", ".snapshot-manifest.json.new"}:
                continue
            if path.is_symlink():
                result[relative] = f"symlink:{os.readlink(path)}"
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                result[relative] = f"file:{digest.hexdigest()}"
            else:
                raise SystemExit(f"Unsupported install snapshot entry: {relative}")
    return dict(sorted(result.items()))

payload = {
    "format": 1,
    "paths": {
        "install_root": sys.argv[2],
        "active_release": sys.argv[3],
        "state_dir": sys.argv[4],
        "config_dir": sys.argv[5],
        "wireguard_dir": sys.argv[6],
        "snapshot_root": sys.argv[7],
    },
    "interfaces": {
        "user": sys.argv[8],
        "amnezia": sys.argv[9],
        "admin": sys.argv[10],
    },
    "inventory": inventory(snapshot),
}
temporary = snapshot / ".snapshot-manifest.json.new"
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
os.chmod(temporary, 0o600)
os.replace(temporary, snapshot / "snapshot-manifest.json")
PY
}

install_release() {
  local architecture wheelhouse
  if [[ -e "${RELEASE_DIR}" || -L "${RELEASE_DIR}" ]]; then
    die "The ${RELEASE_VERSION} release directory already exists without being the active verified installation. Use SSH recovery before installing over it."
  fi
  RELEASE_STAGING_DIR="${INSTALL_ROOT}/.release-staging-${RELEASE_VERSION}-$$"
  install -d -m 0755 "${RELEASE_STAGING_DIR}"
  if [[ -n "${CAYVPN_RELEASE_MANIFEST:-}" && -n "${CAYVPN_RELEASE_SIGNATURE:-}" && -n "${CAYVPN_RELEASE_PUBLIC_KEY:-}" ]]; then
    # The bootstrap already proved this exact inventory. Preserve every signed
    # source file so future update and rollback verification sees the same tree.
    tar -C "${SOURCE_DIR}" -cf - . | tar -C "${RELEASE_STAGING_DIR}" -xf -
    cp -- "${CAYVPN_RELEASE_MANIFEST}" "${RELEASE_STAGING_DIR}/release.manifest"
    cp -- "${CAYVPN_RELEASE_SIGNATURE}" "${RELEASE_STAGING_DIR}/release.signature"
    cp -- "${CAYVPN_RELEASE_PUBLIC_KEY}" "${RELEASE_STAGING_DIR}/release.pub"
    chmod 0644 "${RELEASE_STAGING_DIR}/release.manifest" "${RELEASE_STAGING_DIR}/release.pub"
    chmod 0644 "${RELEASE_STAGING_DIR}/release.signature"
  else
    # Finder metadata can appear as regular AppleDouble files when a local
    # source tree is copied from macOS to Linux. A name such as
    # migrations/versions/._0001.py is otherwise discovered by Alembic as a
    # revision and fails with a misleading NUL-byte syntax error.
    tar -C "${SOURCE_DIR}" \
      --exclude=.git --exclude=.venv --exclude=venv \
      --exclude=.secrets --exclude=config --exclude=wireguard --exclude=releases \
      --exclude=data --exclude=sessions --exclude='*.db' --exclude='*.log' \
      --exclude=__pycache__ --exclude='*/__pycache__' --exclude='*.pyc' \
      --exclude='._*' --exclude='*/._*' \
      --exclude='.DS_Store' --exclude='*/.DS_Store' \
      --exclude='__MACOSX' --exclude='*/__MACOSX' \
      -cf - . | tar -C "${RELEASE_STAGING_DIR}" -xf -
  fi
  python3 -m venv "${RELEASE_STAGING_DIR}/.venv"
  case "$(dpkg --print-architecture)" in
    amd64) architecture="amd64" ;;
    arm64) architecture="arm64" ;;
    *) die "Only amd64 and arm64 release dependencies are supported." ;;
  esac
  wheelhouse="${RELEASE_STAGING_DIR}/wheelhouse/${architecture}"
  if [[ -f "${RELEASE_STAGING_DIR}/requirements.lock" && -d "${wheelhouse}" && -n "$(find "${wheelhouse}" -type f -name '*.whl' -print -quit)" ]]; then
    "${RELEASE_STAGING_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check --no-index --no-deps --find-links "${wheelhouse}" -r "${RELEASE_STAGING_DIR}/requirements.lock"
  elif [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" ]]; then
    log "Signed offline dependencies are unavailable; using the network only for this unverified local installation."
    "${RELEASE_STAGING_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r "${RELEASE_STAGING_DIR}/requirements.txt"
  else
    die "The signed release does not contain its offline ${architecture} dependency bundle."
  fi
  if ! PYTHONDONTWRITEBYTECODE=1 "${RELEASE_STAGING_DIR}/.venv/bin/python" \
    "${RELEASE_STAGING_DIR}/scripts/validate-python-source.py" \
    "${RELEASE_STAGING_DIR}"; then
    die "Release Python source validation failed before database migration."
  fi
  # Handle the migration result explicitly. With ERR tracing enabled, allowing
  # a failing subshell to escape directly invokes rollback both inside the
  # subshell and again in the parent shell.
  if ! (
    cd "${RELEASE_STAGING_DIR}"
    CAYVPN_DB_PATH="${STATE_DIR}/cayvpn.db" PYTHONDONTWRITEBYTECODE=1 "${RELEASE_STAGING_DIR}/.venv/bin/python" -m alembic -c alembic.ini upgrade head
  ); then
    die "Database schema migration failed."
  fi
  if ! PYTHONDONTWRITEBYTECODE=1 "${RELEASE_STAGING_DIR}/.venv/bin/python" \
    "${RELEASE_STAGING_DIR}/scripts/relocate-venv.py" \
    "${RELEASE_STAGING_DIR}/.venv" "${RELEASE_STAGING_DIR}" "${RELEASE_DIR}"; then
    die "The release's Python launchers could not be prepared for their final path."
  fi
  # Alembic runs as root during installation, while the persistent web and
  # worker services intentionally run as the unprivileged cayvpn account.
  chown -R cayvpn:cayvpn "${STATE_DIR}"
  chmod 0750 "${STATE_DIR}"
  chmod -R a+rX "${RELEASE_STAGING_DIR}"
  install -d -m 0755 "${INSTALL_ROOT}/releases"
  mv -- "${RELEASE_STAGING_DIR}" "${RELEASE_DIR}"
  NEW_RELEASE_INSTALLED=1
  RELEASE_STAGING_DIR=""
  if ! "${RELEASE_DIR}/.venv/bin/alembic" --version >/dev/null; then
    die "The installed release's Python launchers still reference its staging path."
  fi
  local temporary_link="${INSTALL_ROOT}/.current-${RELEASE_VERSION}-$$"
  ln -sfn "${RELEASE_DIR}" "${temporary_link}"
  mv -Tf "${temporary_link}" "${ACTIVE_RELEASE}"
  chown -R root:root "${INSTALL_ROOT}"
  chmod -R go-w "${INSTALL_ROOT}"
}

write_environment() {
  local endpoint="$1" flask_secret safe_region
  if [[ -f "${ENV_FILE}" ]]; then # shellcheck disable=SC1090
    . "${ENV_FILE}"
  fi
  flask_secret="${FLASK_SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
  PROXY_TOKEN="${CAYVPN_PROXY_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
  [[ "${PROXY_TOKEN}" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || die "The internal web proxy token is invalid."
  safe_region="$(printf '%s' "${SERVER_REGION:-Unknown}" | tr -cs '[:alnum:]._,-' '_' | cut -c1-120)"
  [[ -n "${safe_region}" ]] || safe_region="Unknown"
  cat > "${ENV_FILE}" <<EOF
FLASK_SECRET_KEY=${flask_secret}
CAYVPN_PROXY_TOKEN=${PROXY_TOKEN}
CAYVPN_PROJECT_DIR=${ACTIVE_RELEASE}
CAYVPN_STATE_DIR=${STATE_DIR}
CAYVPN_CONFIG_DIR=${CONFIG_DIR}
CAYVPN_DB_PATH=${STATE_DIR}/cayvpn.db
CAYVPN_WG_DIR=${WG_DIR}
CAYVPN_AGENT_SOCKET=/run/cayvpn/agent.sock
CAYVPN_ACTIVE_RELEASE=${ACTIVE_RELEASE}
CAYVPN_RELEASE_DIR=${INSTALL_ROOT}/releases
CAYVPN_RELEASE_VERSION=${RELEASE_VERSION}
CAYVPN_RELEASE_TRUST_KEY=${CONFIG_DIR}/release.pub
CAYVPN_UPDATE_STATE=${STATE_DIR}/update-status.json
CAYVPN_UPDATE_METADATA=${CONFIG_DIR}/update-metadata.json
CAYVPN_UPDATE_REPOSITORY=caynetic/cayvpn
CAYVPN_PUBLIC_ENDPOINT=${endpoint}
SERVER_IP=${endpoint}
CAYVPN_PUBLIC_IPV6=${PUBLIC_IPV6}
SERVER_REGION=${safe_region}
CAYVPN_USER_INTERFACE=${WG_IFACE}
CAYVPN_USER_PORT=${WG_PORT}
CAYVPN_USER_ADDRESS=${WG_ADDRESS}
CAYVPN_USER_NETWORK=${WG_NETWORK}
CAYVPN_ULA_PREFIX=${ULA_PREFIX}
CAYVPN_USER_NETWORK_V6=${WG_NETWORK_V6}
CAYVPN_USER_ADDRESS_V6=${WG_ADDRESS_V6}
CAYVPN_CLIENT_DNS_ADDRESS=${CAYVPN_CLIENT_DNS_ADDRESS:-10.254.0.53}
CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS=${CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS:-10.254.0.54}
CAYVPN_CLIENT_DNS_ADDRESS_V6=${CLIENT_DNS_V6}
CAYVPN_CLIENT_ADBLOCK_DNS_ADDRESS_V6=${CLIENT_ADBLOCK_DNS_V6}
CAYVPN_AMNEZIA_INTERFACE=${AWG_IFACE}
CAYVPN_AMNEZIA_PORT=${AWG_PORT}
CAYVPN_AMNEZIA_ADDRESS=${AWG_ADDRESS}
CAYVPN_AMNEZIA_NETWORK=${AWG_NETWORK}
CAYVPN_AMNEZIA_NETWORK_V6=${AWG_NETWORK_V6}
CAYVPN_AMNEZIA_ADDRESS_V6=${AWG_ADDRESS_V6}
CAYVPN_EGRESS_NETWORK_V4=${EGRESS_NETWORK_V4}
CAYVPN_EGRESS_NETWORK_V6=${EGRESS_NETWORK_V6}
CAYVPN_ADMIN_INTERFACE=${ADMIN_IFACE}
CAYVPN_ADMIN_PORT=${ADMIN_PORT}
CAYVPN_ADMIN_ADDRESS=${ADMIN_ADDRESS}
CAYVPN_ADMIN_NETWORK=${ADMIN_NETWORK}
CAYVPN_ADMIN_HOSTNAME=${ADMIN_HOSTNAME}
CAYVPN_ADMIN_HTTPS_PORT=${ADMIN_HTTPS_PORT}
CAYVPN_REMOTE_ADMIN_PORT=${REMOTE_ADMIN_PORT}
CAYVPN_REMOTE_ADMIN_ACME_SERVER=${REMOTE_ADMIN_ACME_SERVER}
CAYVPN_REMOTE_ADMIN_ACME_PROFILE=${REMOTE_ADMIN_ACME_PROFILE}
CAYVPN_REMOTE_ADMIN_WEBROOT=/run/cayvpn-public-acme
CAYVPN_APPLY_NETWORK=1
CAYVPN_OUT_IFACE=${OUT_IFACE}
CAYVPN_RATE_LIMIT_STORAGE_URI=memory://
ENABLE_HTTPS=1
CAYVPN_TLS_CERT=${CONFIG_DIR}/tls/server.crt
CAYVPN_TLS_KEY=${CONFIG_DIR}/tls/server.key
CAYVPN_TRUST_CERT=${CONFIG_DIR}/tls/ca.crt
CAYVPN_SECRET_KEY_FILE=${CONFIG_DIR}/agent.key
EOF
  chmod 0640 "${ENV_FILE}"
  chown root:cayvpn "${ENV_FILE}"
}

sync_native_components() {
  if [[ ! -f "${ACTIVE_RELEASE}/components.lock.json" ]]; then
    if [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" ]]; then
      log "Unverified local installation has no signed native-component lock; optional Locations are unavailable."
      return 0
    fi
    die "The active signed release is missing its native-component lock."
  fi
  (
    set -a
    # shellcheck disable=SC1090
    . "${ENV_FILE}"
    set +a
    cd -- "${ACTIVE_RELEASE}"
    PYTHONDONTWRITEBYTECODE=1 "${ACTIVE_RELEASE}/.venv/bin/python" - <<'PY'
from cayvpn.components import COMPONENT_NAMES, sync_release_components
from cayvpn.config import Settings

paths = sync_release_components(Settings.from_env())
if set(paths) != set(COMPONENT_NAMES):
    raise SystemExit("The signed native-component inventory was not fully installed")
PY
  )
}

write_wireguard() {
  local client_key client_pub
  umask 077
  if [[ ! -s "${WG_DIR}/server.key" ]]; then
    wg genkey > "${WG_DIR}/server.key"
  fi
  wg pubkey < "${WG_DIR}/server.key" > "${WG_DIR}/server.pub"
  if [[ ! -f "${WG_DIR}/${WG_IFACE}.conf" ]]; then
    cat > "${WG_DIR}/${WG_IFACE}.conf" <<EOF
[Interface]
Address = ${WG_ADDRESS}, ${WG_ADDRESS_V6}
ListenPort = ${WG_PORT}
PrivateKey = $(<"${WG_DIR}/server.key")
SaveConfig = false
EOF
  fi
  if [[ ! -s "${WG_DIR}/admin-server.key" ]]; then
    wg genkey > "${WG_DIR}/admin-server.key"
  fi
  wg pubkey < "${WG_DIR}/admin-server.key" > "${WG_DIR}/admin-server.pub"
  if [[ ! -f "${STATE_DIR}/admin-initial.conf" ]]; then
    INITIAL_ADMIN_CREATED=1
    client_key="$(wg genkey)"
    client_pub="$(printf '%s' "${client_key}" | wg pubkey)"
    if [[ ! -f "${WG_DIR}/${ADMIN_IFACE}.conf" ]]; then
      cat > "${WG_DIR}/${ADMIN_IFACE}.conf" <<EOF
[Interface]
Address = ${ADMIN_ADDRESS}
ListenPort = ${ADMIN_PORT}
PrivateKey = $(<"${WG_DIR}/admin-server.key")
SaveConfig = false

[Peer]
# Initial owner admin device
PublicKey = ${client_pub}
AllowedIPs = ${ADMIN_CLIENT_ADDRESS}
EOF
    else
      cat >> "${WG_DIR}/${ADMIN_IFACE}.conf" <<EOF

# Initial owner admin device
[Peer]
PublicKey = ${client_pub}
AllowedIPs = ${ADMIN_CLIENT_ADDRESS}
EOF
    fi
    cat > "${STATE_DIR}/admin-initial.conf" <<EOF
# CayVPN secure settings connection. Keep this file private.
[Interface]
PrivateKey = ${client_key}
Address = ${ADMIN_CLIENT_ADDRESS}
DNS = ${ADMIN_IP}, ${ADMIN_SEARCH_DOMAIN}

[Peer]
PublicKey = $(<"${WG_DIR}/admin-server.pub")
Endpoint = ${PUBLIC_ENDPOINT}:${ADMIN_PORT}
AllowedIPs = ${ADMIN_IP}/32
PersistentKeepalive = 25
EOF
    printf '%s\n' "${client_pub}" > "${STATE_DIR}/admin-initial.pub"
  fi
  chmod 0600 "${WG_DIR}/server.key" "${WG_DIR}/${WG_IFACE}.conf" "${WG_DIR}/admin-server.key" "${WG_DIR}/${ADMIN_IFACE}.conf" "${STATE_DIR}/admin-initial.conf"
  chmod 0644 "${WG_DIR}/server.pub" "${WG_DIR}/admin-server.pub"
  if [[ -f "${WG_DIR}/awg-server.pub" ]]; then chmod 0644 "${WG_DIR}/awg-server.pub"; fi
}

generate_recovery_passphrase() {
  python3 - <<'PY'
import secrets

alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
print("".join(secrets.choice(alphabet) for _ in range(20)))
PY
}

recovery_passphrase() {
  local first="${RECOVERY_PASSPHRASE:-${CAYVPN_RECOVERY_PASSPHRASE:-}}" second=""
  if [[ -n "${first}" ]]; then
    [[ ${#first} -ge 12 ]] || die "The offline recovery passphrase must contain at least 12 characters."
    RECOVERY_PASSPHRASE="${first}"
    return
  fi
  [[ -t 2 ]] || die "A recovery passphrase is required. Run interactively or set CAYVPN_RECOVERY_PASSPHRASE."
  if ! IFS= read -r -s -t 900 -p "Create a recovery passphrase (12+ characters), or press Enter to generate one: " first </dev/tty; then
    printf '\n' >/dev/tty
    die "Recovery passphrase entry timed out or the terminal disconnected."
  fi
  printf '\n' >/dev/tty
  if [[ -z "${first}" ]]; then
    first="$(generate_recovery_passphrase)"
    printf 'CayVPN generated this recovery passphrase. Save it somewhere safe; it will not be shown again:\n\n  %s\n\n' "${first}" >/dev/tty
    if ! IFS= read -r -t 900 -p "After saving it, press Enter to continue: " _ </dev/tty; then
      printf '\n' >/dev/tty
      die "Recovery passphrase confirmation timed out or the terminal disconnected."
    fi
  else
    if ! IFS= read -r -s -t 900 -p "Confirm the recovery passphrase: " second </dev/tty; then
      printf '\n' >/dev/tty
      die "Recovery passphrase confirmation timed out or the terminal disconnected."
    fi
    printf '\n' >/dev/tty
    [[ "${first}" == "${second}" ]] || die "The recovery passphrases did not match. Run the installer again."
  fi
  [[ ${#first} -ge 12 ]] || die "The offline recovery passphrase must contain at least 12 characters."
  RECOVERY_PASSPHRASE="${first}"
}

prepare_recovery_passphrase() {
  if [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" && -z "${CAYVPN_RECOVERY_PASSPHRASE:-}" && ! -t 2 ]]; then
    return
  fi
  recovery_passphrase
}

write_tls() {
  local dir="${CONFIG_DIR}/tls"
  if [[ -f "${dir}/server.crt" && -f "${dir}/server.key" && -f "${dir}/ca.crt" ]]; then
    if [[ -f "${dir}/ca.key" ]]; then
      if [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" && -z "${RECOVERY_PASSPHRASE:-${CAYVPN_RECOVERY_PASSPHRASE:-}}" && ! -t 2 ]]; then
        log "Local development mode left the TLS CA signing key on the node; copy it offline before using this install."
      else
        recovery_passphrase
        CAYVPN_RECOVERY_PASSPHRASE="${RECOVERY_PASSPHRASE}" run_release_python -m cayvpn.recovery protect-ca-key --source "${dir}/ca.key" --destination "${STATE_DIR}/recovery/tls-ca.age"
      fi
    fi
    return
  fi
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=CayVPN local CA" -keyout "${dir}/ca.key" -out "${dir}/ca.crt" >/dev/null 2>&1
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${ADMIN_HOSTNAME}" -keyout "${dir}/server.key" -out "${dir}/server.csr" >/dev/null 2>&1
  cat > "${dir}/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${ADMIN_HOSTNAME},IP:${ADMIN_IP}
EOF
  openssl x509 -req -days 825 -sha256 -in "${dir}/server.csr" -CA "${dir}/ca.crt" -CAkey "${dir}/ca.key" -CAcreateserial -out "${dir}/server.crt" -extfile "${dir}/server.ext" >/dev/null 2>&1
  rm -f "${dir}/server.csr" "${dir}/server.ext" "${dir}/ca.srl"
  chmod 0600 "${dir}/ca.key" "${dir}/server.key"
  chmod 0644 "${dir}/ca.crt" "${dir}/server.crt"
  if [[ -f "${dir}/ca.key" ]]; then
    if [[ "${CAYVPN_ALLOW_UNVERIFIED_LOCAL:-0}" == "1" && -z "${RECOVERY_PASSPHRASE:-${CAYVPN_RECOVERY_PASSPHRASE:-}}" && ! -t 2 ]]; then
      log "Local development mode left the TLS CA signing key on the node; copy it offline before using this install."
    else
      recovery_passphrase
      CAYVPN_RECOVERY_PASSPHRASE="${RECOVERY_PASSPHRASE}" run_release_python -m cayvpn.recovery protect-ca-key --source "${dir}/ca.key" --destination "${STATE_DIR}/recovery/tls-ca.age"
    fi
  fi
}

write_owner_kit() {
  local kit_dir state_archive export_user export_group export_home export_path show_qr
  kit_dir="${STATE_DIR}/owner-kit"
  state_archive="${STATE_DIR}/cayvpn-owner-kit-${RELEASE_VERSION}.zip"
  install -d -m 0700 -o root -g root "${kit_dir}"
  install -m 0600 -o root -g root "${STATE_DIR}/admin-initial.conf" "${kit_dir}/admin.conf"
  install -m 0644 -o root -g root "${CONFIG_DIR}/tls/ca.crt" "${kit_dir}/cayvpn-ca.crt"
  if [[ -f "${STATE_DIR}/recovery/tls-ca.age" ]]; then
    install -m 0600 -o root -g root "${STATE_DIR}/recovery/tls-ca.age" "${kit_dir}/tls-ca-recovery.age"
  fi
  cat > "${kit_dir}/README.txt" <<EOF
CayVPN setup folder (owner kit) - keep this folder private

START HERE

Page 1 of 3 - Add secure access
1. Open admin.conf with the WireGuard app.
2. Add the connection and name it CayVPN Settings.
3. Leave it off until Page 3.

Page 2 of 3 - Trust the private CayVPN page
Install cayvpn-ca.crt as a trusted certificate on this device.

On a Mac:
1. Double-click cayvpn-ca.crt and add it to Keychain Access.
2. Search for "CayVPN local CA" and open it.
3. Expand Trust and set "When using this certificate" to Always Trust.
4. Close the window, approve the change, then fully quit and reopen the browser.

On another device, use its normal steps for installing a trusted CA certificate.

Page 3 of 3 - Open CayVPN
1. Turn off any other active VPN.
2. Turn on CayVPN Settings in WireGuard.
3. Open https://${ADMIN_HOSTNAME}:${ADMIN_HTTPS_PORT}
4. Follow the short checklist to add your first device.

Passwords, authenticator codes, and passkeys are optional. You can add them
later from Security if you want another way to open CayVPN settings.

After optional sign-in is enabled in Security, you can leave CayVPN Settings off,
turn on your normal CayVPN connection, and open https://${ADMIN_IP}:${ADMIN_HTTPS_PORT}
for everyday access. The public server address remains closed unless you
separately choose access from anywhere.

The encrypted tls-ca-recovery.age file belongs in offline recovery storage.
Do not upload this kit or send it through email or chat. Delete extra copies
after your settings device and offline recovery storage are configured.
EOF
  chmod 0600 "${kit_dir}/README.txt"
  rm -f -- "${state_archive}"
  (cd "${kit_dir}" && zip -q -r "${state_archive}" .)
  chmod 0600 "${state_archive}"

  export_user="root"
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" && "${SUDO_USER}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] && id "${SUDO_USER}" >/dev/null 2>&1; then
    export_user="${SUDO_USER}"
  fi
  export_group="$(id -gn "${export_user}")"
  export_home="$(getent passwd "${export_user}" | cut -d: -f6)"
  [[ -n "${export_home}" && -d "${export_home}" ]] || die "Could not determine the SSH user's home directory for the CayVPN setup folder."
  export_path="${export_home}/cayvpn-owner-kit-${RELEASE_VERSION}.zip"
  install -m 0600 -o "${export_user}" -g "${export_group}" "${state_archive}" "${export_path}"
  OWNER_KIT_PATH="${export_path}"
  OWNER_KIT_USER="${export_user}"

  show_qr="${CAYVPN_SHOW_ADMIN_QR:-}"
  if [[ -z "${show_qr}" && "${INITIAL_ADMIN_CREATED}" == "1" && -t 2 ]]; then
    log "The optional setup QR contains the private secure-access key and may remain in provider console history."
    IFS= read -r -p "Show the one-time CayVPN Settings QR now? [y/N] " show_qr </dev/tty
  fi
  if [[ "${show_qr}" =~ ^[Yy]$ && -t 2 ]] && command -v qrencode >/dev/null 2>&1; then
    log "Scan this once with the WireGuard app, then clear or close the console:"
    qrencode -t ANSIUTF8 -m 1 -o - < "${STATE_DIR}/admin-initial.conf" >/dev/tty
  fi
}

configure_dns_filtering() {
  local blocklist_source blocklist_sha blocklist_temporary blocklist_target
  blocklist_source="${CAYVPN_ADBLOCK_FILTER:-${ADBLOCK_FILTER_URL}}"
  blocklist_sha="${CAYVPN_ADBLOCK_FILTER_SHA256:-${ADBLOCK_FILTER_SHA256}}"
  blocklist_target="${CONFIG_DIR}/adblock/adguard-dns-filter.txt"
  [[ "${blocklist_sha}" =~ ^[0-9a-fA-F]{64}$ ]] || die "Ad-blocking filter checksum must be 64 hexadecimal characters."
  blocklist_temporary="$(mktemp)"
  if [[ "${blocklist_source}" =~ ^https:// ]]; then
    if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "${blocklist_source}" -o "${blocklist_temporary}"; then
      rm -f -- "${blocklist_temporary}"
      if [[ "${CAYVPN_ALLOW_MISSING_COMPONENTS:-0}" == "1" ]]; then
        log "The pinned DNS blocklist could not be downloaded; ad and tracker blocking will be unavailable."
        blocklist_temporary=""
      else
        die "The pinned DNS blocklist could not be downloaded. Check the server's internet connection and run the installer again."
      fi
    fi
  else
    [[ -f "${blocklist_source}" ]] || die "The DNS blocklist file was not found."
    cp -- "${blocklist_source}" "${blocklist_temporary}"
  fi
  if [[ -n "${blocklist_temporary}" ]]; then
    printf '%s  %s\n' "${blocklist_sha}" "${blocklist_temporary}" | sha256sum --check --status || die "The DNS blocklist checksum failed."
    [[ "$(stat -c %s "${blocklist_temporary}")" -le 20971520 ]] || die "The DNS blocklist is unexpectedly large."
    grep -Fq '||doubleclick.net^' "${blocklist_temporary}" || die "The DNS blocklist does not contain the expected verified rule."
    install -m 0640 -o root -g cayvpn -- "${blocklist_temporary}" "${blocklist_target}"
    rm -f -- "${blocklist_temporary}"
    runuser -u cayvpn -- test -r "${blocklist_target}" || die "The verified DNS blocklist is not readable by the CayVPN service."
  fi
  # Keep private owner DNS on the admin tunnel only.
  cat > /etc/dnsmasq.d/cayvpn-admin.conf <<EOF
listen-address=${ADMIN_IP}
# wg-quick deliberately starts after name-service initialization. On Linux,
# bind-dynamic lets dnsmasq start before wg-admin exists and attach only to the
# configured private address when the interface appears, without opening DNS
# on the public VPS interface or introducing a systemd ordering cycle.
bind-dynamic
no-resolv
server=1.1.1.1
address=/${ADMIN_HOSTNAME}/${ADMIN_IP}
EOF
  systemctl enable --now dnsmasq >/dev/null 2>&1 || true
}

write_firewall() {
  cat > "${CONFIG_DIR}/firewall/remote-admin.nft" <<EOF
  set cayvpn_remote_admin_ports {
    type inet_service;
  }
EOF
  chmod 0640 "${CONFIG_DIR}/firewall/remote-admin.nft"
  cat > /etc/nftables.conf <<EOF
flush ruleset
table inet cayvpn {
  map cayvpn_snat_v4 {
    type ipv4_addr : ipv4_addr;
  }
  map cayvpn_snat_v6 {
    type ipv6_addr : ipv6_addr;
  }
  include "${CONFIG_DIR}/firewall/remote-admin.nft"
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    meta nfproto ipv6 meta l4proto ipv6-icmp accept
    tcp dport 22 accept
    udp dport ${WG_PORT} accept
    udp dport ${AWG_PORT} accept
    udp dport ${ADMIN_PORT} accept
    iifname "${OUT_IFACE}" tcp dport @cayvpn_remote_admin_ports accept
EOF
  cat >> /etc/nftables.conf <<EOF
    iifname "${ADMIN_IFACE}" tcp dport ${ADMIN_HTTPS_PORT} accept
    iifname "${ADMIN_IFACE}" udp dport 53 accept
    iifname "${ADMIN_IFACE}" tcp dport 53 accept
    iifname "${WG_IFACE}" ip saddr ${WG_NETWORK} tcp dport ${ADMIN_HTTPS_PORT} accept
    iifname "${AWG_IFACE}" ip saddr ${AWG_NETWORK} tcp dport ${ADMIN_HTTPS_PORT} accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "${WG_IFACE}" oifname "cvh*" ip saddr ${WG_NETWORK} accept
    oifname "${WG_IFACE}" ip daddr ${WG_NETWORK} accept
    iifname "${WG_IFACE}" oifname "cvh*" ip6 saddr ${WG_NETWORK_V6} accept
    oifname "${WG_IFACE}" ip6 daddr ${WG_NETWORK_V6} accept
    iifname "${AWG_IFACE}" oifname "cvh*" ip saddr ${AWG_NETWORK} accept
    oifname "${AWG_IFACE}" ip daddr ${AWG_NETWORK} accept
    iifname "${AWG_IFACE}" oifname "cvh*" ip6 saddr ${AWG_NETWORK_V6} accept
    oifname "${AWG_IFACE}" ip6 daddr ${AWG_NETWORK_V6} accept
    iifname "${ADMIN_IFACE}" ip saddr ${ADMIN_NETWORK} accept
    oifname "${ADMIN_IFACE}" ip daddr ${ADMIN_NETWORK} accept
    iifname "cvh*" oifname "${OUT_IFACE}" accept
  }
  chain output { type filter hook output priority 0; policy accept; }
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "${OUT_IFACE}" snat ip to ip saddr map @cayvpn_snat_v4
    oifname "${OUT_IFACE}" snat ip6 to ip6 saddr map @cayvpn_snat_v6
    oifname "${OUT_IFACE}" ip saddr ${WG_NETWORK} masquerade
    oifname "${OUT_IFACE}" ip saddr ${AWG_NETWORK} masquerade
  }
  chain ipv6_leak_guard {
    type filter hook postrouting priority 110; policy accept;
    oifname "${OUT_IFACE}" ip6 saddr ${ULA_PREFIX} drop
  }
}
EOF
  cat > /etc/sysctl.d/99-cayvpn-forwarding.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
  sysctl --system >/dev/null
  nft -f /etc/nftables.conf
  systemctl enable --now nftables >/dev/null 2>&1 || true
}

write_nginx() {
  local temporary_admin_address=0 nginx_status=0
  cat > "${CONFIG_DIR}/nginx/remote-admin.conf" <<EOF
# CayVPN remote administration is disabled.
EOF
  chmod 0640 "${CONFIG_DIR}/nginx/remote-admin.conf"
  cat > /etc/nginx/sites-available/cayvpn <<EOF
server {
  listen ${ADMIN_IP}:${ADMIN_HTTPS_PORT} ssl;
  server_name ${ADMIN_HOSTNAME};
  ssl_certificate ${CONFIG_DIR}/tls/server.crt;
  ssl_certificate_key ${CONFIG_DIR}/tls/server.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  add_header X-Content-Type-Options nosniff always;
  add_header X-Frame-Options DENY always;
  location / {
    proxy_pass http://127.0.0.1:8080;
    # Preserve the private HTTPS port so Flask-WTF's strict HTTPS referrer
    # comparison sees the same origin the browser used.
    proxy_set_header Host \$http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-CayVPN-Proxy-Token ${PROXY_TOKEN};
  }
}
EOF
  chown root:root /etc/nginx/sites-available/cayvpn
  chmod 0640 /etc/nginx/sites-available/cayvpn
  ln -sfn /etc/nginx/sites-available/cayvpn /etc/nginx/sites-enabled/cayvpn
  ln -sfn "${CONFIG_DIR}/nginx/remote-admin.conf" /etc/nginx/sites-enabled/cayvpn-remote
  rm -f /etc/nginx/sites-enabled/default
  if ! ip -4 -o address show | awk '{print $4}' | grep -Eq "^${ADMIN_IP}/"; then
    ip -4 address add "${ADMIN_IP}/32" dev lo
    temporary_admin_address=1
  fi
  if nginx -t; then nginx_status=0; else nginx_status=$?; fi
  if [[ "${temporary_admin_address}" == "1" ]]; then
    ip -4 address delete "${ADMIN_IP}/32" dev lo
  fi
  return "${nginx_status}"
}

write_services() {
  install -d -m 0755 /etc/systemd/system/nginx.service.d
  cat > /etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf <<EOF
[Unit]
Requires=wg-quick@${ADMIN_IFACE}.service
After=wg-quick@${ADMIN_IFACE}.service
EOF
  cat > /etc/systemd/system/cayvpn-update-recovery.service <<EOF
[Unit]
Description=CayVPN interrupted-update recovery
After=local-fs.target
Before=cayvpn-agent.service cayvpn-worker.service cayvpn-web.service
[Service]
Type=oneshot
User=root
Group=root
EnvironmentFile=${ENV_FILE}
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=${ACTIVE_RELEASE}
ExecStart=${ACTIVE_RELEASE}/.venv/bin/python -m cayvpn.update_runner recover
RemainAfterExit=yes
UMask=0077
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${STATE_DIR} ${CONFIG_DIR} ${WG_DIR} ${INSTALL_ROOT}
[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/cayvpn-agent.service <<EOF
[Unit]
Description=CayVPN restricted root node agent
Requires=cayvpn-update-recovery.service
After=cayvpn-update-recovery.service network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Group=root
EnvironmentFile=${ENV_FILE}
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=${ACTIVE_RELEASE}
ExecStart=${ACTIVE_RELEASE}/.venv/bin/python -m cayvpn.agent_service
Restart=on-failure
RestartSec=5
RuntimeDirectory=cayvpn
RuntimeDirectoryMode=0750
UMask=0007
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/run/cayvpn -/run/cayvpn-public-acme ${STATE_DIR} ${CONFIG_DIR} ${WG_DIR}
[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/cayvpn-worker.service <<EOF
[Unit]
Description=CayVPN management worker
After=cayvpn-agent.service network-online.target
Wants=cayvpn-agent.service network-online.target
[Service]
Type=simple
User=cayvpn
Group=cayvpn
EnvironmentFile=${ENV_FILE}
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=${ACTIVE_RELEASE}
ExecStart=${ACTIVE_RELEASE}/.venv/bin/python -m cayvpn.worker_service
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ReadWritePaths=${STATE_DIR}
[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/cayvpn-web.service <<EOF
[Unit]
Description=CayVPN private management panel
After=cayvpn-agent.service cayvpn-worker.service wg-quick@${ADMIN_IFACE}.service nginx.service
Wants=cayvpn-agent.service cayvpn-worker.service wg-quick@${ADMIN_IFACE}.service
[Service]
Type=simple
User=cayvpn
Group=cayvpn
EnvironmentFile=${ENV_FILE}
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=${ACTIVE_RELEASE}
ExecStart=${ACTIVE_RELEASE}/.venv/bin/python -m gunicorn --workers 2 --bind 127.0.0.1:8080 app:app
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${STATE_DIR}
[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/cayvpn-remote-admin-renew.service <<EOF
[Unit]
Description=Renew CayVPN's short-lived remote administration certificate
After=network-online.target cayvpn-agent.service nginx.service
Wants=network-online.target cayvpn-agent.service nginx.service
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/bin/cayvpnctl remote-admin renew
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
EOF
  cat > /etc/systemd/system/cayvpn-remote-admin-renew.timer <<EOF
[Unit]
Description=Check CayVPN's remote administration certificate daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF
  cat > /usr/local/bin/cayvpnctl <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
set -a
. "${ENV_FILE}"
set +a
export PYTHONDONTWRITEBYTECODE=1
cd -- "${ACTIVE_RELEASE}"
exec "${ACTIVE_RELEASE}/.venv/bin/python" -m cayvpn.cli "\$@"
EOF
  chmod 0750 /usr/local/bin/cayvpnctl
  systemctl daemon-reload
  systemctl enable "wg-quick@${WG_IFACE}" "wg-quick@${ADMIN_IFACE}" cayvpn-update-recovery cayvpn-agent cayvpn-worker cayvpn-web nginx >/dev/null
  systemctl enable --now cayvpn-remote-admin-renew.timer >/dev/null
}

start_verify() {
  systemctl restart "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@${ADMIN_IFACE}" >/dev/null 2>&1 || true
  systemctl restart dnsmasq >/dev/null 2>&1 || true
  systemctl restart cayvpn-agent cayvpn-worker cayvpn-web >/dev/null
  systemctl restart nginx >/dev/null
  for _ in $(seq 1 20); do [[ -S /run/cayvpn/agent.sock ]] && break; sleep 1; done
  [[ -S /run/cayvpn/agent.sock ]] || die "The root agent did not start. Inspect journalctl -u cayvpn-agent."
  # Export the root-owned service environment for the provisioning subprocess;
  # merely sourcing it would leave fresh variables as shell-local values.
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
  systemctl is-active --quiet cayvpn-agent || die "The CayVPN agent is not active."
  systemctl is-active --quiet cayvpn-worker || die "The CayVPN worker is not active."
  systemctl is-active --quiet cayvpn-web || die "The CayVPN web service is not active."
  systemctl is-active --quiet nginx || die "nginx is not active."
  systemctl is-active --quiet cayvpn-remote-admin-renew.timer || die "The remote HTTPS renewal timer is not active."
  systemctl is-active --quiet dnsmasq || die "The private admin DNS resolver is not active."
  wg show "${WG_IFACE}" >/dev/null 2>&1 || die "The standard WireGuard interface is not active."
  ip -6 address show dev "${WG_IFACE}" | grep -Fq "${WG_ADDRESS_V6%/*}/" || die "The standard WireGuard IPv6 address is not active."
  wg show "${ADMIN_IFACE}" >/dev/null 2>&1 || die "The private admin WireGuard interface is not active."
  nft -c -f /etc/nftables.conf >/dev/null || die "The deny-by-default firewall rules failed validation."
  nft list table inet cayvpn >/dev/null 2>&1 || die "The deny-by-default firewall rules are not active."
  nft list map inet cayvpn cayvpn_snat_v6 >/dev/null 2>&1 || die "The IPv6 exit translation map is not active."
  remote_admin_set_json="$(nft -j -n list set inet cayvpn cayvpn_remote_admin_ports 2>/dev/null)" || die "The managed remote owner firewall set is missing."
  REMOTE_ADMIN_SET_JSON="${remote_admin_set_json}" python3 - <<'PY' || die "Remote owner access was not installed closed by default."
import json
import os

payload = json.loads(os.environ["REMOTE_ADMIN_SET_JSON"])
sets = [
    item["set"]
    for item in payload.get("nftables", [])
    if isinstance(item, dict)
    and isinstance(item.get("set"), dict)
    and item["set"].get("family") == "inet"
    and item["set"].get("table") == "cayvpn"
    and item["set"].get("name") == "cayvpn_remote_admin_ports"
    and item["set"].get("type") == "inet_service"
]
if len(sets) != 1 or sets[0].get("elem", []) != []:
    raise SystemExit(1)
PY
  [[ -L /etc/nginx/sites-enabled/cayvpn-remote && "$(readlink -f /etc/nginx/sites-enabled/cayvpn-remote)" == "$(readlink -f "${CONFIG_DIR}/nginx/remote-admin.conf")" ]] || die "The disabled remote HTTPS configuration is not managed by CayVPN."
  grep -Fxq '# CayVPN remote administration is disabled.' "${CONFIG_DIR}/nginx/remote-admin.conf" || die "Remote owner access was not installed closed by default."
  python3 - "${ADMIN_IP}" "${ADMIN_HOSTNAME}" <<'PY'
import os
import socket
import struct
import sys

server, hostname = sys.argv[1:]
transaction = os.urandom(2)
question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in hostname.split(".")) + b"\0"
query = transaction + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(3)
    client.sendto(query, (server, 53))
    response, _ = client.recvfrom(4096)
if len(response) < 12 or response[:2] != transaction or response[3] & 0x0F or socket.inet_aton(server) not in response:
    raise SystemExit("The private admin DNS response did not verify")
PY
  local http_code=""
  for _ in $(seq 1 20); do
    http_code="$(curl --silent --cacert "${CONFIG_DIR}/tls/ca.crt" --resolve "${ADMIN_HOSTNAME}:${ADMIN_HTTPS_PORT}:${ADMIN_IP}" -o /dev/null -w '%{http_code}' "https://${ADMIN_HOSTNAME}:${ADMIN_HTTPS_PORT}/" || true)"
    [[ "${http_code}" == "403" || "${http_code}" == "302" ]] && break
    systemctl is-active --quiet cayvpn-web || die "The CayVPN web service stopped during its readiness check."
    sleep 1
  done
  [[ "${http_code}" == "403" || "${http_code}" == "302" ]] || die "The private panel did not answer on the admin tunnel listener."
  systemctl is-active --quiet cayvpn-worker || die "The CayVPN worker stopped during the private-panel readiness check."
  systemctl is-active --quiet cayvpn-web || die "The CayVPN web service stopped during its readiness check."
  run_release_python -m cayvpn.cli provision --admin-public-key "$(<"${STATE_DIR}/admin-initial.pub")" --admin-address "${ADMIN_CLIENT_ADDRESS}" >/dev/null
  local provisioned_state provisioned_release
  IFS='|' read -r provisioned_state provisioned_release <<<"$(sqlite3 "${STATE_DIR}/cayvpn.db" 'SELECT install_state || "|" || release FROM managed_nodes WHERE id = 1;')"
  [[ "${provisioned_state}" == "verified" ]] || die "The persistent CayVPN node was not marked verified."
  [[ "${provisioned_release}" == "${RELEASE_VERSION}" ]] || die "The persistent CayVPN node recorded the wrong release."
}

restore_snapshot_item() {
  local source="$1" destination="$2"
  if [[ -e "${source}" || -L "${source}" ]]; then
    rm -rf -- "${destination}"
    install -d -m 0755 "$(dirname -- "${destination}")"
    cp -a -- "${source}" "${destination}"
  else
    rm -rf -- "${destination}"
  fi
}

verify_install_snapshot() {
  local restored="${1:-0}" arguments
  arguments=(
    "${SNAPSHOT_PATH}"
    "${INSTALL_ROOT}"
    "${ACTIVE_RELEASE}"
    "${STATE_DIR}"
    "${CONFIG_DIR}"
    "${WG_DIR}"
    "${SNAPSHOT_ROOT}"
    "${WG_IFACE}"
    "${AWG_IFACE}"
    "${ADMIN_IFACE}"
  )
  if [[ "${restored}" == "1" ]]; then
    python3 "${SOURCE_DIR}/scripts/verify-install-snapshot.py" "${arguments[@]}" --restored
  else
    python3 "${SOURCE_DIR}/scripts/verify-install-snapshot.py" "${arguments[@]}"
  fi
}

rollback_on_error() {
  local status="$?"
  local rollback_failed=0 snapshot_valid=0 unit enabled active current
  trap - ERR
  set +e

  rollback_problem() {
    rollback_failed=1
    log "Recovery warning: $*"
  }

  log "Installation failed; restoring CayVPN-owned files from the verified snapshot."
  systemctl stop cayvpn-remote-admin-renew.timer cayvpn-remote-admin-renew.service cayvpn-web cayvpn-worker cayvpn-agent cayvpn-update-recovery "wg-quick@${ADMIN_IFACE}" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
  systemctl disable cayvpn-remote-admin-renew.timer cayvpn-web cayvpn-worker cayvpn-agent cayvpn-update-recovery "wg-quick@${ADMIN_IFACE}" "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true

  if [[ -n "${SNAPSHOT_PATH}" ]] && verify_install_snapshot; then
    snapshot_valid=1
  else
    rollback_problem "the install snapshot did not pass integrity verification; automatic file restoration was not attempted"
  fi

  if [[ "${snapshot_valid}" == "1" ]]; then
    rm -rf -- "${ACTIVE_RELEASE}" || rollback_problem "the active release link could not be removed"
    if [[ -n "${PREVIOUS_RELEASE}" && -d "${PREVIOUS_RELEASE}" ]]; then
      ln -s "${PREVIOUS_RELEASE}" "${ACTIVE_RELEASE}"         || rollback_problem "the previous active release link could not be restored"
    fi
    if [[ "${NEW_RELEASE_INSTALLED}" == "1" && -n "${RELEASE_DIR}" && "${RELEASE_DIR}" != "${PREVIOUS_RELEASE}" ]]; then
      rm -rf -- "${RELEASE_DIR}"         || rollback_problem "the failed release directory could not be removed"
    fi

    restore_snapshot_item "${SNAPSHOT_PATH}/wireguard" "${WG_DIR}"       || rollback_problem "WireGuard state could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/cayvpn" "${CONFIG_DIR}"       || rollback_problem "CayVPN configuration could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/state" "${STATE_DIR}"       || rollback_problem "CayVPN data could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/nftables.conf" /etc/nftables.conf       || rollback_problem "the firewall configuration could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/99-cayvpn-forwarding.conf" /etc/sysctl.d/99-cayvpn-forwarding.conf       || rollback_problem "the forwarding configuration could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/cayvpn-admin.conf" /etc/dnsmasq.d/cayvpn-admin.conf       || rollback_problem "the private DNS configuration could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/nginx-cayvpn" /etc/nginx/sites-available/cayvpn       || rollback_problem "the private web configuration could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/nginx-enabled-cayvpn" /etc/nginx/sites-enabled/cayvpn       || rollback_problem "the private web activation could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/nginx-enabled-cayvpn-remote" /etc/nginx/sites-enabled/cayvpn-remote       || rollback_problem "the remote web activation could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/nginx-enabled-default" /etc/nginx/sites-enabled/default       || rollback_problem "the previous default website could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/nginx-cayvpn-dropin" /etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf       || rollback_problem "the web service restrictions could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/cayvpnctl" /usr/local/bin/cayvpnctl       || rollback_problem "the maintenance command could not be restored"
    restore_snapshot_item "${SNAPSHOT_PATH}/external/52-cayvpn-security-updates" /etc/apt/apt.conf.d/52-cayvpn-security-updates       || rollback_problem "the prior security-update policy could not be restored"
    for unit in cayvpn-update-recovery.service cayvpn-agent.service cayvpn-worker.service cayvpn-web.service cayvpn-remote-admin-renew.service cayvpn-remote-admin-renew.timer; do
      restore_snapshot_item "${SNAPSHOT_PATH}/${unit}" "/etc/systemd/system/${unit}"         || rollback_problem "${unit} could not be restored"
    done

    systemctl daemon-reload >/dev/null 2>&1       || rollback_problem "systemd did not reload the restored service definitions"
    if command -v nft >/dev/null 2>&1; then
      nft flush ruleset >/dev/null 2>&1         || rollback_problem "the partial live firewall could not be cleared"
      if [[ -e "${SNAPSHOT_PATH}/nftables-live.conf" ]]; then
        if [[ -s "${SNAPSHOT_PATH}/nftables-live.conf" ]]; then
          nft -f "${SNAPSHOT_PATH}/nftables-live.conf" >/dev/null 2>&1             || rollback_problem "the previous live firewall could not be restored"
        fi
        if ! cmp -s -- "${SNAPSHOT_PATH}/nftables-live.conf" <(nft list ruleset 2>/dev/null); then
          rollback_problem "the restored live firewall did not match the verified snapshot"
        fi
      elif [[ -f /etc/nftables.conf ]]; then
        nft -f /etc/nftables.conf >/dev/null 2>&1           || rollback_problem "the restored firewall configuration could not be loaded"
      fi
    elif [[ -s "${SNAPSHOT_PATH}/nftables-live.conf" ]]; then
      rollback_problem "nftables is unavailable for restoring the previous live firewall"
    fi
    sysctl --system >/dev/null 2>&1       || rollback_problem "the restored kernel forwarding settings did not reload"

    verify_install_snapshot 1       || rollback_problem "restored CayVPN-owned files did not match the verified snapshot"

    if [[ -f "${SNAPSHOT_PATH}/service-state.txt" ]]; then
      while read -r unit enabled active; do
        [[ -n "${unit}" ]] || continue
        enabled="${enabled#enabled=}"
        active="${active#active=}"
        if [[ "${enabled}" == "enabled" ]]; then
          systemctl enable "${unit}" >/dev/null 2>&1             || rollback_problem "${unit} could not be re-enabled"
        else
          systemctl disable "${unit}" >/dev/null 2>&1 || true
        fi
        if [[ "${active}" == "active" ]]; then
          systemctl start "${unit}" >/dev/null 2>&1             || rollback_problem "${unit} could not be restarted"
        else
          systemctl stop "${unit}" >/dev/null 2>&1 || true
        fi

        current="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
        if [[ "${enabled}" == "enabled" && "${current}" != "enabled" ]]; then
          rollback_problem "${unit} did not return to its enabled state"
        elif [[ "${enabled}" != "enabled" && "${current}" == "enabled" ]]; then
          rollback_problem "${unit} remained enabled unexpectedly"
        fi
        current="$(systemctl is-active "${unit}" 2>/dev/null || true)"
        if [[ "${active}" == "active" && "${current}" != "active" ]]; then
          rollback_problem "${unit} did not return to its active state"
        elif [[ "${active}" != "active" && "${current}" == "active" ]]; then
          rollback_problem "${unit} remained active unexpectedly"
        fi
      done < "${SNAPSHOT_PATH}/service-state.txt"
    else
      rollback_problem "the previous service-state record is missing"
    fi

    if [[ ! -e "${SNAPSHOT_PATH}/cayvpn-user-present" ]] && getent passwd cayvpn >/dev/null 2>&1; then
      userdel cayvpn >/dev/null 2>&1         || rollback_problem "the installer-created CayVPN user could not be removed"
    fi
    if [[ ! -e "${SNAPSHOT_PATH}/cayvpn-group-present" ]] && getent group cayvpn >/dev/null 2>&1; then
      groupdel cayvpn >/dev/null 2>&1         || rollback_problem "the installer-created CayVPN group could not be removed"
    fi

    if [[ ! -e "${SNAPSHOT_PATH}/install-root-present" ]]; then
      rmdir -- "${INSTALL_ROOT}/releases" >/dev/null 2>&1 || true
      rmdir -- "${INSTALL_ROOT}" >/dev/null 2>&1 || true
    fi
  fi

  rm -rf -- /run/cayvpn >/dev/null 2>&1 || rollback_problem "temporary CayVPN runtime files could not be removed"
  if [[ -n "${RELEASE_STAGING_DIR}" && -d "${RELEASE_STAGING_DIR}" ]]; then
    rm -rf -- "${RELEASE_STAGING_DIR}"       || rollback_problem "the failed release staging directory could not be removed"
  fi
  systemctl daemon-reload >/dev/null 2>&1     || rollback_problem "systemd did not complete its final reload"

  if [[ -n "${SNAPSHOT_PATH}" && -d "${SNAPSHOT_PATH}" ]]; then
    if [[ "${rollback_failed}" == "0" ]]; then
      printf 'restored_and_verified\n' > "${SNAPSHOT_PATH}/rollback-status.txt"
    else
      printf 'recovery_required\n' > "${SNAPSHOT_PATH}/rollback-status.txt"
    fi
    chmod 0600 "${SNAPSHOT_PATH}/rollback-status.txt" >/dev/null 2>&1 || true
  fi

  if [[ "${rollback_failed}" == "0" ]]; then
    log "CayVPN-owned files and prior service state were restored and verified."
  else
    log "Automatic recovery is incomplete. Do not rerun the installer. Keep the server and snapshot at ${SNAPSHOT_PATH} for SSH recovery."
  fi
  log "Packages installed before the failure may remain, but the installer did not remove owner data."
  (( status != 0 )) || status=1
  exit "${status}"
}


main() {
  log "Installing CayVPN ${RELEASE_VERSION}"
  check_platform
  check_release
  validate_release_source
  handle_existing_v2_install
  refuse_legacy_install
  validate_install_inputs
  check_resources_and_conflicts
  check_clean_vps_boundary
  PUBLIC_ENDPOINT="$(public_endpoint)"
  configure_dual_stack
  # Collect every required secret before snapshotting or changing the server.
  # A closed SSH window can now leave only a harmless prompt, never a partial install.
  prepare_recovery_passphrase
  snapshot_state
  verify_install_snapshot || die "The recovery snapshot did not pass its integrity check; no server changes were made."
  trap rollback_on_error ERR
  install_packages
  prepare_paths
  persist_release_trust
  cleanup_stale_netns_placeholders
  printf '%s\n' "${SNAPSHOT_PATH}" > "${STATE_DIR}/last-install-snapshot"
  install_release
  write_environment "${PUBLIC_ENDPOINT}"
  sync_native_components
  write_wireguard
  write_tls
  configure_dns_filtering
  write_firewall
  write_nginx
  write_services
  start_verify
  write_owner_kit
  trap - ERR
  log "Installation verified. CayVPN is ready for setup."
  log ""
  log "On your own computer, copy the private CayVPN setup folder with:"
  log "  scp ${OWNER_KIT_USER}@${PUBLIC_ENDPOINT}:${OWNER_KIT_PATH} ."
  log ""
  log "Then unzip it and open README.txt. It has three short pages."
  log "You will add CayVPN Settings to WireGuard, trust cayvpn-ca.crt, and open https://${ADMIN_HOSTNAME}:${ADMIN_HTTPS_PORT}"
  log "CayVPN will guide you through adding your first device and optional Location."
}

main "$@"
