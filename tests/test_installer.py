import os
import subprocess
import sys
import tempfile
import unittest
import ipaddress
from pathlib import Path


class InstallerTests(unittest.TestCase):
    def test_native_component_preflight_runs_without_installed_python_packages(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable, "-I", "-S", "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "from cayvpn.components import validate_release_components; "
                "from cayvpn.config import Settings; "
                "assert 'cayvpn.web' not in sys.modules",
                str(root),
            ],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ed25519_verification_uses_raw_input_on_ubuntu_openssl(self):
        root = Path(__file__).resolve().parents[1]
        for script_name in ("install.sh", "bootstrap.sh"):
            script = (root / script_name).read_text()
            self.assertIn("pkeyutl -verify -rawin", script, script_name)
        release_builder = (root / "scripts" / "build-release.sh").read_text()
        self.assertIn("pkeyutl -sign -rawin", release_builder)

    def test_release_version_cannot_be_overwritten_by_os_release(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertIn('RELEASE_VERSION="${CAYVPN_RELEASE_VERSION:-2.0.0-dev}"', installer)
        self.assertNotIn('\nVERSION="${CAYVPN_RELEASE_VERSION', installer)

    def test_staged_virtual_environment_launchers_work_after_release_move(self):
        root = Path(__file__).resolve().parents[1]
        relocator = root / "scripts" / "relocate-venv.py"
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            staged = temporary_root / "release-staging"
            final = temporary_root / "releases" / "2.0.0"
            venv = staged / ".venv"
            bin_dir = venv / "bin"
            bin_dir.mkdir(parents=True)
            python_link = bin_dir / "python"
            python_link.symlink_to(sys.executable)
            launcher = bin_dir / "alembic"
            launcher.write_text(
                f"#!{staged}/.venv/bin/python\n"
                "print('wrapper-ok')\n"
            )
            launcher.chmod(0o755)
            activate = bin_dir / "activate"
            activate.write_text(f'VIRTUAL_ENV="{venv}"\n')
            configuration = venv / "pyvenv.cfg"
            configuration.write_text(
                f"command = {sys.executable} -m venv {venv}\n"
            )

            result = subprocess.run(
                [sys.executable, str(relocator), str(venv), str(staged), str(final)],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Relocated 3 virtual-environment launchers", result.stderr)
            self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
            self.assertNotIn(str(staged), launcher.read_text())
            self.assertIn(str(final), launcher.read_text())
            self.assertNotIn(str(staged), activate.read_text())
            self.assertNotIn(str(staged), configuration.read_text())
            final.parent.mkdir()
            staged.rename(final)
            relocated = subprocess.run(
                [str(final / ".venv" / "bin" / "alembic")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(relocated.returncode, 0, relocated.stderr)
            self.assertEqual(relocated.stdout.strip(), "wrapper-ok")

    def test_optional_remote_https_does_not_block_the_private_base_install(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        conflicts = installer.split("check_resources_and_conflicts() {", 1)[1].split(
            "\n}\n\nclean_vps_conflict()", 1
        )[0]
        validation = installer.split("validate_install_inputs() {", 1)[1].split(
            "\n}\n\npublic_endpoint()", 1
        )[0]
        self.assertNotIn('"${REMOTE_ADMIN_PORT}"; do', conflicts)
        self.assertIn('"${REMOTE_ADMIN_PORT}"; do', validation)
        self.assertIn('[[ "${REMOTE_ADMIN_PORT}" == "443" ]]', validation)

    def test_public_endpoint_preserves_upgrade_value_then_uses_default_route_source(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = installer.split("public_endpoint() {", 1)[1].split("\n}\n\nprepare_paths()", 1)[0]
        function = "public_endpoint() {" + function + "\n}"
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "cayvpn.env"
            env_file.write_text("CAYVPN_PUBLIC_ENDPOINT=8.8.8.8\n")
            script = f'''set -Eeuo pipefail
die() {{ return 1; }}
ENV_FILE={env_file}
OUT_IFACE=eth0
ip() {{
  if [[ "$*" == "-4 route get 1.1.1.1" ]]; then
    printf '%s\n' "1.1.1.1 via 192.0.2.1 dev eth0 src 9.9.9.9"
  else
    printf '%s\n' '[{{"addr_info":[{{"scope":"global","local":"1.1.1.1"}}]}}]'
  fi
}}
{function}
public_endpoint
'''
            preserved = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(preserved.returncode, 0, preserved.stderr)
            self.assertEqual(preserved.stdout, "8.8.8.8")

            env_file.write_text("")
            routed = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(routed.returncode, 0, routed.stderr)
            self.assertEqual(routed.stdout, "9.9.9.9")

    def test_clean_vps_boundary_refuses_existing_managed_state_before_firewall_changes(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        helper = installer.split("clean_vps_conflict() {", 1)[1].split(
            "\n}\n\ncheck_clean_vps_boundary()", 1
        )[0]
        boundary = installer.split("check_clean_vps_boundary() {", 1)[1].split(
            "\n}\n\nvalidate_install_inputs()", 1
        )[0]
        functions = (
            "clean_vps_conflict() {" + helper + "\n}\n\n"
            "check_clean_vps_boundary() {" + boundary + "\n}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            occupied = root / "install"
            occupied.mkdir()
            (occupied / "owner-data").write_text("preserve me")
            script = f"""set -Eeuo pipefail
log() {{ printf '%s\\n' "$*" >&2; }}
die() {{ log "ERROR: $*"; return 1; }}
INSTALL_ROOT={occupied}
STATE_DIR={root / "state"}
CONFIG_DIR={root / "config"}
{functions}
check_clean_vps_boundary
"""
            rejected = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("fresh, dedicated VPS", rejected.stderr)
        self.assertIn(str(occupied), rejected.stderr)
        main = installer.split("main() {", 1)[1]
        self.assertLess(main.index("check_clean_vps_boundary"), main.index("snapshot_state"))
        self.assertLess(main.index("check_clean_vps_boundary"), main.index("write_firewall"))
        self.assertIn("nft list ruleset", boundary)
        self.assertIn("iptables-save", boundary)
        self.assertIn("Status: active", boundary)
        self.assertIn("is_unmodified_packaged_nftables_config", boundary)
        self.assertIn("systemctl is-enabled --quiet nftables.service", boundary)
        self.assertIn("! -L /etc/nftables.conf", boundary)
        self.assertIn("dpkg-query -W -f='${Conffiles}", installer)
        self.assertIn("md5sum --", installer)
        self.assertIn("/opt/AdGuardHome", boundary)


    def test_installer_generates_and_persists_a_per_install_dual_stack_layout(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = installer.split("configure_dual_stack() {", 1)[1].split("\n}\n\nprepare_paths()", 1)[0]
        function = "configure_dual_stack() {" + function + "\n}"
        script = f'''set -Eeuo pipefail
die() {{ printf '%s' "$*" >&2; return 1; }}
ip() {{ return 1; }}
ULA_PREFIX=
WG_NETWORK_V6=
WG_ADDRESS_V6=
AWG_NETWORK_V6=
AWG_ADDRESS_V6=
EGRESS_NETWORK_V6=
CLIENT_DNS_V6=
CLIENT_ADBLOCK_DNS_V6=
PUBLIC_IPV6=
{function}
configure_dual_stack
printf '%s|' "$ULA_PREFIX" "$WG_NETWORK_V6" "$AWG_NETWORK_V6" "$EGRESS_NETWORK_V6" "$CLIENT_DNS_V6" "$CLIENT_ADBLOCK_DNS_V6"
'''
        generated = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        prefix, standard, amnezia, egress, dns, adblock_dns, _ = generated.stdout.split("|")
        parent = ipaddress.IPv6Network(prefix)
        self.assertEqual(parent.prefixlen, 48)
        self.assertEqual(parent.network_address.packed[0], 0xFD)
        networks = [ipaddress.IPv6Network(value) for value in (standard, amnezia, egress)]
        self.assertEqual(len(set(networks)), 3)
        self.assertTrue(all(item.prefixlen == 64 and item.subnet_of(parent) for item in networks))
        self.assertNotEqual(dns, adblock_dns)
        self.assertIn("CAYVPN_ULA_PREFIX=${ULA_PREFIX}", installer)
        self.assertIn("CAYVPN_USER_NETWORK_V6=${WG_NETWORK_V6}", installer)

    def test_explicit_public_ipv6_must_already_be_attached_and_routed(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = installer.split("configure_dual_stack() {", 1)[1].split("\n}\n\nprepare_paths()", 1)[0]
        function = "configure_dual_stack() {" + function + "\n}"
        script = f'''set -Eeuo pipefail
die() {{ printf '%s' "$*" >&2; return 1; }}
ip() {{
  if [[ "$*" == "-6 -o address show scope global" ]]; then
    printf '%s\n' "2: eth0 inet6 2606:4700:4700::9999/64 scope global"
    return 0
  fi
  return 1
}}
ULA_PREFIX=fd12:3456:789a::/48
WG_NETWORK_V6=
WG_ADDRESS_V6=
AWG_NETWORK_V6=
AWG_ADDRESS_V6=
EGRESS_NETWORK_V6=
CLIENT_DNS_V6=
CLIENT_ADBLOCK_DNS_V6=
PUBLIC_IPV6=2606:4700:4700::1234
{function}
configure_dual_stack
'''
        rejected = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("is not attached to this server", rejected.stderr)
        self.assertNotIn("doctl", function)
        self.assertNotIn("DIGITALOCEAN_TOKEN", function)

    def test_firewall_has_family_typed_nat_and_a_final_ipv6_leak_guard(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        firewall = installer.split("write_firewall() {", 1)[1].split("\n}\n\nwrite_nginx()", 1)[0]
        self.assertIn('snat ip to ip saddr map @cayvpn_snat_v4', firewall)
        self.assertIn('snat ip6 to ip6 saddr map @cayvpn_snat_v6', firewall)
        self.assertNotIn('ip saddr 169.254.0.0/16 masquerade', firewall)
        self.assertIn('oifname "${OUT_IFACE}" ip6 saddr ${ULA_PREFIX} drop', firewall)
        self.assertIn('iifname "${WG_IFACE}" ip saddr ${WG_NETWORK} tcp dport ${ADMIN_HTTPS_PORT} accept', firewall)
        self.assertIn('iifname "${AWG_IFACE}" ip saddr ${AWG_NETWORK} tcp dport ${ADMIN_HTTPS_PORT} accept', firewall)
        self.assertIn('meta nfproto ipv6 meta l4proto ipv6-icmp accept', firewall)
        self.assertIn('Address = ${WG_ADDRESS}, ${WG_ADDRESS_V6}', installer)
        admin_config = installer.split('cat > "${WG_DIR}/${ADMIN_IFACE}.conf" <<EOF', 1)[1].split("\nEOF", 1)[0]
        self.assertIn('Address = ${ADMIN_ADDRESS}', admin_config)
        self.assertNotIn('ADDRESS_V6', admin_config)
        self.assertIn('DNS = ${ADMIN_IP}, ${ADMIN_SEARCH_DOMAIN}', installer)
        self.assertIn('CAYVPN_EGRESS_NETWORK_V4=${EGRESS_NETWORK_V4}', installer)
        self.assertIn('CAYVPN_PROXY_TOKEN=${PROXY_TOKEN}', installer)
        self.assertIn('proxy_set_header X-CayVPN-Proxy-Token ${PROXY_TOKEN};', installer)
        self.assertIn('proxy_set_header X-Forwarded-For \\$remote_addr;', installer)
        self.assertNotIn('proxy_set_header X-Forwarded-For \\$proxy_add_x_forwarded_for;', installer)
        self.assertIn('chown root:root /etc/nginx/sites-available/cayvpn', installer)
        self.assertIn('chmod 0640 /etc/nginx/sites-available/cayvpn', installer)
        lock = (Path(__file__).resolve().parents[1] / "requirements.lock").read_text()
        self.assertIn("greenlet==3.5.5", lock)

    def test_owner_kit_uses_plain_paginated_setup_and_keeps_extra_security_optional(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertIn("Page 1 of 3 - Add secure access", installer)
        self.assertIn("Page 2 of 3 - Trust the private CayVPN page", installer)
        self.assertIn("Page 3 of 3 - Open CayVPN", installer)
        self.assertIn("name it CayVPN Settings", installer)
        self.assertIn("Show the one-time CayVPN Settings QR now?", installer)
        self.assertIn("Passwords, authenticator codes, and passkeys are optional", installer)
        self.assertNotIn("Show the one-time CayVPN Owner QR now?", installer)
        self.assertIn("turn on your normal CayVPN connection", installer)
        self.assertNotIn("Register a passkey from Security before making sensitive changes", installer)

    def test_verified_blocklist_is_readable_but_not_writable_by_the_web_service(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        prepare_paths = installer.split("prepare_paths() {", 1)[1].split(
            "\n}\n\npersist_release_trust()", 1
        )[0]
        filtering = installer.split("configure_dns_filtering() {", 1)[1].split(
            "\n}\n\nwrite_firewall()", 1
        )[0]

        self.assertIn('install -d -m 0750 -o root -g cayvpn "${CONFIG_DIR}/adblock"', prepare_paths)
        self.assertNotIn('install -d -m 0700 "${CONFIG_DIR}/adblock"', prepare_paths)
        self.assertLess(prepare_paths.index("useradd --system"), prepare_paths.index('"${CONFIG_DIR}/adblock"'))
        self.assertIn(
            'install -m 0640 -o root -g cayvpn -- "${blocklist_temporary}" "${blocklist_target}"',
            filtering,
        )
        self.assertIn(
            'runuser -u cayvpn -- test -r "${blocklist_target}"',
            filtering,
        )

    def test_snapshot_precedes_path_creation_and_private_nginx_probe_is_cleaned_up(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        main = installer.split("main() {", 1)[1]
        self.assertLess(main.index("prepare_recovery_passphrase"), main.index("snapshot_state"))
        self.assertLess(main.index("snapshot_state"), main.index("prepare_paths"))
        self.assertIn('ip -4 address add "${ADMIN_IP}/32" dev lo', installer)
        self.assertIn('ip -4 address delete "${ADMIN_IP}/32" dev lo', installer)
        self.assertIn('restore_snapshot_item "${SNAPSHOT_PATH}/state" "${STATE_DIR}"', installer)
        self.assertIn('snapshot-manifest.json', installer)
        self.assertIn('cayvpn-user-present', installer)
        self.assertIn('userdel cayvpn', installer)
        self.assertIn('groupdel cayvpn', installer)
        self.assertIn('52-cayvpn-security-updates', installer)
        self.assertIn('CAYVPN_RELEASE_DIR=${INSTALL_ROOT}/releases', installer)
        self.assertLess(main.index("snapshot_state"), main.index("install_packages"))
        self.assertLess(main.index("verify_install_snapshot"), main.index("trap rollback_on_error ERR"))
        self.assertLess(main.index("trap rollback_on_error ERR"), main.index("install_packages"))
        self.assertLess(main.index("validate_release_source"), main.index("snapshot_state"))
        self.assertIn('CayVPN installation path is too broad or is not normalized', installer)
        self.assertIn('The private admin DNS resolver is not active.', installer)
        self.assertIn('bind-dynamic', installer)
        self.assertNotIn('\nbind-interfaces\n', installer)
        self.assertIn('The standard WireGuard interface is not active.', installer)
        self.assertIn('nft list table inet cayvpn', installer)
        self.assertIn('die() { log "ERROR: $*"; return 1; }', installer)
        self.assertIn('chmod -R a+rX "${RELEASE_STAGING_DIR}"', installer)
        relocation_call = '"${RELEASE_STAGING_DIR}/scripts/relocate-venv.py"'
        release_move = 'mv -- "${RELEASE_STAGING_DIR}" "${RELEASE_DIR}"'
        wrapper_check = '"${RELEASE_DIR}/.venv/bin/alembic" --version'
        self.assertIn(relocation_call, installer)
        self.assertIn(wrapper_check, installer)
        self.assertLess(installer.index(relocation_call), installer.index(release_move))
        self.assertLess(installer.index(release_move), installer.index(wrapper_check))
        self.assertIn("staging path", installer)
        self.assertIn("--exclude='._*' --exclude='*/._*'", installer)
        self.assertIn("--exclude='.DS_Store' --exclude='*/.DS_Store'", installer)
        self.assertIn("--exclude='__MACOSX' --exclude='*/__MACOSX'", installer)
        self.assertIn('--exclude=.secrets --exclude=config --exclude=wireguard --exclude=releases', installer)
        self.assertIn('die "Database schema migration failed."', installer)
        self.assertNotIn('(cd "${RELEASE_STAGING_DIR}" && CAYVPN_DB_PATH=', installer)
        self.assertIn('ExecStart=${ACTIVE_RELEASE}/.venv/bin/python -m gunicorn', installer)
        self.assertIn('RuntimeDirectory=cayvpn', installer)
        self.assertIn('RuntimeDirectoryMode=0750', installer)
        self.assertIn('cleanup_stale_netns_placeholders', installer)
        self.assertIn('mountpoint -q -- "${path}" && continue', installer)
        self.assertIn('util-linux', installer)
        self.assertIn('run_release_python() {', installer)
        self.assertIn('run_release_python -m cayvpn.cli provision', installer)
        self.assertEqual(installer.count('run_release_python -m cayvpn.recovery protect-ca-key'), 2)
        self.assertIn('systemctl disable cayvpn-remote-admin-renew.timer cayvpn-web cayvpn-worker cayvpn-agent', installer)
        self.assertIn('rmdir -- "${INSTALL_ROOT}/releases"', installer)
        self.assertLess(main.index("install_release"), main.index("sync_native_components"))
        self.assertIn('components.lock.json', installer)
        self.assertIn('validate_release_components(Settings.from_env(source), source)', installer)
        self.assertIn('sync_release_components(Settings.from_env())', installer)
        self.assertNotIn("stage_optional_components", installer)
        self.assertNotIn("CAYVPN_AMNEZIAWG_TOOLS_SHA256", installer)
        self.assertNotIn("CAYVPN_SOCKS5_TUNNEL_SHA256", installer)
        self.assertNotIn("CAYVPN_LEGO_SHA256", installer)
        self.assertIn('ADBLOCK_FILTER_COMMIT=', installer)
        self.assertIn('ADBLOCK_FILTER_SHA256=', installer)
        self.assertIn("grep -Fq '||doubleclick.net^'", installer)
        self.assertNotIn("install_adguard", installer)
        self.assertNotIn("ADGUARD_VERSION", installer)
        self.assertNotIn("Downloading pinned AdGuard Home", installer)
        self.assertIn('cayvpn_remote_admin_ports', installer)
        self.assertNotIn('elements = { }', installer)
        self.assertIn('nft -j -n list set inet cayvpn cayvpn_remote_admin_ports', installer)
        self.assertIn('item["set"].get("type") == "inet_service"', installer)
        self.assertNotIn("grep -Eq 'elements = \\{[[:space:]]*\\}'", installer)
        self.assertIn('Remote owner access was not installed closed by default.', installer)
        self.assertIn('systemctl enable --now cayvpn-remote-admin-renew.timer', installer)
        self.assertIn('nginx-enabled-cayvpn-remote', installer)
        self.assertIn("Remote owner access must use CayVPN's fixed Let's Encrypt certificate service.", installer)
        self.assertIn('The CayVPN web service stopped during its readiness check.', installer)
        self.assertIn('for _ in $(seq 1 20); do\n    http_code=', installer)
        self.assertIn('chown -R cayvpn:cayvpn "${STATE_DIR}"', installer)
        self.assertIn('The CayVPN worker stopped during the private-panel readiness check.', installer)
        self.assertIn('set -a', installer)
        self.assertIn('. "${ENV_FILE}"', installer)
        self.assertIn('set +a', installer)
        self.assertIn('cd -- "${ACTIVE_RELEASE}"', installer)
        self.assertIn("set +e", installer)
        self.assertIn("recovery_required", installer)
        self.assertIn("restored CayVPN-owned files did not match the verified snapshot", installer)
        self.assertIn('if [[ -e "${SNAPSHOT_PATH}/nftables-live.conf" ]]; then', installer)
        self.assertIn(
            'cmp -s -- "${SNAPSHOT_PATH}/nftables-live.conf" <(nft list ruleset 2>/dev/null)',
            installer,
        )
        self.assertIn("the restored live firewall did not match the verified snapshot", installer)
        self.assertIn('systemctl enable --now nftables', installer)
        self.assertIn('The persistent CayVPN node was not marked verified.', installer)
        self.assertIn('The persistent CayVPN node recorded the wrong release.', installer)
        self.assertEqual(installer.count('Environment=PYTHONDONTWRITEBYTECODE=1'), 5)
        self.assertIn('--no-index --no-deps', installer)
        self.assertIn('persist_release_trust', installer)
        self.assertIn('cayvpn-update-recovery.service', installer)
        self.assertIn('wg show "${WG_IFACE}" listen-port', installer)
        self.assertIn('wg show "${ADMIN_IFACE}" listen-port', installer)
        self.assertIn('chmod 0644 "${WG_DIR}/awg-server.pub"', installer)
        self.assertIn('listen ${ADMIN_IP}:${ADMIN_HTTPS_PORT} ssl;', installer)
        self.assertIn('proxy_set_header Host \\$http_host;', installer)
        self.assertNotIn('proxy_set_header Host \\$host;', installer)
        self.assertLess(main.index("refuse_legacy_install"), main.index("snapshot_state"))
        self.assertLess(main.index("handle_existing_v2_install"), main.index("install_packages"))
        self.assertIn("is already installed. Running its signed health check instead of reinstalling it", installer)
        self.assertIn("Use Settings > CayVPN updates for a new version", installer)
        self.assertNotIn('RELEASE_DIR="${INSTALL_ROOT}/releases/${RELEASE_VERSION}-$(date', installer)
        self.assertIn('find "${content_dir}" -type l -print -quit', installer)
        self.assertIn('find "${content_dir}" -mindepth 1 ! -type d ! -type f -print -quit', installer)
        self.assertIn('die "Release content contains missing or unlisted files."', installer)
        self.assertLess(installer.index('Release content contains missing or unlisted files.'), installer.index('sha256sum --check --strict'))
        self.assertIn('while IFS= read -r manifest_line; do', installer)
        self.assertIn('filename="${BASH_REMATCH[2]}"', installer)
        self.assertNotIn('read -r checksum filename', installer)
        self.assertIn('refuse_legacy_install()', installer)
        self.assertIn('CayVPN 1.x is legacy and is not upgraded in place.', installer)
        self.assertIn('No files were changed', installer)
        self.assertNotIn('stage_legacy_database()', installer)
        self.assertNotIn('load_legacy_network_settings()', installer)
        self.assertNotIn('discover_legacy_install()', installer)
        self.assertNotIn('LEGACY_PANEL_PORT=', installer)
        self.assertNotIn('CAYVPN_ALLOW_PASSWORD_LOGIN=', installer)
        snapshot = installer.split('snapshot_state() {', 1)[1].split('\n}\n\ninstall_release()', 1)[0]
        self.assertNotIn('cayvpn.service', snapshot)

    def test_blank_recovery_passphrase_generates_a_strong_unambiguous_value(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = installer.split("generate_recovery_passphrase() {", 1)[1].split(
            "\n}\n\nrecovery_passphrase()", 1
        )[0]
        script = "generate_recovery_passphrase() {" + function + "\n}\ngenerate_recovery_passphrase\n"
        generated = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        passphrase = generated.stdout.strip()
        self.assertEqual(len(passphrase), 20)
        self.assertTrue(passphrase.isalnum())
        self.assertFalse(set(passphrase) & set("0O1Il"))
        self.assertIn("or press Enter to generate one", installer)
        self.assertIn("After saving it, press Enter to continue", installer)

    def test_cli_release_verification_pins_the_original_ed25519_key(self):
        cli = (Path(__file__).resolve().parents[1] / "cayvpn" / "cli.py").read_text()
        updates = (Path(__file__).resolve().parents[1] / "cayvpn" / "updates.py").read_text()
        self.assertIn("verify_installed_release", cli)
        self.assertIn("Ed25519PublicKey", updates)
        self.assertIn("release_key_mismatch", updates)
        self.assertIn("supplied != trusted", updates)

    def test_bootstrap_verifies_a_bounded_archive_before_extraction(self):
        bootstrap = (Path(__file__).resolve().parents[1] / "bootstrap.sh").read_text()
        self.assertRegex(bootstrap, r'(?m)^VERSION="[0-9]+\.[0-9]+\.[0-9]+"$')
        self.assertIn('REPOSITORY="caynetic/cayvpn"', bootstrap)
        self.assertNotIn("CAYVPN_RELEASE_KEY_SHA256", bootstrap)
        self.assertNotIn("CAYVPN_RELEASE_BASE_URL", bootstrap)
        self.assertNotIn("CAYVPN_REPOSITORY", bootstrap)
        self.assertIn('archive = tarfile.open(archive_path, "r:gz")', bootstrap)
        self.assertIn('if not (member.isdir() or member.isfile())', bootstrap)
        self.assertIn('if set(files) != set(manifest)', bootstrap)
        self.assertIn('with target.open("xb") as output', bootstrap)
        self.assertIn('expanded_bytes > 512 * 1024 * 1024', bootstrap)
        self.assertNotIn('tar -xzf "${WORK_DIR}/${ARCHIVE_NAME}"', bootstrap)
        self.assertIn('release.get("immutable") is not True', bootstrap)
        self.assertIn("The requested CayVPN release is not published and immutable", bootstrap)
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", bootstrap)
        self.assertIn("--noproxy '*'", bootstrap)

    def test_signed_install_preserves_the_exact_verified_source_inventory(self):
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        install_release = installer.split("install_release() {", 1)[1].split("\n}\n\nwrite_environment()", 1)[0]
        signed_branch = install_release.split('if [[ -n "${CAYVPN_RELEASE_MANIFEST:-}"', 1)[1].split("  else\n", 1)[0]
        self.assertIn('tar -C "${SOURCE_DIR}" -cf - .', signed_branch)
        self.assertNotIn("--exclude", signed_branch)
        self.assertIn(
            'PYTHONDONTWRITEBYTECODE=1 "${ACTIVE_RELEASE}/.venv/bin/python" "$@"',
            installer,
        )
        self.assertIn(
            'PYTHONDONTWRITEBYTECODE=1 "${RELEASE_STAGING_DIR}/.venv/bin/python" -m alembic',
            installer,
        )
        self.assertIn(
            'set +a\nexport PYTHONDONTWRITEBYTECODE=1\ncd -- "${ACTIVE_RELEASE}"',
            installer,
        )

    def test_release_build_uses_verified_offline_wheelhouses(self):
        root = Path(__file__).resolve().parents[1]
        preparation = (root / "scripts" / "prepare-wheelhouse.sh").read_text()
        builder = (root / "scripts" / "build-release.sh").read_text()
        artifact_validator = (root / "scripts" / "validate-release-artifacts.py").read_text()
        preflight = (root / "scripts" / "release-preflight.sh").read_text()
        self.assertIn("validate_wheelhouse", preparation)
        self.assertIn("wheelhouse does not exactly match requirements.lock", preparation)
        self.assertIn('metadata.get("Version", "")', preparation)
        self.assertIn("sha256sum --check --strict SHA256SUMS", preparation)
        self.assertIn('[[ -f "${WHEELHOUSE}/SHA256SUMS" ]]', builder)
        self.assertIn("transport checksum verification", builder)
        self.assertIn('MINIMUM_VERSION="${CAYVPN_MINIMUM_VERSION:-2.0.0-dev}"', builder)
        self.assertIn('RELEASE_PYTHON="${CAYVPN_RELEASE_PYTHON:-python3.12}"', builder)
        self.assertIn('ARTIFACT_LOCK="${ROOT}/release-locks/${VERSION}.json"', builder)
        self.assertIn('git -C "${ROOT}" ls-files --error-unmatch', builder)
        self.assertIn("validate-release-artifacts.py", builder)
        self.assertIn("release-preflight.sh", builder)
        self.assertLess(builder.index("release-preflight.sh"), builder.index("pkeyutl -sign"))
        self.assertIn("components.lock.json", builder)
        self.assertIn('FINAL_ASSETS="${OUTPUT_DIR}/${FOLDER}-release"', builder)
        self.assertIn('mv -- "${STAGED_ASSETS}" "${FINAL_ASSETS}"', builder)
        self.assertIn('BOOTSTRAP_VERSION=', builder)
        self.assertIn('Set VERSION in bootstrap.sh to ${VERSION}', builder)
        self.assertIn('METADATA_FILE="${5:-}"', builder)
        self.assertIn('release impact metadata may contain only the documented optional fields', builder)
        self.assertIn('expected_interruption_seconds', builder)
        self.assertIn('COMPONENT_BUNDLE="${CAYVPN_COMPONENT_BUNDLE:-}"', builder)
        self.assertIn('offline_optional_components', builder)
        self.assertIn("export COPYFILE_DISABLE=1", builder)
        self.assertLess(
            builder.index("export COPYFILE_DISABLE=1"),
            builder.index('tar --no-xattrs -C "${WORK_DIR}" -cf "${WORK_DIR}/source-with-wheels.tar"'),
        )
        self.assertIn('source/amneziawg-tools-source.tar.gz', artifact_validator)
        self.assertIn('(3, 12)', preflight)
        self.assertIn("-W error::ResourceWarning", preflight)
        self.assertIn("-m unittest discover -s tests", preflight)
        self.assertIn("shellcheck", preflight)
        workflow = (root / ".github" / "workflows" / "build-optional-components.yml").read_text()
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1", workflow)
        self.assertIn("ee0f0a9aa34ff0a0da4b3433b9512781cfe02843", workflow)
        self.assertIn("958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba", workflow)
        self.assertIn("amneziawg-tools-source.tar.gz", workflow)
        self.assertIn("589c84af4f26629fbdaa7fbca712f806632ccb7e", workflow)
        self.assertIn(
            'build -trimpath -ldflags \'-s -w\' -o "${output}/${ARCHITECTURE}/lego" .',
            workflow,
        )
        self.assertNotIn("./cmd/lego", workflow)

    def test_release_preflight_rejects_a_non_python_312_interpreter_first(self):
        root = Path(__file__).resolve().parents[1]
        preflight = root / "scripts" / "release-preflight.sh"
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["bash", str(preflight), directory],
                capture_output=True,
                text=True,
                check=False,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "CAYVPN_RELEASE_PYTHON": "/bin/sh",
                },
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must resolve to Python 3.12", result.stderr)

    def test_release_preflight_stops_when_git_status_fails_without_output(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            tools = work / "bin"
            tools.mkdir()
            for name, body in {
                "git": "exit 128\n",
                "shellcheck": "exit 0\n",
                "node": "exit 0\n",
                "python3.12": 'if [ "$1" = -c ]; then exit 0; fi\nexit 99\n',
            }.items():
                command = tools / name
                command.write_text("#!/bin/sh\n" + body)
                command.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(root / "scripts" / "release-preflight.sh"), str(work)],
                capture_output=True,
                text=True,
                check=False,
                env={
                    "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
                    "CAYVPN_RELEASE_PYTHON": str(tools / "python3.12"),
                },
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unable to verify release worktree status", result.stderr)
        self.assertNotIn("Creating an offline", result.stderr)


    def test_malformed_python_is_rejected_before_migration_or_signing(self):
        root = Path(__file__).resolve().parents[1]
        validator = root / "scripts" / "validate-python-source.py"
        installer = (root / "install.sh").read_text()
        builder = (root / "scripts" / "build-release.sh").read_text()

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "valid.py").write_text("value = 1\n")
            (source / "broken.py").write_text("def broken(:\n")
            rejected = subprocess.run(
                [sys.executable, str(validator), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("broken.py", rejected.stderr)

            (source / "broken.py").unlink()
            ignored = source / ".venv"
            ignored.mkdir()
            (ignored / "generated.py").write_text("def generated(:\n")
            accepted = subprocess.run(
                [sys.executable, str(validator), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("Validated 1 Python source files", accepted.stderr)

            hostile = source / "cayvpn" / "venv"
            hostile.mkdir(parents=True)
            (hostile / "hidden.py").write_text("def hidden(:\n")
            nested_rejected = subprocess.run(
                [sys.executable, str(validator), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(nested_rejected.returncode, 0)
            self.assertIn("cayvpn/venv/hidden.py", nested_rejected.stderr)

        validation_command = '"${RELEASE_STAGING_DIR}/scripts/validate-python-source.py"'
        migration_command = '"${RELEASE_STAGING_DIR}/.venv/bin/python" -m alembic'
        self.assertIn(validation_command, installer)
        self.assertLess(installer.index(validation_command), installer.index(migration_command))
        self.assertIn(
            '"${RELEASE_PYTHON}" "${ROOT}/scripts/validate-python-source.py"',
            builder,
        )
        main = installer.split("main() {", 1)[1]
        self.assertLess(main.index("validate_release_source"), main.index("snapshot_state"))
        self.assertLess(main.index("validate_release_source"), main.index("install_packages"))
        self.assertLess(
            builder.index("validate-python-source.py"),
            builder.index('> "${MANIFEST}"'),
        )

if __name__ == "__main__":
    unittest.main()
