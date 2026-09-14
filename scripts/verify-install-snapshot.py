#!/usr/bin/env python3
"""Verify a CayVPN installer snapshot before and after rollback restoration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path


IGNORED_SNAPSHOT_FILES = {
    "snapshot-manifest.json",
    ".snapshot-manifest.json.new",
    "rollback-status.txt",
}


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def inventory(root: Path, *, snapshot_root: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        base = Path(directory)
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
            if snapshot_root and relative in IGNORED_SNAPSHOT_FILES:
                continue
            if path.is_symlink():
                result[relative] = f"symlink:{os.readlink(path)}"
            elif path.is_file():
                result[relative] = f"file:{digest(path)}"
            else:
                raise ValueError(f"unsupported snapshot entry: {relative}")
    return dict(sorted(result.items()))


def same_path(source: Path, destination: Path) -> bool:
    source_present = source.exists() or source.is_symlink()
    destination_present = destination.exists() or destination.is_symlink()
    if source_present != destination_present:
        return False
    if not source_present:
        return True
    if source.is_symlink() or destination.is_symlink():
        return (
            source.is_symlink()
            and destination.is_symlink()
            and os.readlink(source) == os.readlink(destination)
        )
    if source.is_file() or destination.is_file():
        return source.is_file() and destination.is_file() and digest(source) == digest(destination)
    return source.is_dir() and destination.is_dir() and inventory(source) == inventory(destination)


def expected_paths(arguments: argparse.Namespace) -> dict[str, str]:
    return {
        "install_root": str(arguments.install_root),
        "active_release": str(arguments.active_release),
        "state_dir": str(arguments.state_dir),
        "config_dir": str(arguments.config_dir),
        "wireguard_dir": str(arguments.wireguard_dir),
        "snapshot_root": str(arguments.snapshot_root),
    }


def verify_manifest(arguments: argparse.Namespace) -> dict[str, object]:
    snapshot = arguments.snapshot
    if (
        not snapshot.is_dir()
        or snapshot.is_symlink()
        or snapshot.resolve().parent != arguments.snapshot_root.resolve()
        or stat.S_IMODE(snapshot.stat().st_mode) & 0o077
    ):
        raise ValueError("snapshot directory is missing, outside its root, or not root-private")
    manifest_path = snapshot / "snapshot-manifest.json"
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or manifest_path.stat().st_size > 8 * 1024 * 1024
    ):
        raise ValueError("snapshot manifest is missing or unsafe")
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or set(document) != {"format", "paths", "interfaces", "inventory"}
        or document.get("format") != 1
        or document.get("paths") != expected_paths(arguments)
        or document.get("interfaces")
        != {
            "user": arguments.user_interface,
            "amnezia": arguments.amnezia_interface,
            "admin": arguments.admin_interface,
        }
        or not isinstance(document.get("inventory"), dict)
    ):
        raise ValueError("snapshot manifest does not match this installation")
    observed = inventory(snapshot, snapshot_root=True)
    if observed != document["inventory"]:
        raise ValueError("snapshot content no longer matches its integrity manifest")
    return document


def verify_restored(arguments: argparse.Namespace) -> None:
    mappings = (
        ("wireguard", arguments.wireguard_dir),
        ("cayvpn", arguments.config_dir),
        ("state", arguments.state_dir),
        ("nftables.conf", Path("/etc/nftables.conf")),
        ("99-cayvpn-forwarding.conf", Path("/etc/sysctl.d/99-cayvpn-forwarding.conf")),
        ("external/cayvpn-admin.conf", Path("/etc/dnsmasq.d/cayvpn-admin.conf")),
        ("external/nginx-cayvpn", Path("/etc/nginx/sites-available/cayvpn")),
        ("external/nginx-enabled-cayvpn", Path("/etc/nginx/sites-enabled/cayvpn")),
        ("external/nginx-enabled-cayvpn-remote", Path("/etc/nginx/sites-enabled/cayvpn-remote")),
        ("external/nginx-enabled-default", Path("/etc/nginx/sites-enabled/default")),
        (
            "external/nginx-cayvpn-dropin",
            Path("/etc/systemd/system/nginx.service.d/10-cayvpn-admin.conf"),
        ),
        ("external/cayvpnctl", Path("/usr/local/bin/cayvpnctl")),
        (
            "external/52-cayvpn-security-updates",
            Path("/etc/apt/apt.conf.d/52-cayvpn-security-updates"),
        ),
    )
    units = (
        "cayvpn-update-recovery.service",
        "cayvpn-agent.service",
        "cayvpn-worker.service",
        "cayvpn-web.service",
        "cayvpn-remote-admin-renew.service",
        "cayvpn-remote-admin-renew.timer",
    )
    mappings += tuple(
        (unit, Path("/etc/systemd/system") / unit) for unit in units
    )
    failed = [
        str(destination)
        for relative, destination in mappings
        if not same_path(arguments.snapshot / relative, destination)
    ]
    if failed:
        raise ValueError(
            "restored filesystem does not match the snapshot: " + ", ".join(failed)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("install_root", type=Path)
    parser.add_argument("active_release", type=Path)
    parser.add_argument("state_dir", type=Path)
    parser.add_argument("config_dir", type=Path)
    parser.add_argument("wireguard_dir", type=Path)
    parser.add_argument("snapshot_root", type=Path)
    parser.add_argument("user_interface")
    parser.add_argument("amnezia_interface")
    parser.add_argument("admin_interface")
    parser.add_argument("--restored", action="store_true")
    arguments = parser.parse_args()
    try:
        verify_manifest(arguments)
        if arguments.restored:
            verify_restored(arguments)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: CayVPN install snapshot verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        "CayVPN install snapshot and restored files verified."
        if arguments.restored
        else "CayVPN install snapshot verified.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
