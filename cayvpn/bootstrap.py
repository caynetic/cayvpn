from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

from sqlalchemy import select

from .config import Settings
from .db import Database
from .models import AdminDevice, ManagedNode, Setting


def bootstrap(settings: Settings, admin_public_key: str, admin_address: str = "10.255.0.2/32") -> None:
    if not admin_public_key or len(admin_public_key) < 40:
        raise ValueError("A valid admin WireGuard public key is required")
    try:
        address = ipaddress.ip_interface(admin_address)
        if address.version != 4 or address.network.prefixlen != 32 or address.ip not in ipaddress.ip_network(settings.admin_network, strict=False):
            raise ValueError
    except ValueError as exc:
        raise ValueError("The initial admin address must be an IPv4 /32 in the admin network") from exc
    with Database(settings) as db:
        db.initialize_defaults(settings)
        with db.session() as session:
            node = session.get(ManagedNode, 1)
            node.install_state = "verified"
            node.release = os.environ.get("CAYVPN_RELEASE_VERSION", "2.0.0-dev")
            node.updated_at = node.created_at
            if session.scalar(select(AdminDevice.id).where(AdminDevice.public_key == admin_public_key)) is None:
                session.add(AdminDevice(name="Initial admin device", public_key=admin_public_key, address=admin_address, enabled=True))
            marker = session.get(Setting, "admin_bootstrapped")
            if marker is None:
                session.add(Setting(key="admin_bootstrapped", value="1"))
            else:
                marker.value = "1"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cayvpn-bootstrap")
    parser.add_argument("--admin-public-key", required=True)
    parser.add_argument("--admin-address", default="10.255.0.2/32")
    args = parser.parse_args(argv)
    bootstrap(Settings.from_env(), args.admin_public_key, args.admin_address)
    print(json.dumps({"install_state": "verified", "admin_address": args.admin_address}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
