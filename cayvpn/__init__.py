"""CayVPN 2.0 management appliance.

The package deliberately separates the web application from privileged node
operations.  The public ``app.py`` module is kept as a small WSGI shim for
existing deployments.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings

__version__ = "2.0.0-dev"


def create_app(settings: Settings | None = None):
    # Installer preflight imports the stdlib-only configuration and component
    # modules before the signed wheelhouse is installed. Load web dependencies
    # only when a caller actually requests the application factory.
    from .web import create_app as factory

    return factory(settings)

__all__ = ["create_app", "__version__"]
