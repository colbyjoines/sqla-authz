"""sqla-authz pytest plugin -- auto-discovered via pytest11 entry point.

This module is registered as a pytest plugin in ``pyproject.toml``::

    [project.entry-points.pytest11]
    sqla_authz = "sqla_authz.testing._plugin"

All fixtures defined here are automatically available in projects
that install sqla-authz.
"""

from __future__ import annotations

# Re-export fixtures so they are auto-discovered by pytest.
from sqla_authz.testing._fixtures import (  # noqa: F401
    authz_config,
    authz_context,
    authz_registry,
    isolated_authz_state,
)

__all__ = ["authz_config", "authz_context", "authz_registry", "isolated_authz_state"]
