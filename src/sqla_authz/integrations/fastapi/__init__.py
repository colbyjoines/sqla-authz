"""FastAPI integration for sqla-authz."""

from __future__ import annotations

try:
    import fastapi as _fastapi_check  # noqa: F401  # pyright: ignore[reportUnusedImport]

    del _fastapi_check
except ImportError as exc:
    raise ImportError(
        "FastAPI integration requires fastapi. Install it with: pip install sqla-authz[fastapi]"
    ) from exc

from sqla_authz.integrations.fastapi._dependencies import AuthzDep, configure_authz
from sqla_authz.integrations.fastapi._errors import install_error_handlers

__all__ = ["AuthzDep", "configure_authz", "install_error_handlers"]
