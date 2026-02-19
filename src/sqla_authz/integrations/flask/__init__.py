"""Flask integration for sqla-authz."""

from __future__ import annotations

try:
    import flask as _flask_check  # noqa: F401  # pyright: ignore[reportUnusedImport]

    del _flask_check
except ImportError as exc:
    raise ImportError(
        "Flask integration requires flask. Install it with: pip install sqla-authz[flask]"
    ) from exc

from sqla_authz.integrations.flask._extension import AuthzExtension

__all__ = ["AuthzExtension"]
