"""FastAPI integration for sqla-authz."""

from __future__ import annotations

__all__ = [
    "AuthzDep",
    "get_actor",
    "get_session",
    "install_authz_interceptor",
    "install_error_handlers",
]

_import_error: ImportError | None = None

try:
    from sqla_authz.integrations.fastapi._dependencies import (
        AuthzDep,
        get_actor,
        get_session,
    )
    from sqla_authz.integrations.fastapi._errors import install_error_handlers
    from sqla_authz.integrations.fastapi._middleware import install_authz_interceptor
except ModuleNotFoundError as exc:
    if exc.name is None or exc.name.split(".")[0] != "fastapi":
        raise
    _import_error = ImportError(
        "sqla_authz FastAPI integration requires FastAPI. "
        'Install with `pip install "sqla-authz[fastapi]"`.'
    )


def __getattr__(name: str) -> object:
    if name in __all__ and _import_error is not None:
        raise _import_error from None
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
