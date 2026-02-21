"""Session module for sqla-authz — automatic authorization interception."""

from __future__ import annotations

from sqla_authz.session._context import AuthorizationContext
from sqla_authz.session._interceptor import authorized_sessionmaker, install_interceptor
from sqla_authz.session._safe_get import (
    async_safe_get,
    async_safe_get_or_raise,
    safe_get,
    safe_get_or_raise,
)

__all__ = [
    "AuthorizationContext",
    "async_safe_get",
    "async_safe_get_or_raise",
    "authorized_sessionmaker",
    "install_interceptor",
    "safe_get",
    "safe_get_or_raise",
]
