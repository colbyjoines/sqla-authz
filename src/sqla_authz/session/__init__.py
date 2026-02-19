"""Session module for sqla-authz — automatic authorization interception."""

from __future__ import annotations

from sqla_authz.session._context import AuthorizationContext
from sqla_authz.session._interceptor import authorized_sessionmaker, install_interceptor

__all__ = ["AuthorizationContext", "authorized_sessionmaker", "install_interceptor"]
