"""Configuration module for sqla-authz."""

from __future__ import annotations

from sqla_authz.config._config import AuthzConfig, configure, get_global_config

__all__ = ["AuthzConfig", "configure", "get_global_config"]
