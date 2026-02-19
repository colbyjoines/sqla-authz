"""Tests for sqla_authz.testing._plugin — pytest plugin registration."""

from __future__ import annotations

from sqla_authz.testing import _plugin


class TestPluginExports:
    """The plugin module re-exports fixture functions for auto-discovery."""

    def test_exports_authz_registry(self) -> None:
        assert hasattr(_plugin, "authz_registry")

    def test_exports_authz_config(self) -> None:
        assert hasattr(_plugin, "authz_config")

    def test_exports_authz_context(self) -> None:
        assert hasattr(_plugin, "authz_context")
