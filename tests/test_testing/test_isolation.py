"""Tests for sqla_authz.testing._isolation — isolated_authz context manager."""

from __future__ import annotations

import pytest
from sqlalchemy import true

from sqla_authz.config._config import (
    AuthzConfig,
    _reset_global_config,
    configure,
    get_global_config,
)
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry
from sqla_authz.testing._isolation import isolated_authz
from tests.conftest import Post


class TestIsolatedAuthzContextManager:
    """Tests for the isolated_authz() context manager."""

    def setup_method(self) -> None:
        _reset_global_config()
        get_default_registry().clear()

    def teardown_method(self) -> None:
        _reset_global_config()
        get_default_registry().clear()

    def test_resets_config_on_entry(self) -> None:
        """Inside isolated_authz, config should be reset to defaults."""
        configure(on_missing_policy="raise")
        with isolated_authz() as (cfg, _reg):
            assert cfg.on_missing_policy == "deny"

    def test_restores_config_on_exit(self) -> None:
        """After exiting isolated_authz, original config is restored."""
        configure(on_missing_policy="raise", default_action="update")
        with isolated_authz():
            pass
        restored = get_global_config()
        assert restored.on_missing_policy == "raise"
        assert restored.default_action == "update"

    def test_restores_config_on_exception(self) -> None:
        """Config is restored even if the body raises."""
        configure(on_missing_policy="raise")
        with pytest.raises(RuntimeError):
            with isolated_authz():
                raise RuntimeError("boom")
        assert get_global_config().on_missing_policy == "raise"

    def test_applies_config_override(self) -> None:
        """isolated_authz(config=...) applies the override inside the block."""
        with isolated_authz(config=AuthzConfig(on_missing_policy="raise")) as (cfg, _reg):
            assert cfg.on_missing_policy == "raise"

    def test_clears_registry_on_entry(self) -> None:
        """Inside isolated_authz, default registry should be empty."""
        registry = get_default_registry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        with isolated_authz() as (_cfg, reg):
            assert reg.lookup(Post, "read") == []

    def test_restores_registry_on_exit(self) -> None:
        """After exiting isolated_authz, original registry policies are restored."""
        registry = get_default_registry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        with isolated_authz():
            pass
        assert len(registry.lookup(Post, "read")) == 1

    def test_restores_registry_on_exception(self) -> None:
        """Registry is restored even if the body raises."""
        registry = get_default_registry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        with pytest.raises(RuntimeError):
            with isolated_authz():
                raise RuntimeError("boom")
        assert len(registry.lookup(Post, "read")) == 1

    def test_yields_config_and_registry(self) -> None:
        """The context manager yields a (config, registry) tuple."""
        with isolated_authz() as result:
            cfg, reg = result
            assert isinstance(cfg, AuthzConfig)
            assert isinstance(reg, PolicyRegistry)

    def test_restores_all_12_config_fields(self) -> None:
        """All 12 config fields are restored exactly after exit."""
        original = AuthzConfig(
            on_missing_policy="raise",
            default_action="update",
            log_policy_decisions=True,
            on_unloaded_relationship="raise",
            strict_mode=True,
            on_unprotected_get="raise",
            on_text_query="raise",
            on_skip_authz="warn",
            audit_bypasses=True,
            intercept_updates=True,
            intercept_deletes=True,
            on_write_denied="filter",
        )
        from sqla_authz.config._config import _set_global_config

        _set_global_config(original)

        with isolated_authz():
            # Inside: should be defaults
            inner = get_global_config()
            assert inner.on_missing_policy == "deny"
            assert inner.strict_mode is False

        # After exit: all 12 fields restored exactly
        restored = get_global_config()
        assert restored.on_missing_policy == "raise"
        assert restored.default_action == "update"
        assert restored.log_policy_decisions is True
        assert restored.on_unloaded_relationship == "raise"
        assert restored.strict_mode is True
        assert restored.on_unprotected_get == "raise"
        assert restored.on_text_query == "raise"
        assert restored.on_skip_authz == "warn"
        assert restored.audit_bypasses is True
        assert restored.intercept_updates is True
        assert restored.intercept_deletes is True
        assert restored.on_write_denied == "filter"

    def test_strict_mode_with_custom_overrides_roundtrips(self) -> None:
        """strict_mode=True + custom on_unprotected_get='raise' roundtrips correctly."""
        original = AuthzConfig(
            strict_mode=True,
            on_unprotected_get="raise",
        )
        from sqla_authz.config._config import _set_global_config

        _set_global_config(original)

        with isolated_authz():
            pass

        restored = get_global_config()
        # Must be "raise" (user's explicit value), not re-defaulted to "warn"
        assert restored.on_unprotected_get == "raise"
        assert restored.strict_mode is True

    def test_restores_all_fields_on_exception(self) -> None:
        """All 12 fields are restored even when the body raises."""
        original = AuthzConfig(
            on_missing_policy="raise",
            default_action="delete",
            log_policy_decisions=True,
            on_unloaded_relationship="warn",
            strict_mode=False,
            on_unprotected_get="warn",
            on_text_query="warn",
            on_skip_authz="log",
            audit_bypasses=True,
            intercept_updates=True,
            intercept_deletes=True,
            on_write_denied="filter",
        )
        from sqla_authz.config._config import _set_global_config

        _set_global_config(original)

        with pytest.raises(RuntimeError):
            with isolated_authz():
                raise RuntimeError("boom")

        restored = get_global_config()
        assert restored.on_missing_policy == "raise"
        assert restored.default_action == "delete"
        assert restored.on_unloaded_relationship == "warn"
        assert restored.on_unprotected_get == "warn"
        assert restored.on_text_query == "warn"
        assert restored.on_skip_authz == "log"
        assert restored.audit_bypasses is True
        assert restored.intercept_updates is True
        assert restored.intercept_deletes is True
        assert restored.on_write_denied == "filter"

    def test_config_override_applies_all_fields(self) -> None:
        """isolated_authz(config=...) applies all fields, not just 3."""
        override = AuthzConfig(
            on_missing_policy="raise",
            strict_mode=True,
            on_unprotected_get="raise",
            intercept_updates=True,
        )
        with isolated_authz(config=override) as (cfg, _reg):
            assert cfg.on_missing_policy == "raise"
            assert cfg.strict_mode is True
            assert cfg.on_unprotected_get == "raise"
            assert cfg.intercept_updates is True


class TestIsolatedAuthzStateFixture:
    """Tests for the isolated_authz_state pytest fixture."""

    def test_provides_clean_state(self, isolated_authz_state) -> None:
        cfg, reg = isolated_authz_state
        assert cfg.on_missing_policy == "deny"
        assert reg.lookup(Post, "read") == []

    def test_isolation_a(self, isolated_authz_state) -> None:
        """Register something in one test..."""
        _cfg, reg = isolated_authz_state
        reg.register(Post, "read", lambda a: true(), name="p", description="")
        assert len(reg.lookup(Post, "read")) == 1

    def test_isolation_b(self, isolated_authz_state) -> None:
        """...and verify it doesn't leak to the next test."""
        _cfg, reg = isolated_authz_state
        assert reg.lookup(Post, "read") == []
