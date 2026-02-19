"""Tests for AuthzConfig — layered configuration."""

from __future__ import annotations

import pytest

from sqla_authz.config._config import (
    AuthzConfig,
    _reset_global_config,
    configure,
    get_global_config,
)


class TestAuthzConfigDefaults:
    """Test default configuration values."""

    def test_default_on_missing_policy(self) -> None:
        config = AuthzConfig()
        assert config.on_missing_policy == "deny"

    def test_default_action(self) -> None:
        config = AuthzConfig()
        assert config.default_action == "read"


class TestAuthzConfigFrozen:
    """Test that AuthzConfig is immutable."""

    def test_cannot_set_on_missing_policy(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.on_missing_policy = "raise"  # type: ignore[misc]

    def test_cannot_set_default_action(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.default_action = "write"  # type: ignore[misc]


class TestAuthzConfigMerge:
    """Test merge semantics for layered configuration."""

    def test_merge_overrides_on_missing_policy(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_missing_policy="raise")
        assert merged.on_missing_policy == "raise"
        assert merged.default_action == "read"  # unchanged

    def test_merge_overrides_default_action(self) -> None:
        config = AuthzConfig()
        merged = config.merge(default_action="update")
        assert merged.default_action == "update"
        assert merged.on_missing_policy == "deny"  # unchanged

    def test_merge_with_no_overrides(self) -> None:
        config = AuthzConfig()
        merged = config.merge()
        assert merged.on_missing_policy == "deny"
        assert merged.default_action == "read"

    def test_merge_with_none_values_does_not_override(self) -> None:
        config = AuthzConfig(on_missing_policy="raise")
        merged = config.merge(on_missing_policy=None)
        assert merged.on_missing_policy == "raise"

    def test_merge_returns_new_instance(self) -> None:
        config = AuthzConfig()
        merged = config.merge(default_action="write")
        assert config is not merged
        assert config.default_action == "read"  # original unchanged

    def test_merge_multiple_overrides(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_missing_policy="raise", default_action="delete")
        assert merged.on_missing_policy == "raise"
        assert merged.default_action == "delete"


class TestGlobalConfig:
    """Test global config get/set/configure."""

    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_get_global_config_returns_defaults(self) -> None:
        config = get_global_config()
        assert config.on_missing_policy == "deny"
        assert config.default_action == "read"

    def test_configure_sets_global_config(self) -> None:
        configure(on_missing_policy="raise")
        config = get_global_config()
        assert config.on_missing_policy == "raise"

    def test_configure_merges_with_existing(self) -> None:
        configure(on_missing_policy="raise")
        configure(default_action="update")
        config = get_global_config()
        assert config.on_missing_policy == "raise"
        assert config.default_action == "update"

    def test_configure_returns_new_config(self) -> None:
        result = configure(default_action="write")
        assert isinstance(result, AuthzConfig)
        assert result.default_action == "write"


class TestConfigLayering:
    """Test configuration layering: global -> session -> query."""

    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_session_config_overrides_global(self) -> None:
        configure(on_missing_policy="deny", default_action="read")
        global_config = get_global_config()
        session_config = global_config.merge(on_missing_policy="raise")
        assert session_config.on_missing_policy == "raise"
        assert session_config.default_action == "read"  # inherited from global

    def test_query_config_overrides_session(self) -> None:
        configure(on_missing_policy="deny")
        global_config = get_global_config()
        session_config = global_config.merge(on_missing_policy="raise")
        query_config = session_config.merge(default_action="delete")
        assert query_config.on_missing_policy == "raise"  # from session
        assert query_config.default_action == "delete"  # query override

    def test_full_layering_chain(self) -> None:
        # Global defaults
        configure(on_missing_policy="deny", default_action="read")
        global_cfg = get_global_config()

        # Session layer overrides on_missing_policy
        session_cfg = global_cfg.merge(on_missing_policy="raise")

        # Query layer overrides default_action
        query_cfg = session_cfg.merge(default_action="update")

        assert query_cfg.on_missing_policy == "raise"
        assert query_cfg.default_action == "update"
