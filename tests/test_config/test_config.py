"""Tests for AuthzConfig — layered configuration."""

from __future__ import annotations

import pytest

from sqla_authz._types import OnMissingPolicy
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


class TestOnMissingPolicyType:
    """Test the OnMissingPolicy type alias exists and is usable."""

    def test_type_alias_exists(self) -> None:
        # OnMissingPolicy should be importable from _types
        assert OnMissingPolicy is not None

    def test_valid_deny_value(self) -> None:
        val: OnMissingPolicy = "deny"
        assert val == "deny"

    def test_valid_raise_value(self) -> None:
        val: OnMissingPolicy = "raise"
        assert val == "raise"


class TestAuthzConfigValidation:
    """Test runtime validation of on_missing_policy."""

    def test_deny_is_valid(self) -> None:
        config = AuthzConfig(on_missing_policy="deny")
        assert config.on_missing_policy == "deny"

    def test_raise_is_valid(self) -> None:
        config = AuthzConfig(on_missing_policy="raise")
        assert config.on_missing_policy == "raise"

    def test_invalid_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="on_missing_policy"):
            AuthzConfig(on_missing_policy="banana")  # type: ignore[arg-type]

    def test_case_sensitive_deny(self) -> None:
        with pytest.raises(ValueError, match="on_missing_policy"):
            AuthzConfig(on_missing_policy="DENY")  # type: ignore[arg-type]

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="on_missing_policy"):
            AuthzConfig(on_missing_policy="")  # type: ignore[arg-type]

    def test_merge_with_valid_value(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_missing_policy="raise")
        assert merged.on_missing_policy == "raise"

    def test_merge_with_invalid_value_raises(self) -> None:
        config = AuthzConfig()
        with pytest.raises(ValueError, match="on_missing_policy"):
            config.merge(on_missing_policy="invalid")  # type: ignore[arg-type]

    def test_configure_with_valid_value(self) -> None:
        _reset_global_config()
        try:
            configure(on_missing_policy="raise")
            assert get_global_config().on_missing_policy == "raise"
        finally:
            _reset_global_config()

    def test_configure_with_invalid_value_raises(self) -> None:
        _reset_global_config()
        try:
            with pytest.raises(ValueError, match="on_missing_policy"):
                configure(on_missing_policy="invalid")  # type: ignore[arg-type]
        finally:
            _reset_global_config()


# ---------------------------------------------------------------------------
# Strict mode configuration tests
# ---------------------------------------------------------------------------


class TestStrictModeConfigDefaults:
    """Test default values for strict mode fields."""

    def test_strict_mode_defaults_to_false(self) -> None:
        config = AuthzConfig()
        assert config.strict_mode is False

    def test_on_unprotected_get_defaults_to_ignore(self) -> None:
        config = AuthzConfig()
        assert config.on_unprotected_get == "ignore"

    def test_on_text_query_defaults_to_ignore(self) -> None:
        config = AuthzConfig()
        assert config.on_text_query == "ignore"

    def test_on_skip_authz_defaults_to_ignore(self) -> None:
        config = AuthzConfig()
        assert config.on_skip_authz == "ignore"

    def test_audit_bypasses_defaults_to_false(self) -> None:
        config = AuthzConfig()
        assert config.audit_bypasses is False


class TestStrictModeConfigValidation:
    """Test validation of strict mode fields."""

    def test_valid_on_unprotected_get_values(self) -> None:
        for val in ("ignore", "warn", "raise"):
            config = AuthzConfig(on_unprotected_get=val)  # type: ignore[arg-type]
            assert config.on_unprotected_get == val

    def test_invalid_on_unprotected_get_raises(self) -> None:
        with pytest.raises(ValueError, match="on_unprotected_get"):
            AuthzConfig(on_unprotected_get="invalid")  # type: ignore[arg-type]

    def test_valid_on_text_query_values(self) -> None:
        for val in ("ignore", "warn", "raise"):
            config = AuthzConfig(on_text_query=val)  # type: ignore[arg-type]
            assert config.on_text_query == val

    def test_invalid_on_text_query_raises(self) -> None:
        with pytest.raises(ValueError, match="on_text_query"):
            AuthzConfig(on_text_query="invalid")  # type: ignore[arg-type]

    def test_valid_on_skip_authz_values(self) -> None:
        for val in ("ignore", "warn", "log"):
            config = AuthzConfig(on_skip_authz=val)  # type: ignore[arg-type]
            assert config.on_skip_authz == val

    def test_invalid_on_skip_authz_raises(self) -> None:
        with pytest.raises(ValueError, match="on_skip_authz"):
            AuthzConfig(on_skip_authz="invalid")  # type: ignore[arg-type]

    def test_on_skip_authz_raise_is_invalid(self) -> None:
        """'raise' is not valid for on_skip_authz (only ignore/warn/log)."""
        with pytest.raises(ValueError, match="on_skip_authz"):
            AuthzConfig(on_skip_authz="raise")  # type: ignore[arg-type]


class TestStrictModeConvenience:
    """Test strict_mode=True convenience defaults."""

    def test_strict_mode_applies_defaults(self) -> None:
        config = AuthzConfig(strict_mode=True)
        assert config.on_unprotected_get == "warn"
        assert config.on_text_query == "warn"
        assert config.on_skip_authz == "log"
        assert config.audit_bypasses is True

    def test_strict_mode_preserves_explicit_overrides(self) -> None:
        config = AuthzConfig(
            strict_mode=True,
            on_unprotected_get="raise",
            on_text_query="raise",
            on_skip_authz="warn",
        )
        assert config.on_unprotected_get == "raise"
        assert config.on_text_query == "raise"
        assert config.on_skip_authz == "warn"

    def test_non_strict_does_not_apply_defaults(self) -> None:
        config = AuthzConfig(strict_mode=False)
        assert config.on_unprotected_get == "ignore"
        assert config.on_text_query == "ignore"
        assert config.on_skip_authz == "ignore"
        assert config.audit_bypasses is False


class TestStrictModeConfigMerge:
    """Test merge with strict mode fields."""

    def test_merge_strict_mode(self) -> None:
        config = AuthzConfig()
        merged = config.merge(strict_mode=True)
        assert merged.strict_mode is True
        # Convenience defaults applied
        assert merged.on_unprotected_get == "warn"

    def test_merge_on_unprotected_get(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_unprotected_get="raise")
        assert merged.on_unprotected_get == "raise"

    def test_merge_on_text_query(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_text_query="warn")
        assert merged.on_text_query == "warn"

    def test_merge_on_skip_authz(self) -> None:
        config = AuthzConfig()
        merged = config.merge(on_skip_authz="log")
        assert merged.on_skip_authz == "log"

    def test_merge_audit_bypasses(self) -> None:
        config = AuthzConfig()
        merged = config.merge(audit_bypasses=True)
        assert merged.audit_bypasses is True

    def test_merge_none_does_not_override_strict_fields(self) -> None:
        config = AuthzConfig(on_unprotected_get="raise", on_text_query="warn")
        merged = config.merge(on_unprotected_get=None, on_text_query=None)
        assert merged.on_unprotected_get == "raise"
        assert merged.on_text_query == "warn"

    def test_merge_preserves_existing_strict_fields(self) -> None:
        config = AuthzConfig(
            on_unprotected_get="warn",
            on_text_query="raise",
            on_skip_authz="log",
            audit_bypasses=True,
        )
        # Merge only default_action — strict fields stay
        merged = config.merge(default_action="update")
        assert merged.on_unprotected_get == "warn"
        assert merged.on_text_query == "raise"
        assert merged.on_skip_authz == "log"
        assert merged.audit_bypasses is True
        assert merged.default_action == "update"


class TestStrictModeConfigGlobal:
    """Test global configure() with strict mode fields."""

    def setup_method(self) -> None:
        _reset_global_config()

    def teardown_method(self) -> None:
        _reset_global_config()

    def test_configure_strict_mode(self) -> None:
        configure(strict_mode=True)
        config = get_global_config()
        assert config.strict_mode is True
        assert config.on_unprotected_get == "warn"

    def test_configure_on_unprotected_get(self) -> None:
        configure(on_unprotected_get="raise")
        config = get_global_config()
        assert config.on_unprotected_get == "raise"

    def test_configure_on_text_query(self) -> None:
        configure(on_text_query="warn")
        config = get_global_config()
        assert config.on_text_query == "warn"

    def test_configure_on_skip_authz(self) -> None:
        configure(on_skip_authz="log")
        config = get_global_config()
        assert config.on_skip_authz == "log"

    def test_configure_audit_bypasses(self) -> None:
        configure(audit_bypasses=True)
        config = get_global_config()
        assert config.audit_bypasses is True

    def test_configure_invalid_on_unprotected_get_raises(self) -> None:
        with pytest.raises(ValueError, match="on_unprotected_get"):
            configure(on_unprotected_get="invalid")  # type: ignore[arg-type]

    def test_configure_invalid_on_text_query_raises(self) -> None:
        with pytest.raises(ValueError, match="on_text_query"):
            configure(on_text_query="invalid")  # type: ignore[arg-type]

    def test_configure_invalid_on_skip_authz_raises(self) -> None:
        with pytest.raises(ValueError, match="on_skip_authz"):
            configure(on_skip_authz="invalid")  # type: ignore[arg-type]


class TestStrictModeConfigFrozen:
    """Test that strict mode fields are also frozen."""

    def test_cannot_set_strict_mode(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.strict_mode = True  # type: ignore[misc]

    def test_cannot_set_on_unprotected_get(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.on_unprotected_get = "raise"  # type: ignore[misc]

    def test_cannot_set_on_text_query(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.on_text_query = "warn"  # type: ignore[misc]

    def test_cannot_set_on_skip_authz(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.on_skip_authz = "log"  # type: ignore[misc]

    def test_cannot_set_audit_bypasses(self) -> None:
        config = AuthzConfig()
        with pytest.raises(AttributeError):
            config.audit_bypasses = True  # type: ignore[misc]
