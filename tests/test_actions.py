"""Tests for typed actions — constants, factory, validation, and wiring."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import select, true

from sqla_authz._action_validation import check_unknown_action
from sqla_authz.actions import CREATE, DELETE, READ, UPDATE, action
from sqla_authz.config._config import AuthzConfig, _reset_global_config, _set_global_config
from sqla_authz.exceptions import UnknownActionError
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post, User


# ---------------------------------------------------------------------------
# Action constants
# ---------------------------------------------------------------------------


class TestActionConstants:
    def test_read_value(self):
        assert READ == "read"

    def test_update_value(self):
        assert UPDATE == "update"

    def test_delete_value(self):
        assert DELETE == "delete"

    def test_create_value(self):
        assert CREATE == "create"

    def test_constants_are_plain_strings(self):
        for const in (READ, UPDATE, DELETE, CREATE):
            assert isinstance(const, str)

    def test_constants_work_as_dict_keys(self):
        d = {READ: 1, UPDATE: 2}
        assert d[READ] == 1
        assert d["read"] == 1

    def test_importable_from_top_level(self):
        from sqla_authz import CREATE, DELETE, READ, UPDATE

        assert READ == "read"
        assert UPDATE == "update"
        assert DELETE == "delete"
        assert CREATE == "create"


# ---------------------------------------------------------------------------
# action() factory
# ---------------------------------------------------------------------------


class TestActionFactory:
    def test_valid_simple_name(self):
        assert action("approve") == "approve"

    def test_valid_underscore_name(self):
        assert action("soft_delete") == "soft_delete"

    def test_valid_multi_underscore(self):
        assert action("mark_as_read") == "mark_as_read"

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError, match="non-empty"):
            action("")

    def test_rejects_uppercase(self):
        with pytest.raises(ValueError, match="lowercase"):
            action("Read")

    def test_rejects_all_uppercase(self):
        with pytest.raises(ValueError, match="lowercase"):
            action("READ")

    def test_rejects_spaces(self):
        with pytest.raises(ValueError, match="only lowercase letters and underscores"):
            action("read posts")

    def test_rejects_numbers(self):
        with pytest.raises(ValueError, match="only lowercase letters and underscores"):
            action("read2")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError, match="only lowercase letters and underscores"):
            action("read!")

    def test_rejects_hyphens(self):
        with pytest.raises(ValueError, match="only lowercase letters and underscores"):
            action("soft-delete")

    def test_suggests_lowercase_in_error(self):
        with pytest.raises(ValueError, match="'read'"):
            action("Read")

    def test_importable_from_top_level(self):
        from sqla_authz import action

        assert action("test") == "test"


# ---------------------------------------------------------------------------
# UnknownActionError
# ---------------------------------------------------------------------------


class TestUnknownActionError:
    def test_attributes(self):
        err = UnknownActionError(
            action="raed",
            known_actions=["read", "update"],
            suggestion="read",
        )
        assert err.action == "raed"
        assert err.known_actions == ["read", "update"]
        assert err.suggestion == "read"

    def test_message_with_suggestion(self):
        err = UnknownActionError(
            action="raed",
            known_actions=["read", "update"],
            suggestion="read",
        )
        msg = str(err)
        assert "raed" in msg
        assert "Did you mean 'read'?" in msg
        assert "['read', 'update']" in msg

    def test_message_without_suggestion(self):
        err = UnknownActionError(
            action="xyz",
            known_actions=["read", "update"],
            suggestion=None,
        )
        msg = str(err)
        assert "xyz" in msg
        assert "Did you mean" not in msg

    def test_importable_from_top_level(self):
        from sqla_authz import UnknownActionError

        assert issubclass(UnknownActionError, Exception)


# ---------------------------------------------------------------------------
# check_unknown_action
# ---------------------------------------------------------------------------


class TestCheckUnknownAction:
    def _registry_with_read(self) -> PolicyRegistry:
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(Post, "update", lambda a: true(), name="u", description="")
        return registry

    def test_ignore_mode_no_error(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="ignore")
        # Should not raise
        check_unknown_action(registry, "raed", config=config)

    def test_warn_mode_logs_warning(self, caplog):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="warn")
        with caplog.at_level(logging.WARNING, logger="sqla_authz.actions"):
            check_unknown_action(registry, "raed", config=config)
        assert "raed" in caplog.text
        assert "Did you mean 'read'?" in caplog.text

    def test_raise_mode_raises_error(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="raise")
        with pytest.raises(UnknownActionError, match="raed"):
            check_unknown_action(registry, "raed", config=config)

    def test_raise_includes_known_actions(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="raise")
        with pytest.raises(UnknownActionError) as exc_info:
            check_unknown_action(registry, "xyz", config=config)
        assert "read" in exc_info.value.known_actions
        assert "update" in exc_info.value.known_actions

    def test_raise_includes_suggestion(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="raise")
        with pytest.raises(UnknownActionError) as exc_info:
            check_unknown_action(registry, "raed", config=config)
        assert exc_info.value.suggestion == "read"

    def test_raise_no_suggestion_for_distant_string(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="raise")
        with pytest.raises(UnknownActionError) as exc_info:
            check_unknown_action(registry, "xyzabc", config=config)
        assert exc_info.value.suggestion is None

    def test_empty_registry_skips_validation(self):
        registry = PolicyRegistry()
        config = AuthzConfig(on_unknown_action="raise")
        # Should not raise — empty registry means startup/test setup
        check_unknown_action(registry, "anything", config=config)

    def test_known_action_passes(self):
        registry = self._registry_with_read()
        config = AuthzConfig(on_unknown_action="raise")
        # Should not raise
        check_unknown_action(registry, "read", config=config)

    def test_uses_global_config_by_default(self):
        registry = self._registry_with_read()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            with pytest.raises(UnknownActionError):
                check_unknown_action(registry, "raed")
        finally:
            _reset_global_config()


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------


class TestConfigUnknownAction:
    def test_default_is_ignore(self):
        config = AuthzConfig()
        assert config.on_unknown_action == "ignore"

    def test_valid_values(self):
        for val in ("ignore", "warn", "raise"):
            config = AuthzConfig(on_unknown_action=val)
            assert config.on_unknown_action == val

    def test_invalid_value_rejected(self):
        with pytest.raises(ValueError, match="on_unknown_action"):
            AuthzConfig(on_unknown_action="bad")  # type: ignore[arg-type]

    def test_strict_mode_upgrades_to_warn(self):
        config = AuthzConfig(strict_mode=True)
        assert config.on_unknown_action == "warn"

    def test_strict_mode_does_not_override_explicit_raise(self):
        config = AuthzConfig(strict_mode=True, on_unknown_action="raise")
        assert config.on_unknown_action == "raise"

    def test_merge_preserves_default(self):
        config = AuthzConfig(on_unknown_action="raise")
        merged = config.merge()
        assert merged.on_unknown_action == "raise"

    def test_merge_overrides(self):
        config = AuthzConfig(on_unknown_action="ignore")
        merged = config.merge(on_unknown_action="raise")
        assert merged.on_unknown_action == "raise"


# ---------------------------------------------------------------------------
# PolicyRegistry.known_actions
# ---------------------------------------------------------------------------


class TestKnownActions:
    def test_empty_registry(self):
        registry = PolicyRegistry()
        assert registry.known_actions() == set()

    def test_with_policies(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(Post, "update", lambda a: true(), name="u", description="")
        registry.register(User, "read", lambda a: true(), name="ur", description="")
        assert registry.known_actions() == {"read", "update"}

    def test_known_actions_for_model(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(Post, "update", lambda a: true(), name="u", description="")
        registry.register(User, "delete", lambda a: true(), name="d", description="")
        assert registry.known_actions_for(Post) == {"read", "update"}
        assert registry.known_actions_for(User) == {"delete"}

    def test_known_actions_for_unknown_model(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        assert registry.known_actions_for(User) == set()


# ---------------------------------------------------------------------------
# Validation wiring — authorize_query, can, authorize
# ---------------------------------------------------------------------------


class TestValidationWiring:
    """Verify that check_unknown_action fires at every consumption point."""

    def _setup(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        config = AuthzConfig(on_unknown_action="raise")
        return registry, config

    def test_authorize_query_validates(self):
        registry, _ = self._setup()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            with pytest.raises(UnknownActionError, match="raed"):
                from sqla_authz import authorize_query

                authorize_query(
                    select(Post),
                    actor=MockActor(id=1),
                    action="raed",
                    registry=registry,
                )
        finally:
            _reset_global_config()

    def test_can_validates(self):
        registry, _ = self._setup()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            post = Post(id=1, title="t", is_published=True, author_id=1)
            with pytest.raises(UnknownActionError, match="raed"):
                from sqla_authz import can

                can(MockActor(id=1), "raed", post, registry=registry)
        finally:
            _reset_global_config()

    def test_authorize_validates(self):
        registry, _ = self._setup()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            post = Post(id=1, title="t", is_published=True, author_id=1)
            with pytest.raises(UnknownActionError, match="raed"):
                from sqla_authz import authorize

                authorize(MockActor(id=1), "raed", post, registry=registry)
        finally:
            _reset_global_config()

    def test_known_action_passes_authorize_query(self):
        registry, _ = self._setup()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            from sqla_authz import authorize_query

            # Should not raise
            result = authorize_query(
                select(Post),
                actor=MockActor(id=1),
                action="read",
                registry=registry,
            )
            assert result is not None
        finally:
            _reset_global_config()

    def test_constants_pass_validation(self):
        registry, _ = self._setup()
        _set_global_config(AuthzConfig(on_unknown_action="raise"))
        try:
            from sqla_authz import authorize_query

            result = authorize_query(
                select(Post),
                actor=MockActor(id=1),
                action=READ,
                registry=registry,
            )
            assert result is not None
        finally:
            _reset_global_config()


# ---------------------------------------------------------------------------
# assert_actions_covered
# ---------------------------------------------------------------------------


class TestAssertActionsCovered:
    def test_all_covered_passes(self):
        from sqla_authz.testing import assert_actions_covered

        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(Post, "update", lambda a: true(), name="u", description="")

        # Should not raise
        assert_actions_covered(
            models=[Post],
            actions=["read", "update"],
            registry=registry,
        )

    def test_gap_detected(self):
        from sqla_authz.testing import assert_actions_covered

        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")

        with pytest.raises(AssertionError, match="Missing policies"):
            assert_actions_covered(
                models=[Post],
                actions=["read", "delete"],
                registry=registry,
            )

    def test_multiple_gaps_listed(self):
        from sqla_authz.testing import assert_actions_covered

        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")

        with pytest.raises(AssertionError) as exc_info:
            assert_actions_covered(
                models=[Post, User],
                actions=["read", "update"],
                registry=registry,
            )
        msg = str(exc_info.value)
        assert "(Post, 'update')" in msg
        assert "(User, 'read')" in msg
        assert "(User, 'update')" in msg
