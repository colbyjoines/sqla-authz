"""Tests for the @scope decorator and ScopeRegistration."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import ColumnElement, true

from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration, scope

from tests.conftest import MockActor, Post, Tag, User


class TestScopeRegistration:
    """Test ScopeRegistration dataclass."""

    def test_creation(self) -> None:
        """ScopeRegistration is a frozen dataclass with expected fields."""
        fn = lambda actor, Model: true()  # noqa: E731
        reg = ScopeRegistration(
            applies_to=(Post,),
            fn=fn,
            name="test",
            description="A test scope",
            actions=None,
        )
        assert reg.applies_to == (Post,)
        assert reg.fn is fn
        assert reg.name == "test"
        assert reg.description == "A test scope"
        assert reg.actions is None

    def test_with_actions(self) -> None:
        """ScopeRegistration can store action restrictions."""
        reg = ScopeRegistration(
            applies_to=(Post, User),
            fn=lambda actor, Model: true(),
            name="test",
            description="",
            actions=("read",),
        )
        assert reg.actions == ("read",)

    def test_frozen(self) -> None:
        """ScopeRegistration is immutable."""
        reg = ScopeRegistration(
            applies_to=(Post,),
            fn=lambda actor, Model: true(),
            name="test",
            description="",
            actions=None,
        )
        with pytest.raises(AttributeError):
            reg.name = "changed"  # type: ignore[misc]


class TestScopeDecorator:
    """Test the @scope decorator registration behavior."""

    def test_registers_scope_in_registry(self) -> None:
        """@scope registers a ScopeRegistration in the provided registry."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post, User], registry=registry)
        def tenant(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return Model.org_id == actor.org_id  # type: ignore[attr-defined]

        scopes = registry.lookup_scopes(Post)
        assert len(scopes) == 1
        assert scopes[0].name == "tenant"
        assert scopes[0].applies_to == (Post, User)
        assert scopes[0].actions is None

    def test_returns_original_function(self) -> None:
        """@scope returns the decorated function unchanged."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def my_scope(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert my_scope.__name__ == "my_scope"
        assert callable(my_scope)

    def test_captures_docstring(self) -> None:
        """@scope captures the function's docstring as description."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def tenant(actor: MockActor, Model: type) -> ColumnElement[bool]:
            """Tenant isolation scope."""
            return true()

        scopes = registry.lookup_scopes(Post)
        assert scopes[0].description == "Tenant isolation scope."

    def test_with_actions_restriction(self) -> None:
        """@scope with actions= restricts to specific actions."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], actions=["read"], registry=registry)
        def soft_delete(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        scopes = registry.lookup_scopes(Post, "read")
        assert len(scopes) == 1

        scopes = registry.lookup_scopes(Post, "delete")
        assert len(scopes) == 0

    def test_empty_applies_to_raises(self) -> None:
        """@scope with empty applies_to raises ValueError."""
        with pytest.raises(ValueError, match="non-empty"):

            @scope(applies_to=[], registry=PolicyRegistry())
            def bad(actor: MockActor, Model: type) -> ColumnElement[bool]:
                return true()

    def test_missing_model_param_raises(self) -> None:
        """@scope function with only one param raises TypeError."""
        with pytest.raises(TypeError, match="at least two positional"):

            @scope(applies_to=[Post], registry=PolicyRegistry())
            def bad(actor: MockActor) -> ColumnElement[bool]:
                return true()

    def test_multiple_scopes_on_same_model(self) -> None:
        """Multiple @scope decorators can target the same model."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def scope_a(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        @scope(applies_to=[Post], registry=registry)
        def scope_b(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        scopes = registry.lookup_scopes(Post)
        assert len(scopes) == 2


class TestRegistryScopeMethods:
    """Test PolicyRegistry scope storage and lookup."""

    def test_lookup_scopes_no_match(self) -> None:
        """lookup_scopes returns empty list when no scopes match."""
        registry = PolicyRegistry()
        assert registry.lookup_scopes(Post) == []

    def test_lookup_scopes_filters_by_model(self) -> None:
        """lookup_scopes only returns scopes that include the model."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def post_scope(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert len(registry.lookup_scopes(Post)) == 1
        assert len(registry.lookup_scopes(User)) == 0

    def test_lookup_scopes_filters_by_action(self) -> None:
        """lookup_scopes filters by action when scope has actions restriction."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], actions=["read", "update"], registry=registry)
        def read_update_scope(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert len(registry.lookup_scopes(Post, "read")) == 1
        assert len(registry.lookup_scopes(Post, "update")) == 1
        assert len(registry.lookup_scopes(Post, "delete")) == 0

    def test_lookup_scopes_no_action_filter_returns_all(self) -> None:
        """Scopes with actions=None match any action."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def universal(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert len(registry.lookup_scopes(Post, "read")) == 1
        assert len(registry.lookup_scopes(Post, "delete")) == 1
        assert len(registry.lookup_scopes(Post, "anything")) == 1

    def test_has_scopes(self) -> None:
        """has_scopes returns True when a model has scopes."""
        registry = PolicyRegistry()
        assert registry.has_scopes(Post) is False

        @scope(applies_to=[Post], registry=registry)
        def s(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert registry.has_scopes(Post) is True
        assert registry.has_scopes(User) is False

    def test_clear_removes_scopes(self) -> None:
        """registry.clear() removes both policies and scopes."""
        registry = PolicyRegistry()

        @scope(applies_to=[Post], registry=registry)
        def s(actor: MockActor, Model: type) -> ColumnElement[bool]:
            return true()

        assert registry.has_scopes(Post) is True
        registry.clear()
        assert registry.has_scopes(Post) is False

    def test_thread_safe_scope_registration(self) -> None:
        """Concurrent scope registrations don't corrupt the registry."""
        registry = PolicyRegistry()
        num_threads = 10
        barrier = threading.Barrier(num_threads)

        def register_scope_fn(i: int) -> None:
            barrier.wait()
            reg = ScopeRegistration(
                applies_to=(Post,),
                fn=lambda actor, Model: true(),
                name=f"scope_{i}",
                description="",
                actions=None,
            )
            registry.register_scope(reg)

        threads = [
            threading.Thread(target=register_scope_fn, args=(i,))
            for i in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(registry.lookup_scopes(Post)) == num_threads
