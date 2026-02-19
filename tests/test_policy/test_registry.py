"""Tests for policy/_registry.py — PolicyRegistry."""

from __future__ import annotations

import threading

from sqlalchemy import false, true

from sqla_authz.policy._base import PolicyRegistration
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import Post, User


class TestPolicyRegistration:
    """PolicyRegistration is a frozen dataclass holding policy metadata."""

    def test_is_frozen(self):
        reg = PolicyRegistration(
            resource_type=Post,
            action="read",
            fn=lambda actor: true(),
            name="test_policy",
            description="test",
        )
        import pytest

        with pytest.raises(AttributeError):
            reg.action = "write"  # type: ignore[misc]

    def test_fields(self):
        def fn(actor):
            return true()

        reg = PolicyRegistration(
            resource_type=Post,
            action="read",
            fn=fn,
            name="my_policy",
            description="A test policy",
        )
        assert reg.resource_type is Post
        assert reg.action == "read"
        assert reg.fn is fn
        assert reg.name == "my_policy"
        assert reg.description == "A test policy"


class TestPolicyRegistry:
    """PolicyRegistry stores and retrieves policies keyed by (model, action)."""

    def test_register_and_lookup(self):
        registry = PolicyRegistry()

        def fn(actor):
            return true()

        registry.register(Post, "read", fn, name="p", description="d")
        policies = registry.lookup(Post, "read")
        assert len(policies) == 1
        assert policies[0].fn is fn

    def test_lookup_returns_empty_for_unregistered(self):
        registry = PolicyRegistry()
        policies = registry.lookup(Post, "delete")
        assert policies == []

    def test_multiple_policies_same_key(self):
        registry = PolicyRegistry()

        def fn1(actor):
            return true()

        def fn2(actor):
            return false()

        registry.register(Post, "read", fn1, name="p1", description="d1")
        registry.register(Post, "read", fn2, name="p2", description="d2")
        policies = registry.lookup(Post, "read")
        assert len(policies) == 2
        assert policies[0].fn is fn1
        assert policies[1].fn is fn2

    def test_different_actions_are_separate(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="r", description="")
        registry.register(Post, "update", lambda a: false(), name="u", description="")
        assert len(registry.lookup(Post, "read")) == 1
        assert len(registry.lookup(Post, "update")) == 1
        assert registry.lookup(Post, "read")[0].action == "read"

    def test_different_models_are_separate(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(User, "read", lambda a: true(), name="u", description="")
        assert len(registry.lookup(Post, "read")) == 1
        assert len(registry.lookup(User, "read")) == 1

    def test_clear(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.clear()
        assert registry.lookup(Post, "read") == []

    def test_has_policy(self):
        registry = PolicyRegistry()
        assert not registry.has_policy(Post, "read")
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        assert registry.has_policy(Post, "read")

    def test_concurrent_registration(self):
        """Concurrent policy registrations should all succeed without data loss."""
        registry = PolicyRegistry()
        num_threads = 20
        barrier = threading.Barrier(num_threads)
        errors: list[Exception] = []

        def register_policy(i: int) -> None:
            try:
                barrier.wait(timeout=5)
                registry.register(
                    Post,
                    "read",
                    lambda a: true(),
                    name=f"policy_{i}",
                    description=f"concurrent policy {i}",
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=register_policy, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Errors during concurrent registration: {errors}"
        policies = registry.lookup(Post, "read")
        assert len(policies) == num_threads

    def test_registered_entities(self):
        """registered_entities returns all entities with policies for an action."""
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda a: true(), name="p", description="")
        registry.register(User, "read", lambda a: true(), name="u", description="")
        registry.register(Post, "update", lambda a: true(), name="pu", description="")

        read_entities = registry.registered_entities("read")
        assert read_entities == {Post, User}

        update_entities = registry.registered_entities("update")
        assert update_entities == {Post}
