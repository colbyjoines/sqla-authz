"""Tests for policy/_registry.py — PolicyRegistry."""

from __future__ import annotations

import threading

import pytest
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


class TestPolicyRegistryThreadSafety:
    """Thread safety stress tests for PolicyRegistry."""

    def test_100_thread_concurrent_register_no_lost_registrations(self):
        """100 threads registering concurrently — no lost registrations."""
        registry = PolicyRegistry()
        num_threads = 100
        barrier = threading.Barrier(num_threads)
        errors: list[Exception] = []

        def register_policy(i: int) -> None:
            try:
                barrier.wait(timeout=10)
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
            t.join(timeout=15)

        assert not errors, f"Errors during concurrent registration: {errors}"
        policies = registry.lookup(Post, "read")
        assert len(policies) == num_threads

    def test_concurrent_register_and_lookup(self):
        """Concurrent register + lookup — no exceptions, no lost data."""
        registry = PolicyRegistry()
        num_writers = 50
        num_readers = 50
        barrier = threading.Barrier(num_writers + num_readers)
        errors: list[Exception] = []

        def writer(i: int) -> None:
            try:
                barrier.wait(timeout=10)
                registry.register(
                    Post,
                    "read",
                    lambda a: true(),
                    name=f"w_{i}",
                    description="",
                )
            except Exception as exc:
                errors.append(exc)

        def reader() -> None:
            try:
                barrier.wait(timeout=10)
                # Should never raise, even during concurrent writes
                registry.lookup(Post, "read")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_writers)] + [
            threading.Thread(target=reader) for _ in range(num_readers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors
        assert len(registry.lookup(Post, "read")) == num_writers

    def test_clear_under_concurrent_access(self):
        """clear() during concurrent access doesn't raise."""
        registry = PolicyRegistry()
        # Pre-populate
        for i in range(20):
            registry.register(Post, "read", lambda a: true(), name=f"p_{i}", description="")

        errors: list[Exception] = []
        barrier = threading.Barrier(3)

        def do_clear() -> None:
            try:
                barrier.wait(timeout=5)
                registry.clear()
            except Exception as exc:
                errors.append(exc)

        def do_lookup() -> None:
            try:
                barrier.wait(timeout=5)
                registry.lookup(Post, "read")
            except Exception as exc:
                errors.append(exc)

        def do_register() -> None:
            try:
                barrier.wait(timeout=5)
                registry.register(Post, "read", lambda a: true(), name="new", description="")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=do_clear),
            threading.Thread(target=do_lookup),
            threading.Thread(target=do_register),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors


class TestPolicySignatureValidation:
    """Test runtime signature validation on register()."""

    def test_valid_single_arg_lambda(self):
        registry = PolicyRegistry()
        registry.register(Post, "read", lambda actor: true(), name="p", description="")
        assert len(registry.lookup(Post, "read")) == 1

    def test_valid_function_with_one_arg(self):
        registry = PolicyRegistry()

        def my_policy(actor):
            return true()

        registry.register(Post, "read", my_policy, name="p", description="")
        assert len(registry.lookup(Post, "read")) == 1

    def test_zero_arg_lambda_rejected(self):
        registry = PolicyRegistry()
        with pytest.raises(TypeError, match="must accept at least one positional"):
            registry.register(Post, "read", lambda: true(), name="p", description="")

    def test_zero_arg_function_rejected(self):
        registry = PolicyRegistry()

        def no_args():
            return true()

        with pytest.raises(TypeError, match="must accept at least one positional"):
            registry.register(Post, "read", no_args, name="p", description="")

    def test_validate_signature_false_skips_check(self):
        registry = PolicyRegistry()
        # Zero-arg lambda should be accepted when validation is disabled
        registry.register(
            Post,
            "read",
            lambda: true(),
            name="p",
            description="",
            validate_signature=False,
        )
        assert len(registry.lookup(Post, "read")) == 1

    def test_extra_positional_args_accepted(self):
        """Functions with more than one positional arg are accepted."""
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda a, b, c: true(),
            name="p",
            description="",
        )
        assert len(registry.lookup(Post, "read")) == 1

    def test_kwargs_only_function_rejected(self):
        """A function with only **kwargs and no positional params is rejected."""
        registry = PolicyRegistry()

        def only_kwargs(**kwargs):
            return true()

        with pytest.raises(TypeError, match="must accept at least one positional"):
            registry.register(Post, "read", only_kwargs, name="p", description="")

    def test_function_with_defaults_accepted(self):
        """A function with one required positional + defaults is valid."""
        registry = PolicyRegistry()

        def with_defaults(actor, extra=None):
            return true()

        registry.register(Post, "read", with_defaults, name="p", description="")
        assert len(registry.lookup(Post, "read")) == 1
