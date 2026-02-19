"""Tests for sqla_authz.testing._fixtures — pytest fixture functions."""

from __future__ import annotations

from sqla_authz.policy._registry import PolicyRegistry


class TestAuthzRegistryFixture:
    """authz_registry returns isolated PolicyRegistry instances."""

    def test_returns_policy_registry(self, authz_registry: PolicyRegistry) -> None:
        """The fixture yields a PolicyRegistry."""
        assert isinstance(authz_registry, PolicyRegistry)

    def test_registry_starts_empty(self, authz_registry: PolicyRegistry) -> None:
        """A fresh registry has no policies registered."""
        from tests.conftest import Post

        assert not authz_registry.has_policy(Post, "read")

    def test_isolated_between_tests_a(self, authz_registry: PolicyRegistry) -> None:
        """Register a policy in one test..."""
        from tests.conftest import Post

        authz_registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="pub",
            description="",
        )
        assert authz_registry.has_policy(Post, "read")

    def test_isolated_between_tests_b(self, authz_registry: PolicyRegistry) -> None:
        """...and verify it does not leak to another test."""
        from tests.conftest import Post

        assert not authz_registry.has_policy(Post, "read")
