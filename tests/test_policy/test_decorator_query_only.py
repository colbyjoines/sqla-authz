"""Tests for the query_only parameter on @policy decorator."""

from __future__ import annotations

from sqlalchemy import ColumnElement, func, true

from sqla_authz.policy import policy
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import MockActor, Post


class TestPolicyDecoratorQueryOnly:
    """Tests for @policy(..., query_only=True)."""

    def test_query_only_true(self):
        """query_only=True is stored on the PolicyRegistration."""
        registry = PolicyRegistry()

        @policy(Post, "read", registry=registry, query_only=True)
        def complex_read(actor: MockActor) -> ColumnElement[bool]:
            return func.lower(Post.title) == "test"

        reg = registry.lookup(Post, "read")[0]
        assert reg.query_only is True

    def test_query_only_false_default(self):
        """Default query_only is False."""
        registry = PolicyRegistry()

        @policy(Post, "read", registry=registry)
        def simple_read(actor: MockActor) -> ColumnElement[bool]:
            return true()

        reg = registry.lookup(Post, "read")[0]
        assert reg.query_only is False

    def test_query_only_with_predicate(self):
        """query_only works alongside predicate parameter."""
        from sqla_authz.policy._predicate import Predicate

        pred = Predicate(lambda actor: true(), name="always")
        registry = PolicyRegistry()

        @policy(Post, "read", registry=registry, predicate=pred, query_only=True)
        def predicated_read(actor: MockActor) -> ColumnElement[bool]:
            ...

        reg = registry.lookup(Post, "read")[0]
        assert reg.query_only is True
        assert reg.fn is pred
