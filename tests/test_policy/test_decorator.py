"""Tests for policy/_decorator.py — @policy decorator."""

from __future__ import annotations

from sqlalchemy import ColumnElement, false, true

from sqla_authz.policy import policy
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry
from tests.conftest import MockActor, Post


class TestPolicyDecorator:
    """The @policy decorator registers functions in the global registry."""

    def setup_method(self):
        """Clear the global registry before each test."""
        get_default_registry().clear()

    def test_registers_function(self):
        @policy(Post, "read")
        def post_read(actor: MockActor) -> ColumnElement[bool]:
            return true()

        registry = get_default_registry()
        policies = registry.lookup(Post, "read")
        assert len(policies) == 1
        assert policies[0].fn is post_read

    def test_preserves_function_identity(self):
        """Decorated function should still be callable directly."""

        @policy(Post, "read")
        def post_read(actor: MockActor) -> ColumnElement[bool]:
            return true()

        result = post_read(MockActor(id=1))
        # Should return a ColumnElement
        assert result is not None

    def test_uses_function_name_and_docstring(self):
        @policy(Post, "update")
        def post_update_policy(actor: MockActor) -> ColumnElement[bool]:
            """Authors can update their own posts."""
            return true()

        registry = get_default_registry()
        reg = registry.lookup(Post, "update")[0]
        assert reg.name == "post_update_policy"
        assert reg.description == "Authors can update their own posts."

    def test_multiple_decorators_same_model_action(self):
        @policy(Post, "read")
        def public_posts(actor: MockActor) -> ColumnElement[bool]:
            return Post.is_published == True

        @policy(Post, "read")
        def own_posts(actor: MockActor) -> ColumnElement[bool]:
            return Post.author_id == actor.id

        registry = get_default_registry()
        policies = registry.lookup(Post, "read")
        assert len(policies) == 2

    def test_custom_registry(self):
        """@policy can target a specific registry instead of the global one."""
        custom = PolicyRegistry()

        @policy(Post, "read", registry=custom)
        def p(actor: MockActor) -> ColumnElement[bool]:
            return true()

        # Should be in custom registry
        assert len(custom.lookup(Post, "read")) == 1
        # Should NOT be in default registry
        assert len(get_default_registry().lookup(Post, "read")) == 0

    def test_no_docstring_uses_empty_description(self):
        @policy(Post, "delete")
        def delete_policy(actor: MockActor) -> ColumnElement[bool]:
            return false()

        registry = get_default_registry()
        reg = registry.lookup(Post, "delete")[0]
        assert reg.description == ""
