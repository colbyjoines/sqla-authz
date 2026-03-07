"""Tests for scope awareness in explain_access()."""

from __future__ import annotations

import json

from sqlalchemy import Integer, String, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz.explain import explain_access
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration
from tests.conftest import MockActor


# ---------------------------------------------------------------------------
# Test-local model with org_id for scope testing
# ---------------------------------------------------------------------------


class ScopeAccessBase(DeclarativeBase):
    pass


class ScopedPost(ScopeAccessBase):
    __tablename__ = "scoped_access_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[int] = mapped_column(Integer)
    is_published: Mapped[bool] = mapped_column(default=False)


class TestExplainAccessScopes:
    def _make_post(self, *, id: int, org_id: int, is_published: bool) -> ScopedPost:
        return ScopedPost(id=id, title=f"Post {id}", org_id=org_id, is_published=is_published)

    def test_scope_match_allows_access(self) -> None:
        """When policy matches AND scope matches, access is allowed."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published_only",
            description="Allow reading published posts",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="Tenant isolation",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is True
        assert len(result.scopes) == 1
        assert result.scopes[0].name == "tenant"
        assert result.scopes[0].matched is True

    def test_scope_blocks_access(self) -> None:
        """When policy matches but scope doesn't match, access is denied."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published_only",
            description="Published posts",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="Tenant isolation",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=99)  # Wrong org
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        # Policy matched but scope blocked
        assert any(p.matched for p in result.policies)
        assert result.scopes[0].matched is False

    def test_no_scopes_returns_empty_list(self) -> None:
        """When no scopes are registered, scopes list is empty."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )

        actor = MockActor(id=1)
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is True
        assert result.scopes == []

    def test_multiple_scopes_all_must_match(self) -> None:
        """When multiple scopes exist, all must match for access."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: true(),
            name="allow_all",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="Tenant isolation",
            actions=None,
        ))
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.is_published == True,  # noqa: E712
            name="published_only",
            description="Only published",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        # Right org but not published -> second scope blocks
        post = self._make_post(id=1, org_id=42, is_published=False)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        assert len(result.scopes) == 2
        scope_results = {s.name: s.matched for s in result.scopes}
        assert scope_results["tenant"] is True
        assert scope_results["published_only"] is False

    def test_scope_bypass_with_true(self) -> None:
        """Admin bypass (scope returns true()) allows access."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: true() if actor.role == "admin" else Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        admin = MockActor(id=1, role="admin", org_id=1)
        post = self._make_post(id=1, org_id=999, is_published=True)
        result = explain_access(admin, "read", post, registry=registry)

        assert result.allowed is True
        assert result.scopes[0].matched is True

    def test_deny_by_default_no_scopes_evaluated(self) -> None:
        """When no policies exist, scopes are not evaluated."""
        registry = PolicyRegistry()
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        assert result.allowed is False
        assert result.deny_by_default is True
        assert result.scopes == []

    def test_to_dict_includes_scopes(self) -> None:
        """to_dict() includes scope evaluations."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="Tenant isolation",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        d = result.to_dict()
        assert "scopes" in d
        assert len(d["scopes"]) == 1
        assert d["scopes"][0]["name"] == "tenant"
        assert d["scopes"][0]["matched"] is True
        # JSON-serializable
        json.dumps(d)

    def test_str_includes_scopes(self) -> None:
        """__str__() includes scope results."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="Published posts",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="Tenant isolation",
            actions=None,
        ))

        actor = MockActor(id=1, org_id=99)
        post = self._make_post(id=1, org_id=42, is_published=True)
        result = explain_access(actor, "read", post, registry=registry)

        text = str(result)
        assert "DENIED" in text
        assert "Scope Results:" in text
        assert "tenant" in text
        assert "NO MATCH" in text

    def test_action_specific_scope(self) -> None:
        """A scope with actions=['read'] only applies to read."""
        registry = PolicyRegistry()
        registry.register(
            ScopedPost,
            "read",
            lambda actor: ScopedPost.is_published == True,  # noqa: E712
            name="published",
            description="",
        )
        registry.register(
            ScopedPost,
            "delete",
            lambda actor: true(),
            name="allow_del",
            description="",
        )
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedPost,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant",
            description="",
            actions=("read",),
        ))

        actor = MockActor(id=1, org_id=99)
        post = self._make_post(id=1, org_id=42, is_published=True)

        # Read should have scope (and be denied due to wrong org)
        read_result = explain_access(actor, "read", post, registry=registry)
        assert len(read_result.scopes) == 1
        assert read_result.allowed is False

        # Delete should have NO scope
        del_result = explain_access(actor, "delete", post, registry=registry)
        assert len(del_result.scopes) == 0
        assert del_result.allowed is True
