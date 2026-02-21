"""Tests for sqla_authz.testing._simulation — policy testing tools."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.testing._actors import MockActor
from sqla_authz.testing._simulation import (
    SimulationResult,
    assert_policy_sql_snapshot,
    diff_policies,
    policy_matrix,
    simulate_query,
)
from tests.conftest import Post, Tag

# ---------------------------------------------------------------------------
# policy_matrix
# ---------------------------------------------------------------------------


class TestPolicyMatrix:
    """policy_matrix generates a coverage matrix from a registry."""

    def test_all_covered(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        registry.register(
            Post,
            "update",
            lambda actor: Post.author_id == actor.id,
            name="own",
            description="",
        )

        matrix = policy_matrix(registry)
        assert len(matrix.entries) == 2
        assert len(matrix.uncovered) == 0

    def test_uncovered_detected(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )

        matrix = policy_matrix(
            registry,
            models=[Post],
            actions=["read", "update", "delete"],
        )
        assert len(matrix.entries) == 3
        uncovered = matrix.uncovered
        assert len(uncovered) == 2
        uncovered_actions = {e.action for e in uncovered}
        assert uncovered_actions == {"update", "delete"}

    def test_explicit_models_actions(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )

        matrix = policy_matrix(
            registry,
            models=[Post, Tag],
            actions=["read"],
        )
        assert len(matrix.entries) == 2
        names = {e.resource_type for e in matrix.entries}
        assert names == {"Post", "Tag"}

    def test_policy_names_included(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published_only",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )

        matrix = policy_matrix(registry, models=[Post], actions=["read"])
        entry = matrix.entries[0]
        assert entry.policy_count == 2
        assert set(entry.policy_names) == {"published_only", "own_posts"}

    def test_summary_output(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )

        matrix = policy_matrix(registry, models=[Post], actions=["read"])
        summary = matrix.summary
        assert "Post" in summary
        assert "read" in summary
        assert "pub" in summary

    def test_empty_registry(self) -> None:
        registry = PolicyRegistry()
        matrix = policy_matrix(registry)
        assert matrix.entries == []
        assert matrix.uncovered == []

    def test_infers_models_and_actions_from_registry(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        registry.register(
            Tag,
            "read",
            lambda actor: Tag.visibility == "public",
            name="public_tags",
            description="",
        )

        matrix = policy_matrix(registry)
        assert len(matrix.entries) == 2
        types = {e.resource_type for e in matrix.entries}
        assert types == {"Post", "Tag"}


# ---------------------------------------------------------------------------
# simulate_query
# ---------------------------------------------------------------------------


class TestSimulateQuery:
    """simulate_query produces SQL without executing."""

    def test_produces_authorized_sql(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)
        stmt = select(Post)

        result = simulate_query(stmt, actor=actor, action="read", registry=registry)
        assert isinstance(result, SimulationResult)
        assert "is_published" in result.authorized_sql
        assert result.action == "read"

    def test_original_sql_unchanged(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)
        stmt = select(Post)

        result = simulate_query(stmt, actor=actor, action="read", registry=registry)
        # Original should NOT have the policy filter
        assert (
            "is_published" not in result.original_sql
            or result.original_sql != result.authorized_sql
        )

    def test_shows_applied_policies(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="published_only",
            description="",
        )
        actor = MockActor(id=1)
        stmt = select(Post)

        result = simulate_query(stmt, actor=actor, action="read", registry=registry)
        assert "Post" in result.policies_applied
        assert "published_only" in result.policies_applied["Post"]

    def test_str_representation(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)
        stmt = select(Post)

        result = simulate_query(stmt, actor=actor, action="read", registry=registry)
        text = str(result)
        assert "Simulation" in text
        assert "read" in text

    def test_no_policy_shows_false_filter(self) -> None:
        registry = PolicyRegistry()
        actor = MockActor(id=1)
        stmt = select(Post)

        result = simulate_query(stmt, actor=actor, action="read", registry=registry)
        # Should contain a FALSE clause (deny by default)
        assert (
            "0 = 1" in result.authorized_sql
            or "false" in result.authorized_sql.lower()
            or "1 = 0" in result.authorized_sql
        )


# ---------------------------------------------------------------------------
# diff_policies
# ---------------------------------------------------------------------------


class TestDiffPolicies:
    """diff_policies detects changes between registries."""

    def test_detects_added_policy(self) -> None:
        old = PolicyRegistry()
        new = PolicyRegistry()
        new.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )

        diff = diff_policies(old, new)
        assert diff.has_changes
        assert len(diff.added) == 1
        assert diff.added[0] == ("Post", "read", "pub")
        assert "Post" in diff.changed_models

    def test_detects_removed_policy(self) -> None:
        old = PolicyRegistry()
        old.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        new = PolicyRegistry()

        diff = diff_policies(old, new)
        assert diff.has_changes
        assert len(diff.removed) == 1
        assert diff.removed[0] == ("Post", "read", "pub")

    def test_no_changes(self) -> None:
        old = PolicyRegistry()

        def fn(actor):
            return Post.is_published == True

        old.register(Post, "read", fn, name="pub", description="")

        new = PolicyRegistry()
        new.register(Post, "read", fn, name="pub", description="")

        diff = diff_policies(old, new)
        assert not diff.has_changes
        assert len(diff.added) == 0
        assert len(diff.removed) == 0

    def test_changed_same_key(self) -> None:
        old = PolicyRegistry()
        old.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="old_policy",
            description="",
        )

        new = PolicyRegistry()
        new.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="new_policy",
            description="",
        )

        diff = diff_policies(old, new)
        assert diff.has_changes
        assert any(name == "new_policy" for _, _, name in diff.added)
        assert any(name == "old_policy" for _, _, name in diff.removed)

    def test_str_representation(self) -> None:
        old = PolicyRegistry()
        new = PolicyRegistry()
        new.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )

        diff = diff_policies(old, new)
        text = str(diff)
        assert "+ Post.read: pub" in text

    def test_empty_registries_no_changes(self) -> None:
        diff = diff_policies(PolicyRegistry(), PolicyRegistry())
        assert not diff.has_changes
        assert str(diff) == "  (no changes)"

    def test_multiple_models_tracked(self) -> None:
        old = PolicyRegistry()
        new = PolicyRegistry()
        new.register(Post, "read", lambda a: Post.is_published == True, name="p1", description="")
        new.register(Tag, "read", lambda a: Tag.visibility == "public", name="p2", description="")

        diff = diff_policies(old, new)
        assert diff.changed_models == frozenset({"Post", "Tag"})


# ---------------------------------------------------------------------------
# assert_policy_sql_snapshot
# ---------------------------------------------------------------------------


class TestAssertPolicySqlSnapshot:
    """assert_policy_sql_snapshot validates SQL against a snapshot."""

    def test_snapshot_match(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)

        # Get the actual SQL to use as snapshot
        from sqla_authz.compiler._expression import evaluate_policies

        expr = evaluate_policies(registry, Post, "read", actor)
        actual_sql = str(expr.compile(compile_kwargs={"literal_binds": True}))

        assert_policy_sql_snapshot(
            registry,
            Post,
            "read",
            actor,
            snapshot=actual_sql,
        )

    def test_snapshot_mismatch_raises(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)

        with pytest.raises(AssertionError, match="Policy SQL snapshot mismatch"):
            assert_policy_sql_snapshot(
                registry,
                Post,
                "read",
                actor,
                snapshot="something_completely_different = 1",
            )

    def test_whitespace_normalized(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)

        from sqla_authz.compiler._expression import evaluate_policies

        expr = evaluate_policies(registry, Post, "read", actor)
        actual_sql = str(expr.compile(compile_kwargs={"literal_binds": True}))
        # Add extra whitespace — should still match
        spaced = "  " + actual_sql.replace(" ", "   ") + "  "

        assert_policy_sql_snapshot(
            registry,
            Post,
            "read",
            actor,
            snapshot=spaced,
            normalize_whitespace=True,
        )

    def test_no_normalization_exact_match(self) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,
            name="pub",
            description="",
        )
        actor = MockActor(id=1)

        from sqla_authz.compiler._expression import evaluate_policies

        expr = evaluate_policies(registry, Post, "read", actor)
        actual_sql = str(expr.compile(compile_kwargs={"literal_binds": True}))

        assert_policy_sql_snapshot(
            registry,
            Post,
            "read",
            actor,
            snapshot=actual_sql,
            normalize_whitespace=False,
        )
