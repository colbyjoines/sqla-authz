"""Tests for compiler/_relationship.py — relationship traversal."""

from __future__ import annotations

from sqlalchemy import ColumnElement

from sqla_authz.compiler._relationship import traverse_relationship_path
from tests.conftest import Organization, Post, Tag, User


class TestTraverseRelationshipPath:
    """traverse_relationship_path() builds EXISTS subqueries via has()/any()."""

    def test_single_hop_many_to_one(self):
        """Post.author (many-to-one) should use has()."""
        condition = User.org_id == 1
        result = traverse_relationship_path(Post, ["author"], condition)
        assert isinstance(result, ColumnElement)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "EXISTS" in sql.upper() or "exists" in sql.lower()

    def test_multi_hop_traversal(self):
        """Post -> author -> organization should chain EXISTS subqueries."""
        condition = Organization.id == 1
        result = traverse_relationship_path(Post, ["author", "organization"], condition)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # Should have nested EXISTS
        assert sql.upper().count("EXISTS") >= 2 or sql.lower().count("exists") >= 2

    def test_one_to_many_uses_any(self):
        """Post.tags (many-to-many) should use any()."""
        condition = Tag.visibility == "public"
        result = traverse_relationship_path(Post, ["tags"], condition)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "EXISTS" in sql.upper() or "exists" in sql.lower()

    def test_empty_path_returns_leaf_condition(self):
        """Empty path should return the leaf condition unchanged."""
        condition = Post.is_published == True
        result = traverse_relationship_path(Post, [], condition)
        sql_original = str(condition.compile(compile_kwargs={"literal_binds": True}))
        sql_result = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert sql_original == sql_result

    def test_three_hop_deep_traversal(self):
        """Post -> author -> organization -> parent (3 hops) should chain 3 EXISTS."""
        condition = Organization.name == "Global Corp"
        result = traverse_relationship_path(Post, ["author", "organization", "parent"], condition)
        assert isinstance(result, ColumnElement)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        # Should have 3 nested EXISTS subqueries
        exists_count = sql.upper().count("EXISTS")
        assert exists_count >= 3, f"Expected >= 3 EXISTS, found {exists_count} in: {sql}"

    def test_invalid_relationship_raises(self):
        """Traversing a non-existent relationship should raise KeyError."""
        import pytest

        condition = Organization.name == "test"
        with pytest.raises(KeyError):
            traverse_relationship_path(Post, ["nonexistent_rel"], condition)
