"""Tests for explain data models."""

from __future__ import annotations

import json

import pytest

from sqla_authz.explain._models import (
    AccessExplanation,
    AccessPolicyEvaluation,
    AuthzExplanation,
    EntityExplanation,
    PolicyEvaluation,
)


class TestPolicyEvaluation:
    def test_to_dict(self) -> None:
        pe = PolicyEvaluation(
            name="published_only",
            description="Allow reading published posts",
            filter_expression="posts.is_published = true",
            filter_sql="posts.is_published = 1",
        )
        d = pe.to_dict()
        assert d == {
            "name": "published_only",
            "description": "Allow reading published posts",
            "filter_expression": "posts.is_published = true",
            "filter_sql": "posts.is_published = 1",
        }

    def test_frozen(self) -> None:
        pe = PolicyEvaluation(
            name="p",
            description="d",
            filter_expression="expr",
            filter_sql="sql",
        )
        with pytest.raises(AttributeError):
            pe.name = "changed"  # type: ignore[misc]


class TestEntityExplanation:
    def test_to_dict(self) -> None:
        policy = PolicyEvaluation(
            name="p1",
            description="desc",
            filter_expression="expr",
            filter_sql="sql",
        )
        ee = EntityExplanation(
            entity_name="Post",
            entity_type="tests.conftest.Post",
            action="read",
            policies_found=1,
            policies=[policy],
            combined_filter_sql="posts.is_published = 1",
            deny_by_default=False,
        )
        d = ee.to_dict()
        assert d["entity_name"] == "Post"
        assert d["entity_type"] == "tests.conftest.Post"
        assert d["action"] == "read"
        assert d["policies_found"] == 1
        assert len(d["policies"]) == 1
        assert d["policies"][0]["name"] == "p1"
        assert d["combined_filter_sql"] == "posts.is_published = 1"
        assert d["deny_by_default"] is False

    def test_frozen(self) -> None:
        ee = EntityExplanation(
            entity_name="Post",
            entity_type="tests.conftest.Post",
            action="read",
            policies_found=0,
            policies=[],
            combined_filter_sql="0 = 1",
            deny_by_default=True,
        )
        with pytest.raises(AttributeError):
            ee.entity_name = "changed"  # type: ignore[misc]


class TestAuthzExplanation:
    def _make_explanation(self) -> AuthzExplanation:
        policy = PolicyEvaluation(
            name="published_only",
            description="Allow reading published posts",
            filter_expression="posts.is_published = true",
            filter_sql="posts.is_published = 1",
        )
        entity = EntityExplanation(
            entity_name="Post",
            entity_type="tests.conftest.Post",
            action="read",
            policies_found=1,
            policies=[policy],
            combined_filter_sql="posts.is_published = 1",
            deny_by_default=False,
        )
        return AuthzExplanation(
            action="read",
            actor_repr="MockActor(id=1, role='viewer', org_id=None)",
            entities=[entity],
            authorized_sql="SELECT posts.id FROM posts WHERE posts.is_published = 1",
            has_deny_by_default=False,
        )

    def test_to_dict(self) -> None:
        explanation = self._make_explanation()
        d = explanation.to_dict()
        assert d["action"] == "read"
        assert d["actor_repr"].startswith("MockActor")
        assert len(d["entities"]) == 1
        assert d["entities"][0]["entity_name"] == "Post"
        assert "authorized_sql" in d
        assert d["has_deny_by_default"] is False

    def test_to_dict_json_serializable(self) -> None:
        explanation = self._make_explanation()
        d = explanation.to_dict()
        # Should not raise
        json.dumps(d)

    def test_str_human_readable(self) -> None:
        explanation = self._make_explanation()
        s = str(explanation)
        assert "read" in s
        assert "Post" in s
        assert "published_only" in s

    def test_frozen(self) -> None:
        explanation = self._make_explanation()
        with pytest.raises(AttributeError):
            explanation.action = "changed"  # type: ignore[misc]


class TestAccessPolicyEvaluation:
    def test_to_dict(self) -> None:
        ape = AccessPolicyEvaluation(
            name="published_only",
            description="Allow reading published posts",
            filter_sql="posts.is_published = 1",
            matched=True,
        )
        d = ape.to_dict()
        assert d == {
            "name": "published_only",
            "description": "Allow reading published posts",
            "filter_sql": "posts.is_published = 1",
            "matched": True,
        }

    def test_frozen(self) -> None:
        ape = AccessPolicyEvaluation(
            name="p",
            description="d",
            filter_sql="sql",
            matched=False,
        )
        with pytest.raises(AttributeError):
            ape.matched = True  # type: ignore[misc]


class TestAccessExplanation:
    def _make_allowed(self) -> AccessExplanation:
        return AccessExplanation(
            actor_repr="MockActor(id=1, role='viewer', org_id=None)",
            action="read",
            resource_type="Post",
            resource_repr="Post(id=1)",
            allowed=True,
            deny_by_default=False,
            policies=[
                AccessPolicyEvaluation(
                    name="published_only",
                    description="Allow reading published posts",
                    filter_sql="posts.is_published = 1",
                    matched=True,
                ),
            ],
        )

    def _make_denied(self) -> AccessExplanation:
        return AccessExplanation(
            actor_repr="MockActor(id=1, role='viewer', org_id=None)",
            action="read",
            resource_type="Post",
            resource_repr="Post(id=2)",
            allowed=False,
            deny_by_default=False,
            policies=[
                AccessPolicyEvaluation(
                    name="published_only",
                    description="Allow reading published posts",
                    filter_sql="posts.is_published = 1",
                    matched=False,
                ),
            ],
        )

    def test_to_dict(self) -> None:
        ae = self._make_allowed()
        d = ae.to_dict()
        assert d["allowed"] is True
        assert d["action"] == "read"
        assert d["resource_type"] == "Post"
        assert len(d["policies"]) == 1
        assert d["policies"][0]["matched"] is True
        assert d["deny_by_default"] is False

    def test_str_allowed(self) -> None:
        ae = self._make_allowed()
        s = str(ae)
        assert "ALLOWED" in s
        assert "read" in s
        assert "Post" in s

    def test_str_denied(self) -> None:
        ae = self._make_denied()
        s = str(ae)
        assert "DENIED" in s
        assert "read" in s

    def test_to_dict_json_serializable(self) -> None:
        ae = self._make_allowed()
        d = ae.to_dict()
        json.dumps(d)

    def test_frozen(self) -> None:
        ae = self._make_allowed()
        with pytest.raises(AttributeError):
            ae.allowed = False  # type: ignore[misc]
