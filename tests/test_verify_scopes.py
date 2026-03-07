"""Tests for verify_scopes() safety net function."""

from __future__ import annotations

import pytest
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sqla_authz._verify import verify_scopes
from sqla_authz.exceptions import UnscopedModelError
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration


# ---------------------------------------------------------------------------
# Test-local models for verify_scopes testing
# ---------------------------------------------------------------------------


class VerifyBase(DeclarativeBase):
    pass


class ScopedModel(VerifyBase):
    __tablename__ = "verify_scoped"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(Integer)


class UnscopedModel(VerifyBase):
    __tablename__ = "verify_unscoped"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(Integer)


class NoOrgModel(VerifyBase):
    __tablename__ = "verify_no_org"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))


class TestVerifyScopes:
    """Test the verify_scopes() safety net."""

    def test_raises_when_model_lacks_scope(self) -> None:
        """verify_scopes raises UnscopedModelError for unscoped models."""
        registry = PolicyRegistry()
        # Only register scope for ScopedModel, not UnscopedModel
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedModel,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        with pytest.raises(UnscopedModelError) as exc_info:
            verify_scopes(VerifyBase, field="org_id", registry=registry)

        assert UnscopedModel in exc_info.value.models
        assert ScopedModel not in exc_info.value.models

    def test_passes_when_all_models_scoped(self) -> None:
        """verify_scopes succeeds when all matching models have scopes."""
        registry = PolicyRegistry()
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedModel, UnscopedModel),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        # Should not raise
        verify_scopes(VerifyBase, field="org_id", registry=registry)

    def test_ignores_models_without_field(self) -> None:
        """verify_scopes ignores models that don't have the specified field."""
        registry = PolicyRegistry()
        registry.register_scope(ScopeRegistration(
            applies_to=(ScopedModel, UnscopedModel),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        # NoOrgModel has no org_id — should pass without scoping it
        verify_scopes(VerifyBase, field="org_id", registry=registry)

    def test_field_based_matching(self) -> None:
        """verify_scopes with field= checks for column presence."""
        registry = PolicyRegistry()

        with pytest.raises(UnscopedModelError) as exc_info:
            verify_scopes(VerifyBase, field="org_id", registry=registry)

        # Both ScopedModel and UnscopedModel have org_id
        names = {m.__name__ for m in exc_info.value.models}
        assert "ScopedModel" in names
        assert "UnscopedModel" in names
        assert "NoOrgModel" not in names

    def test_when_predicate(self) -> None:
        """verify_scopes with when= uses a custom predicate."""
        registry = PolicyRegistry()

        with pytest.raises(UnscopedModelError) as exc_info:
            verify_scopes(
                VerifyBase,
                when=lambda M: M.__tablename__.startswith("verify_scoped"),
                registry=registry,
            )

        # Only ScopedModel matches the predicate
        assert len(exc_info.value.models) == 1
        assert exc_info.value.models[0] is ScopedModel

    def test_requires_field_or_when(self) -> None:
        """verify_scopes raises ValueError if neither field nor when provided."""
        with pytest.raises(ValueError, match="Either"):
            verify_scopes(VerifyBase, registry=PolicyRegistry())

    def test_rejects_both_field_and_when(self) -> None:
        """verify_scopes raises ValueError if both field and when provided."""
        with pytest.raises(ValueError, match="Only one"):
            verify_scopes(
                VerifyBase,
                field="org_id",
                when=lambda M: True,
                registry=PolicyRegistry(),
            )

    def test_error_message_includes_field(self) -> None:
        """UnscopedModelError message mentions the field name."""
        registry = PolicyRegistry()
        with pytest.raises(UnscopedModelError, match="org_id"):
            verify_scopes(VerifyBase, field="org_id", registry=registry)

    def test_error_message_lists_model_names(self) -> None:
        """UnscopedModelError message lists the unscoped model names."""
        registry = PolicyRegistry()
        with pytest.raises(UnscopedModelError, match="ScopedModel"):
            verify_scopes(VerifyBase, field="org_id", registry=registry)

    def test_no_matching_models_passes(self) -> None:
        """verify_scopes passes when no models match the criteria."""
        registry = PolicyRegistry()
        # No models have 'nonexistent_column'
        verify_scopes(VerifyBase, field="nonexistent_column", registry=registry)
