"""verify_scopes() — startup safety check for scope coverage."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase

from sqla_authz.exceptions import UnscopedModelError
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["verify_scopes"]


def verify_scopes(
    base: type[DeclarativeBase],
    *,
    field: str | None = None,
    when: Callable[[type], bool] | None = None,
    registry: PolicyRegistry | None = None,
) -> None:
    """Verify that all matching models have scope coverage.

    Scans all concrete subclasses of *base* and checks that each
    matching model has at least one registered scope.

    Exactly one of *field* or *when* must be provided.

    Args:
        base: The SQLAlchemy ``DeclarativeBase`` class to scan.
        field: Column name to match on.  Models with this column
            are expected to have a scope.
        when: Predicate ``(Model) -> bool``.  Models for which
            the predicate returns ``True`` are expected to have a scope.
        registry: Optional custom registry.  Defaults to the global registry.

    Raises:
        ValueError: If neither or both of *field* and *when* are provided.
        UnscopedModelError: If any matching models lack scope coverage.

    Example::

        from sqla_authz import verify_scopes
        verify_scopes(Base, field="org_id")
    """
    if field is None and when is None:
        raise ValueError("Either 'field' or 'when' must be provided")
    if field is not None and when is not None:
        raise ValueError("Only one of 'field' or 'when' may be provided, not both")

    target_registry = registry if registry is not None else get_default_registry()

    if field is not None:
        predicate = _field_predicate(field)
    else:
        assert when is not None
        predicate = when

    unscoped: list[type] = []
    for model in _concrete_subclasses(base):
        if predicate(model) and not target_registry.has_scopes(model):
            unscoped.append(model)

    if unscoped:
        raise UnscopedModelError(models=unscoped, field=field)


def _field_predicate(field: str) -> Callable[[type], bool]:
    """Return a predicate that checks if a model has the given column."""

    def check(model: type) -> bool:
        try:
            mapper = sa_inspect(model)
        except Exception:
            return False
        return field in mapper.column_attrs

    return check


def _concrete_subclasses(base: type) -> list[type]:
    """Collect all concrete (non-abstract) mapped subclasses of *base*."""
    result: list[type] = []
    for cls in base.__subclasses__():
        # Skip abstract bases (no __tablename__)
        if hasattr(cls, "__tablename__"):
            result.append(cls)
        result.extend(_concrete_subclasses(cls))
    return result
