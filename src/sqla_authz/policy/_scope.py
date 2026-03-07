"""@scope decorator — register cross-cutting authorization filters."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy import ColumnElement

from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["ScopeRegistration", "scope"]


@dataclass(frozen=True, slots=True)
class ScopeRegistration:
    """A registered scope function with its metadata.

    Attributes:
        applies_to: The model classes this scope applies to.
        fn: The scope function ``(actor, Model) -> ColumnElement[bool]``.
        name: The scope function name (for debugging/logging).
        description: Human-readable description (from docstring).
        actions: Actions this scope is restricted to, or ``None`` for all.
    """

    applies_to: tuple[type, ...]
    fn: Callable[..., ColumnElement[bool]]
    name: str
    description: str
    actions: tuple[str, ...] | None


def _validate_scope_signature(fn: Callable[..., ColumnElement[bool]]) -> None:
    """Validate that a scope function has at least two positional parameters."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return

    params = [
        p
        for p in sig.parameters.values()
        if p.default is inspect.Parameter.empty
        and p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(params) < 2:
        raise TypeError(
            f"Scope function {fn!r} must accept at least two positional "
            f"parameters (actor, Model), but has signature {sig}"
        )


F = TypeVar("F", bound=Callable[..., ColumnElement[bool]])


def scope(
    applies_to: Sequence[type],
    *,
    actions: Sequence[str] | None = None,
    registry: PolicyRegistry | None = None,
) -> Callable[[F], F]:
    """Decorator that registers a cross-cutting scope filter.

    Scopes are AND'd with OR'd policy results for matching models.
    They enforce invariants like tenant isolation that must not be
    accidentally bypassed by adding a new policy.

    The decorated function receives ``(actor, Model)`` where ``Model``
    is the class currently being filtered, and returns a
    ``ColumnElement[bool]``.

    Args:
        applies_to: List of SQLAlchemy model classes this scope covers.
        actions: Optional list of actions to restrict this scope to.
            If ``None`` (default), the scope applies to all actions.
        registry: Optional custom registry. Defaults to the global registry.

    Returns:
        A decorator that registers the function and returns it unchanged.

    Example::

        @scope(applies_to=[Post, Comment, Document])
        def tenant_scope(actor: User, Model: type) -> ColumnElement[bool]:
            return Model.org_id == actor.org_id

        @scope(applies_to=[Post, Comment], actions=["read"])
        def soft_delete(actor: User, Model: type) -> ColumnElement[bool]:
            return Model.deleted_at.is_(None)
    """
    if not applies_to:
        raise ValueError("applies_to must be a non-empty sequence of model classes")

    def decorator(fn: F) -> F:
        _validate_scope_signature(fn)

        target = registry if registry is not None else get_default_registry()
        scope_reg = ScopeRegistration(
            applies_to=tuple(applies_to),
            fn=fn,
            name=fn.__name__,
            description=fn.__doc__ or "",
            actions=tuple(actions) if actions is not None else None,
        )
        target.register_scope(scope_reg)
        return fn

    return decorator
