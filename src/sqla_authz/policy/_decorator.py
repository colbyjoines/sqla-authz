"""@policy decorator — register authorization policy functions."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

from sqlalchemy import ColumnElement

from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

if TYPE_CHECKING:
    from sqla_authz.policy._predicate import Predicate

__all__ = ["policy"]

F = TypeVar("F", bound=Callable[..., ColumnElement[bool]])


def policy(
    resource_type: type,
    action: str,
    *,
    predicate: Predicate | None = None,
    registry: PolicyRegistry | None = None,
) -> Callable[[F], F]:
    """Decorator that registers a policy function for (model, action).

    The decorated function receives an actor and returns a
    ``ColumnElement[bool]`` filter expression.

    When ``predicate`` is provided, the predicate's ``__call__`` is
    registered as the policy function instead of the decorated function body.
    The decorated function is still used for its name and docstring.

    Args:
        resource_type: The SQLAlchemy model class.
        action: The action string (e.g., "read", "update").
        predicate: Optional composable predicate to use as the policy function.
        registry: Optional custom registry. Defaults to the global registry.

    Returns:
        A decorator that registers the function and returns it unchanged.

    Example::

        @policy(Post, "read")
        def post_read(actor: User) -> ColumnElement[bool]:
            return or_(
                Post.is_published == True,
                Post.author_id == actor.id,
            )

        @policy(Post, "update", predicate=is_author)
        def post_update(actor: User) -> ColumnElement[bool]:
            ...
    """

    def decorator(fn: F) -> F:
        target = registry if registry is not None else get_default_registry()
        policy_fn: Callable[..., ColumnElement[bool]] = predicate if predicate is not None else fn
        target.register(
            resource_type,
            action,
            policy_fn,
            name=fn.__name__,
            description=fn.__doc__ or "",
        )
        return fn

    return decorator
