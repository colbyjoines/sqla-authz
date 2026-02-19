"""Composable predicates for authorization policies."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import ColumnElement, and_, false, not_, or_, true

from sqla_authz._types import ActorLike

__all__ = ["Predicate", "predicate", "always_allow", "always_deny"]


class Predicate:
    """A composable authorization predicate.

    Wraps a callable that takes an actor and returns a
    ``ColumnElement[bool]``. Supports ``&`` (AND), ``|`` (OR),
    and ``~`` (NOT) composition.

    Example::

        is_published = Predicate(lambda actor: Post.is_published == True)
        is_author = Predicate(lambda actor: Post.author_id == actor.id)

        combined = is_published | is_author
        expr = combined(current_user)  # ColumnElement[bool]
    """

    def __init__(self, fn: Callable[..., ColumnElement[bool]], *, name: str = "") -> None:
        self._fn = fn
        self._name = name or getattr(fn, "__name__", "<anonymous>")

    def __call__(self, actor: ActorLike) -> ColumnElement[bool]:
        return self._fn(actor)

    def __and__(self, other: Predicate) -> Predicate:
        def _and(actor: ActorLike) -> ColumnElement[bool]:
            return and_(self(actor), other(actor))

        return Predicate(_and, name=f"({self._name} & {other._name})")

    def __or__(self, other: Predicate) -> Predicate:
        def _or(actor: ActorLike) -> ColumnElement[bool]:
            return or_(self(actor), other(actor))

        return Predicate(_or, name=f"({self._name} | {other._name})")

    def __invert__(self) -> Predicate:
        def _not(actor: ActorLike) -> ColumnElement[bool]:
            return not_(self(actor))

        return Predicate(_not, name=f"~{self._name}")

    @property
    def name(self) -> str:
        """The human-readable name of this predicate."""
        return self._name

    def __repr__(self) -> str:
        return f"Predicate({self._name!r})"


def predicate(fn: Callable[..., ColumnElement[bool]]) -> Predicate:
    """Decorator/factory that creates a Predicate from a callable.

    Example::

        @predicate
        def is_published(actor: User) -> ColumnElement[bool]:
            return Post.is_published == True

        # Or as a factory:
        is_author = predicate(lambda actor: Post.author_id == actor.id)
    """
    return Predicate(fn, name=getattr(fn, "__name__", "<lambda>"))


# Built-in predicates


def _always_allow(actor: ActorLike) -> ColumnElement[bool]:
    return true()


def _always_deny(actor: ActorLike) -> ColumnElement[bool]:
    return false()


always_allow: Predicate = Predicate(_always_allow, name="always_allow")
always_deny: Predicate = Predicate(_always_deny, name="always_deny")
