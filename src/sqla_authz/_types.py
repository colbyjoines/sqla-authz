"""Shared protocols and type aliases for sqla-authz."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sqlalchemy import ColumnElement

__all__ = ["ActorLike", "FilterExpression"]


@runtime_checkable
class ActorLike(Protocol):
    """Structural type for authorization actors.

    Any object with an ``id`` attribute satisfies this protocol.
    Works with SQLAlchemy models, dataclasses, Pydantic models,
    named tuples — no inheritance required.

    Example::

        @dataclass
        class User:
            id: int
            name: str

        user = User(id=1, name="Alice")
        assert isinstance(user, ActorLike)
    """

    @property
    def id(self) -> int | str: ...


# The universal output type for policy functions.
FilterExpression = ColumnElement[bool]
