"""PolicyRegistration dataclass — metadata for a registered policy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import ColumnElement

__all__ = ["PolicyRegistration"]


@dataclass(frozen=True, slots=True)
class PolicyRegistration:
    """A single registered policy function with its metadata.

    Attributes:
        resource_type: The SQLAlchemy model class this policy applies to.
        action: The action string (e.g., "read", "update", "delete").
        fn: The policy function that takes an actor and returns a filter.
        name: The policy function name (for debugging/logging).
        description: Human-readable description (from docstring).
    """

    resource_type: type
    action: str
    fn: Callable[..., ColumnElement[bool]]
    name: str
    description: str
