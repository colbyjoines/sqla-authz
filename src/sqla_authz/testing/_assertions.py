"""Assertion helpers for testing sqla-authz authorization behavior."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm import Session

from sqla_authz._types import ActorLike
from sqla_authz.compiler._query import authorize_query
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = ["assert_authorized", "assert_denied", "assert_query_contains"]


def assert_authorized(
    session: Session,
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    expected_count: int | None = None,
    registry: PolicyRegistry | None = None,
) -> None:
    """Assert that a query returns results after authorization.

    Applies ``authorize_query`` and executes the statement. Fails with
    ``AssertionError`` if zero rows are returned. Optionally checks
    that the exact number of rows matches ``expected_count``.

    Args:
        session: A SQLAlchemy ``Session`` to execute the query.
        stmt: A ``Select`` statement to authorize.
        actor: The actor to authorize as.
        action: The action string (e.g., ``"read"``).
        expected_count: If given, assert exactly this many rows.
        registry: Optional custom registry.

    Example::

        assert_authorized(session, select(Post), admin, "read", expected_count=3)
    """
    target_registry = registry if registry is not None else get_default_registry()
    authorized_stmt = authorize_query(
        stmt,
        actor=actor,
        action=action,
        registry=target_registry,
    )
    results = session.execute(authorized_stmt).scalars().all()
    count = len(results)

    if count == 0:
        raise AssertionError(
            f"expected authorized query to return rows, but got 0 "
            f"(actor={actor!r}, action={action!r})"
        )

    if expected_count is not None and count != expected_count:
        raise AssertionError(
            f"expected {expected_count} rows, but got {count} (actor={actor!r}, action={action!r})"
        )


def assert_denied(
    session: Session,
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    registry: PolicyRegistry | None = None,
) -> None:
    """Assert that a query returns zero results after authorization.

    The inverse of ``assert_authorized`` — verifies deny-by-default
    or explicit denial.

    Args:
        session: A SQLAlchemy ``Session`` to execute the query.
        stmt: A ``Select`` statement to authorize.
        actor: The actor to authorize as.
        action: The action string.
        registry: Optional custom registry.

    Example::

        assert_denied(session, select(Post), anonymous_user, "delete")
    """
    target_registry = registry if registry is not None else get_default_registry()
    authorized_stmt = authorize_query(
        stmt,
        actor=actor,
        action=action,
        registry=target_registry,
    )
    results = session.execute(authorized_stmt).scalars().all()
    count = len(results)

    if count != 0:
        raise AssertionError(
            f"expected zero rows but got {count} (actor={actor!r}, action={action!r})"
        )


def assert_query_contains(
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    text: str,
    registry: PolicyRegistry | None = None,
) -> None:
    """Assert that compiled SQL of an authorized query contains the given text.

    Useful for structural tests that verify filter expressions are applied
    without requiring a database connection.

    Args:
        stmt: A ``Select`` statement to authorize.
        actor: The actor to authorize as.
        action: The action string.
        text: The text to search for in the compiled SQL.
        registry: Optional custom registry.

    Example::

        assert_query_contains(
            select(Post), admin, "read",
            text="is_published", registry=registry,
        )
    """
    target_registry = registry if registry is not None else get_default_registry()
    authorized_stmt = authorize_query(
        stmt,
        actor=actor,
        action=action,
        registry=target_registry,
    )
    compiled_sql = str(authorized_stmt.compile(compile_kwargs={"literal_binds": True}))

    if text not in compiled_sql:
        raise AssertionError(f"{text!r} not found in compiled SQL:\n{compiled_sql}")
