"""Exception hierarchy for sqla-authz."""

from __future__ import annotations

__all__ = [
    "AuthzError",
    "AuthorizationDenied",
    "NoPolicyError",
    "PolicyCompilationError",
]


class AuthzError(Exception):
    """Base exception for all sqla-authz errors."""


class AuthorizationDenied(AuthzError):  # noqa: N818
    """Actor is not authorized to perform the requested action.

    Attributes:
        actor: The actor that was denied.
        action: The action that was attempted.
        resource_type: The type of resource involved.

    Example::

        try:
            authorize(user, "delete", post)
        except AuthorizationDenied as exc:
            print(f"{exc.actor} cannot {exc.action} {exc.resource_type}")
    """

    def __init__(
        self,
        *,
        actor: object,
        action: str,
        resource_type: str,
        message: str | None = None,
    ) -> None:
        self.actor = actor
        self.action = action
        self.resource_type = resource_type
        if message is None:
            message = f"Actor {actor!r} is not authorized to {action} {resource_type}"
        super().__init__(message)


class NoPolicyError(AuthzError):
    """No policy registered for (resource_type, action).

    Raised when configured to error on missing policies instead of
    the default deny-by-default (WHERE FALSE) behavior.

    Attributes:
        resource_type: The resource type with no policy.
        action: The action with no policy.

    Example::

        configure(on_missing_policy="raise")
        # Now missing policies raise instead of silently denying
    """

    def __init__(
        self,
        *,
        resource_type: str,
        action: str,
    ) -> None:
        self.resource_type = resource_type
        self.action = action
        super().__init__(f"No policy registered for ({resource_type}, {action!r})")


class PolicyCompilationError(AuthzError):
    """Policy returned an invalid expression.

    Raised when a policy function returns something other than
    a SQLAlchemy ``ColumnElement[bool]``.
    """
