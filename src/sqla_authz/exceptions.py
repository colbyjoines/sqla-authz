"""Exception hierarchy for sqla-authz."""

from __future__ import annotations

__all__ = [
    "AuthzBypassError",
    "AuthzError",
    "AuthorizationDenied",
    "NoPolicyError",
    "PolicyCompilationError",
    "UnloadedRelationshipError",
    "UnsupportedExpressionError",
    "WriteDeniedError",
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


class UnloadedRelationshipError(AuthzError):
    """Relationship was not loaded and cannot be evaluated in-memory.

    Raised when ``on_unloaded_relationship`` is set to ``"raise"`` and
    the expression evaluator encounters a relationship that has not been
    eagerly loaded on the instance.

    Attributes:
        model: The model class that owns the relationship.
        relationship: The name of the unloaded relationship.
    """

    def __init__(self, *, model: str, relationship: str) -> None:
        self.model = model
        self.relationship = relationship
        super().__init__(
            f"Relationship '{relationship}' on {model} is not loaded. "
            f"Either eagerly load it or set on_unloaded_relationship='deny'."
        )


class AuthzBypassError(AuthzError):
    """Raised in strict mode when an unprotected access pattern is detected.

    This exception is raised when ``on_unprotected_get="raise"`` or
    ``on_text_query="raise"`` and an authorization bypass is detected.

    Example::

        config = AuthzConfig(strict_mode=True, on_unprotected_get="raise")
        # session.get(Post, 1) now raises AuthzBypassError
    """


class UnsupportedExpressionError(AuthzError):
    """Expression type is not supported by the in-memory evaluator.

    Raised when ``eval_expression`` encounters a SQLAlchemy AST node
    that it does not know how to evaluate.
    """


class WriteDeniedError(AuthzError):
    """Write operation denied by authorization policy.

    Raised when ``on_write_denied="raise"`` and an UPDATE or DELETE
    statement targets rows that the actor is not authorized to modify.

    Attributes:
        actor: The actor that was denied.
        action: The action that was attempted (``"update"`` or ``"delete"``).
        resource_type: The type of resource involved.
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
