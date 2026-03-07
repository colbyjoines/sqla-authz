"""Exception hierarchy for sqla-authz."""

from __future__ import annotations

__all__ = [
    "AuthzBypassError",
    "AuthzError",
    "AuthorizationDenied",
    "NoPolicyError",
    "PolicyCompilationError",
    "QueryOnlyPolicyError",
    "UnknownActionError",
    "UnloadedRelationshipError",
    "UnscopedModelError",
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


class UnknownActionError(AuthzError):
    """Action string has no registered policies for any model.

    Raised when ``on_unknown_action="raise"`` and the action string
    doesn't match any registered policy. This typically indicates a
    typo in the action name.

    Attributes:
        action: The unrecognized action string.
        known_actions: List of valid action strings.
        suggestion: Closest matching action, if any.

    Example::

        configure(on_unknown_action="raise")
        # authorize_query(..., action="raed") now raises:
        # UnknownActionError: Action 'raed' has no registered policies.
        #   Did you mean 'read'?
        #   Known actions: ['create', 'delete', 'read', 'update']
    """

    def __init__(
        self,
        *,
        action: str,
        known_actions: list[str],
        suggestion: str | None = None,
    ) -> None:
        self.action = action
        self.known_actions = known_actions
        self.suggestion = suggestion
        parts = [f"Action {action!r} has no registered policies."]
        if suggestion:
            parts.append(f"Did you mean {suggestion!r}?")
        parts.append(f"Known actions: {known_actions}")
        super().__init__(" ".join(parts))


class QueryOnlyPolicyError(AuthzError):
    """Point check attempted on a query-only policy.

    Raised when ``can()`` or ``authorize()`` is called and one or more
    matching policies are marked ``query_only=True``.  These policies use
    SQL constructs that cannot be evaluated in-memory.

    Use ``authorize_query()`` instead, or remove the ``query_only`` flag
    if the policy only uses supported operators.

    Attributes:
        resource_type: The model class name involved.
        action: The action string.
        query_only_policies: Names of the query-only policies.
    """

    def __init__(
        self,
        *,
        resource_type: str,
        action: str,
        query_only_policies: list[str],
    ) -> None:
        self.resource_type = resource_type
        self.action = action
        self.query_only_policies = query_only_policies
        names = ", ".join(query_only_policies)
        super().__init__(
            f"Cannot use can()/authorize() for ({resource_type}, {action!r}): "
            f"the following policies are query-only: [{names}]. "
            f"Use authorize_query() instead."
        )


class UnscopedModelError(AuthzError):
    """One or more models lack required scope coverage.

    Raised by ``verify_scopes()`` when models matching the check
    criteria have no registered scopes.

    Attributes:
        models: The model classes that lack scope coverage.
        field: The field name used for matching (if any).
    """

    def __init__(
        self,
        *,
        models: list[type],
        field: str | None = None,
    ) -> None:
        self.models = models
        self.field = field
        names = ", ".join(m.__name__ for m in models)
        if field:
            msg = (
                f"The following models have a '{field}' column but no "
                f"registered scope: {names}"
            )
        else:
            msg = f"The following models have no registered scope: {names}"
        super().__init__(msg)


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
