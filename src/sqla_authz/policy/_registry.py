"""PolicyRegistry — stores and retrieves policy registrations."""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from sqlalchemy import ColumnElement

from sqla_authz.policy._base import PolicyRegistration

if TYPE_CHECKING:
    from sqla_authz.policy._scope import ScopeRegistration

if TYPE_CHECKING:
    from sqla_authz.policy._scope import ScopeRegistration

__all__ = ["PolicyRegistry", "get_default_registry"]


def _validate_policy_signature(fn: Callable[..., ColumnElement[bool]]) -> None:
    """Validate that a policy function has at least one positional parameter."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return  # Can't inspect (builtins, C extensions) — skip validation

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
    if len(params) < 1:
        raise TypeError(
            f"Policy function {fn!r} must accept at least one positional "
            f"parameter (actor), but has signature {sig}"
        )


class PolicyRegistry:
    """Registry that maps (model, action) pairs to policy functions.

    All public methods are thread-safe via an internal lock.

    Example::

        registry = PolicyRegistry()
        registry.register(Post, "read", my_policy_fn, name="p", description="")
        policies = registry.lookup(Post, "read")
    """

    def __init__(self) -> None:
        self._policies: dict[tuple[type, str], list[PolicyRegistration]] = {}
        self._scopes: list[ScopeRegistration] = []
        self._lock = threading.Lock()

    def register(
        self,
        resource_type: type,
        action: str,
        fn: Callable[..., ColumnElement[bool]],
        *,
        name: str,
        description: str,
        validate_signature: bool = True,
        query_only: bool = False,
    ) -> None:
        """Register a policy function for a (model, action) pair.

        Multiple policies can be registered for the same key; they will
        be OR'd together at evaluation time.

        Args:
            resource_type: The SQLAlchemy model class.
            action: The action string (e.g., ``"read"``, ``"update"``).
            fn: A callable that takes an actor and returns a
                ``ColumnElement[bool]`` filter expression.
            name: Human-readable name for the policy (used in logging).
            description: Description of the policy (typically the docstring).
            validate_signature: If ``True`` (default), validate that *fn*
                accepts at least one positional parameter.

        Returns:
            None

        Example::

            registry = PolicyRegistry()
            registry.register(
                Post, "read",
                lambda actor: Post.is_published == True,
                name="published_only",
                description="Allow reading published posts",
            )
        """
        if validate_signature:
            _validate_policy_signature(fn)

        registration = PolicyRegistration(
            resource_type=resource_type,
            action=action,
            fn=fn,
            name=name,
            description=description,
            query_only=query_only,
        )
        key = (resource_type, action)
        with self._lock:
            if key not in self._policies:
                self._policies[key] = []
            self._policies[key].append(registration)

    def lookup(self, resource_type: type, action: str) -> list[PolicyRegistration]:
        """Look up all policies for a (model, action) pair.

        Returns a copy of the internal list so callers cannot mutate
        the registry state.

        Args:
            resource_type: The SQLAlchemy model class to look up.
            action: The action string to look up.

        Returns:
            A list of ``PolicyRegistration`` objects.  Empty list if
            no policies are registered for the given key.

        Example::

            policies = registry.lookup(Post, "read")
            for p in policies:
                print(p.name)
        """
        with self._lock:
            return list(self._policies.get((resource_type, action), []))

    def has_policy(self, resource_type: type, action: str) -> bool:
        """Check whether at least one policy exists for (model, action).

        Args:
            resource_type: The SQLAlchemy model class.
            action: The action string.

        Returns:
            ``True`` if at least one policy is registered, ``False`` otherwise.

        Example::

            if not registry.has_policy(Post, "delete"):
                print("No delete policy for Post")
        """
        with self._lock:
            return (resource_type, action) in self._policies

    def registered_entities(self, action: str) -> set[type]:
        """Return all entity types that have policies registered for *action*.

        Useful for applying loader criteria to relationship loads
        that are not part of the main query.

        Args:
            action: The action string to filter by.

        Returns:
            A set of model classes with registered policies for the action.

        Example::

            entities = registry.registered_entities("read")
            # e.g., {Post, User}
        """
        with self._lock:
            return {entity for entity, act in self._policies if act == action}

    def registered_keys(self) -> set[tuple[type, str]]:
        """Return all (model, action) pairs that have registered policies.

        Returns:
            A set of ``(resource_type, action)`` tuples.

        Example::

            keys = registry.registered_keys()
            # e.g., {(Post, "read"), (Post, "update")}
        """
        with self._lock:
            return set(self._policies.keys())

    def known_actions(self) -> set[str]:
        """Return all action strings that have registered policies.

        Thread-safe. Useful for introspection and validation.

        Returns:
            A set of action strings.

        Example::

            actions = registry.known_actions()
            # e.g., {"read", "update", "delete"}
        """
        with self._lock:
            return {action for _, action in self._policies.keys()}

    def known_actions_for(self, resource_type: type) -> set[str]:
        """Return all action strings registered for a specific model.

        Args:
            resource_type: The SQLAlchemy model class.

        Returns:
            A set of action strings registered for that model.

        Example::

            actions = registry.known_actions_for(Post)
            # e.g., {"read", "update"}
        """
        with self._lock:
            return {
                act
                for rt, act in self._policies.keys()
                if rt is resource_type
            }

    def register_scope(self, scope_reg: ScopeRegistration) -> None:
        """Register a cross-cutting scope filter.

        Args:
            scope_reg: A ``ScopeRegistration`` containing the scope
                function, target models, and optional action restriction.

        Example::

            from sqla_authz.policy._scope import ScopeRegistration
            reg = ScopeRegistration(
                applies_to=(Post, Comment),
                fn=my_scope_fn,
                name="tenant",
                description="Tenant isolation",
                actions=None,
            )
            registry.register_scope(reg)
        """
        with self._lock:
            self._scopes.append(scope_reg)

    def lookup_scopes(
        self, resource_type: type, action: str | None = None
    ) -> list[ScopeRegistration]:
        """Look up all scopes that apply to a model and optional action.

        Args:
            resource_type: The SQLAlchemy model class.
            action: Optional action string to filter by. Scopes with
                no ``actions`` restriction always match. Scopes with
                an ``actions`` list only match if *action* is included.

        Returns:
            A list of matching ``ScopeRegistration`` objects.

        Example::

            scopes = registry.lookup_scopes(Post, "read")
        """
        with self._lock:
            result: list[ScopeRegistration] = []
            for s in self._scopes:
                if resource_type not in s.applies_to:
                    continue
                if action is not None and s.actions is not None and action not in s.actions:
                    continue
                result.append(s)
            return result

    def has_scopes(self, resource_type: type) -> bool:
        """Check whether at least one scope exists for a model.

        Args:
            resource_type: The SQLAlchemy model class.

        Returns:
            ``True`` if at least one scope covers this model.

        Example::

            if registry.has_scopes(Post):
                print("Post has scope coverage")
        """
        with self._lock:
            return any(resource_type in s.applies_to for s in self._scopes)

    def clear(self) -> None:
        """Remove all registered policies and scopes.

        Primarily useful in test teardown to reset the registry state
        between tests.

        Returns:
            None

        Example::

            registry.clear()
            assert registry.lookup(Post, "read") == []
        """
        with self._lock:
            self._policies.clear()
            self._scopes.clear()


# Module-level default registry (singleton).
_default_registry = PolicyRegistry()


def get_default_registry() -> PolicyRegistry:
    """Return the global default (singleton) policy registry.

    This is the registry used by ``@policy``, ``authorize_query``,
    and other APIs when no explicit registry is provided.

    Returns:
        The module-level ``PolicyRegistry`` singleton.

    Example::

        registry = get_default_registry()
        registry.clear()  # reset between tests
    """
    return _default_registry
