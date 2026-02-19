"""PolicyRegistry — stores and retrieves policy registrations."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import ColumnElement

from sqla_authz.policy._base import PolicyRegistration

__all__ = ["PolicyRegistry", "get_default_registry"]


class PolicyRegistry:
    """Registry that maps (model, action) pairs to policy functions.

    Thread-safe for reads after startup. Append-only during registration.

    Example::

        registry = PolicyRegistry()
        registry.register(Post, "read", my_policy_fn, name="p", description="")
        policies = registry.lookup(Post, "read")
    """

    def __init__(self) -> None:
        self._policies: dict[tuple[type, str], list[PolicyRegistration]] = {}

    def register(
        self,
        resource_type: type,
        action: str,
        fn: Callable[..., ColumnElement[bool]],
        *,
        name: str,
        description: str,
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
        registration = PolicyRegistration(
            resource_type=resource_type,
            action=action,
            fn=fn,
            name=name,
            description=description,
        )
        key = (resource_type, action)
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
        return {entity for entity, act in self._policies if act == action}

    def clear(self) -> None:
        """Remove all registered policies.

        Primarily useful in test teardown to reset the registry state
        between tests.

        Returns:
            None

        Example::

            registry.clear()
            assert registry.lookup(Post, "read") == []
        """
        self._policies.clear()


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
