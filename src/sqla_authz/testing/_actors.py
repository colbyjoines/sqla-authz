"""MockActor and factory functions for testing sqla-authz policies."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["MockActor", "make_admin", "make_anonymous", "make_user"]


@dataclass(frozen=True, slots=True)
class MockActor:
    """Test actor that satisfies the ``ActorLike`` protocol.

    A lightweight, immutable dataclass for use in tests. Provides
    the ``id`` property required by ``ActorLike``, plus optional
    ``role`` and ``org_id`` attributes commonly used in policies.

    Example::

        actor = MockActor(id=1, role="admin", org_id=5)
        assert isinstance(actor, ActorLike)
    """

    id: int | str
    role: str = "viewer"
    org_id: int | None = None


def make_admin(id: int | str = 1) -> MockActor:
    """Create an admin ``MockActor``.

    Args:
        id: The actor's identifier. Defaults to ``1``.

    Returns:
        A ``MockActor`` with ``role="admin"``.

    Example::

        admin = make_admin()
        assert admin.role == "admin"
    """
    return MockActor(id=id, role="admin")


def make_user(
    id: int | str = 1,
    role: str = "viewer",
    org_id: int | None = None,
) -> MockActor:
    """Create a regular user ``MockActor``.

    Args:
        id: The actor's identifier. Defaults to ``1``.
        role: The actor's role. Defaults to ``"viewer"``.
        org_id: Optional organization ID.

    Returns:
        A ``MockActor`` with the specified attributes.

    Example::

        user = make_user(id=5, role="editor", org_id=3)
        assert user.role == "editor"
    """
    return MockActor(id=id, role=role, org_id=org_id)


def make_anonymous() -> MockActor:
    """Create an anonymous ``MockActor`` with ``id=0``.

    Returns:
        A ``MockActor`` with ``id=0`` and ``role="anonymous"``.

    Example::

        anon = make_anonymous()
        assert anon.id == 0
        assert anon.role == "anonymous"
    """
    return MockActor(id=0, role="anonymous")
