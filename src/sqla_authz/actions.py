"""Action constants and factory for sqla-authz.

Provides well-known action constants for use with ``@policy``,
``authorize_query``, ``can``, and other APIs. Using constants
instead of bare strings gives IDE autocomplete and prevents typos.

Example::

    from sqla_authz.actions import READ, UPDATE, action

    PUBLISH = action("publish")

    @policy(Post, READ)
    def post_read(actor: User) -> ColumnElement[bool]:
        return Post.is_published == True

    @policy(Post, PUBLISH)
    def post_publish(actor: User) -> ColumnElement[bool]:
        return Post.author_id == actor.id
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "CREATE",
    "DELETE",
    "READ",
    "UPDATE",
    "action",
]

READ: Final = "read"
"""Built-in action constant for read operations."""

UPDATE: Final = "update"
"""Built-in action constant for update operations."""

DELETE: Final = "delete"
"""Built-in action constant for delete operations."""

CREATE: Final = "create"
"""Built-in action constant for create operations."""


def action(name: str) -> str:
    """Create a validated action name for use in policies and queries.

    Validates that the name follows conventions: non-empty, lowercase,
    alphabetic (underscores allowed). This catches common mistakes like
    ``action("Read Posts")`` or ``action("")`` at definition time.

    Custom actions created with this factory work identically to the
    built-in constants — they're plain strings.

    Args:
        name: The action name. Must be lowercase alphabetic with
            optional underscores (e.g., ``"approve"``, ``"soft_delete"``).

    Returns:
        The validated action name string.

    Raises:
        ValueError: If the name doesn't follow naming conventions.

    Example::

        APPROVE = action("approve")
        SOFT_DELETE = action("soft_delete")
        PUBLISH = action("publish")

        @policy(Article, PUBLISH)
        def article_publish(actor: User) -> ColumnElement[bool]:
            return Article.author_id == actor.id
    """
    if not name:
        raise ValueError("Action name must be non-empty")
    if not name.replace("_", "").isalpha():
        raise ValueError(
            f"Action name must contain only lowercase letters and underscores, "
            f"got {name!r}"
        )
    if not name.islower():
        raise ValueError(
            f"Action name must be lowercase, got {name!r}. "
            f"Use {name.lower()!r} instead."
        )
    return name
