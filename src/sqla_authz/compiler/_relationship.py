"""Relationship traversal — build EXISTS subqueries via has()/any()."""

from __future__ import annotations

from typing import Any

from sqlalchemy import ColumnElement
from sqlalchemy.inspection import inspect as sa_inspect
from sqlalchemy.orm import Mapper, RelationshipDirection, RelationshipProperty

__all__ = ["traverse_relationship_path"]


def traverse_relationship_path(
    model: type,
    path: list[str],
    leaf_condition: ColumnElement[bool],
) -> ColumnElement[bool]:
    """Traverse a chain of relationships and wrap in EXISTS subqueries.

    Uses ``has()`` for MANYTOONE relationships and ``any()`` for
    ONETOMANY / MANYTOMANY relationships, producing nested EXISTS
    subqueries.

    Args:
        model: The starting SQLAlchemy model class.
        path: List of relationship attribute names to traverse.
        leaf_condition: The filter condition to apply at the end of the path.

    Returns:
        A ``ColumnElement[bool]`` with nested EXISTS subqueries.

    Example::

        # Post -> author -> organization, where org.id == 1
        expr = traverse_relationship_path(
            Post, ["author", "organization"], Organization.id == 1
        )
        # Produces:
        # EXISTS (SELECT 1 FROM user WHERE user.id = post.author_id
        #   AND EXISTS (SELECT 1 FROM organization
        #     WHERE organization.id = user.org_id AND organization.id = 1))
    """
    if not path:
        return leaf_condition

    attr_name = path[0]
    mapper: Mapper[Any] = sa_inspect(model)
    prop: RelationshipProperty[Any] = mapper.relationships[attr_name]
    relationship_attr: Any = getattr(model, attr_name)
    target_model: type = prop.mapper.class_
    inner = traverse_relationship_path(target_model, path[1:], leaf_condition)

    if prop.direction is RelationshipDirection.MANYTOONE:
        result: ColumnElement[bool] = relationship_attr.has(inner)
    else:
        result = relationship_attr.any(inner)
    return result
