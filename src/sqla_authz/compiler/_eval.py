"""In-memory expression evaluator for point checks (can/authorize).

Walks the SQLAlchemy ColumnElement AST and evaluates it against a single
mapped model instance, avoiding the overhead of creating an in-memory
SQLite engine per call.
"""

from __future__ import annotations

import logging
import operator
import re
from typing import Any

from sqlalchemy import ColumnElement
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm.base import ATTR_EMPTY, NO_VALUE
from sqlalchemy.sql import operators as sa_operators
from sqlalchemy.sql.elements import (
    BinaryExpression,
    BindParameter,
    BooleanClauseList,
    ClauseList,
    Grouping,
    Null,
    UnaryExpression,
)
from sqlalchemy.sql.expression import Exists
from sqlalchemy.sql.expression import False_ as SAFalse
from sqlalchemy.sql.expression import True_ as SATrue

from sqla_authz.config._config import get_global_config
from sqla_authz.exceptions import UnloadedRelationshipError, UnsupportedExpressionError

__all__ = ["eval_expression"]

logger = logging.getLogger(__name__)

# Map SQLAlchemy operator symbols to Python callables.
_OPERATOR_MAP: dict[Any, Any] = {
    sa_operators.eq: operator.eq,
    sa_operators.ne: operator.ne,
    sa_operators.lt: operator.lt,
    sa_operators.le: operator.le,
    sa_operators.gt: operator.gt,
    sa_operators.ge: operator.ge,
    sa_operators.is_: operator.is_,
    sa_operators.is_not: operator.is_not,
}


def _sql_like_match(value: Any, pattern: Any, *, case_sensitive: bool = True) -> bool:
    """Match a value against a SQL LIKE pattern in-memory.

    Converts SQL wildcards (``%`` → ``.*``, ``_`` → ``.``) to a Python
    regex and performs a full-string match.
    """
    if not isinstance(value, str) or not isinstance(pattern, str):
        return False
    # Replace SQL wildcards BEFORE escaping so they aren't escaped away.
    # Use placeholders that won't collide with user text.
    _ph_pct = "\x00PCT\x00"
    _ph_usc = "\x00USC\x00"
    temp = pattern.replace("%", _ph_pct).replace("_", _ph_usc)
    regex = re.escape(temp).replace(_ph_pct, ".*").replace(_ph_usc, ".")
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.fullmatch(regex, value, flags) is not None


def eval_expression(
    expr: ColumnElement[bool],
    instance: DeclarativeBase,
) -> bool:
    """Evaluate a SQLAlchemy filter expression against a model instance in-memory.

    Args:
        expr: A SQLAlchemy ``ColumnElement[bool]`` (the policy filter).
        instance: A mapped SQLAlchemy model instance.

    Returns:
        ``True`` if the expression matches the instance, ``False`` otherwise.

    Raises:
        UnloadedRelationshipError: If a relationship is not loaded and
            ``on_unloaded_relationship`` is ``"raise"``.
        UnsupportedExpressionError: If the expression contains unsupported nodes.
    """
    return _eval(expr, instance)


def _resolve_value(element: Any, instance: DeclarativeBase) -> Any:
    """Resolve an AST node to a Python value."""
    # Unwrap Grouping
    if isinstance(element, Grouping):
        return _resolve_value(element.element, instance)  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]  # SA stubs

    # Null literal
    if isinstance(element, Null):
        return None

    # True/False literals
    if isinstance(element, SATrue):
        return True
    if isinstance(element, SAFalse):
        return False

    # BindParameter -- actor-bound values or literal values
    if isinstance(element, BindParameter):
        val: Any = element.effective_value  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]  # SA stubs
        if val is None:
            val = element.value  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]  # SA stubs
        return val  # pyright: ignore[reportUnknownVariableType]  # SA stubs

    # Column reference -- read attribute from instance
    if hasattr(element, "key") and hasattr(element, "table"):
        key = element.key
        return getattr(instance, key, None)

    # ClauseList inside IN -- extract values from the list of bind params
    if isinstance(element, ClauseList):
        return [_resolve_value(c, instance) for c in element.clauses]

    return element


def _eval(expr: Any, instance: DeclarativeBase) -> bool:
    """Recursively evaluate an expression AST node."""
    # --- Unwrap Grouping ---
    if isinstance(expr, Grouping):
        return _eval(expr.element, instance)  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]  # SA stubs

    # --- True / False literals ---
    if isinstance(expr, SATrue):
        return True
    if isinstance(expr, SAFalse):
        return False

    # --- Boolean clause lists (AND / OR) ---
    if isinstance(expr, BooleanClauseList):
        op = expr.operator
        if op is sa_operators.and_:
            return all(_eval(clause, instance) for clause in expr.clauses)
        if op is sa_operators.or_:
            return any(_eval(clause, instance) for clause in expr.clauses)
        raise UnsupportedExpressionError(f"Unsupported BooleanClauseList operator: {op}")

    # --- EXISTS (from .has() / .any()) ---
    # IMPORTANT: Check Exists before UnaryExpression since Exists is a subclass
    if isinstance(expr, Exists):
        return _eval_exists(expr, instance)

    # --- Unary expressions (NOT) ---
    if isinstance(expr, UnaryExpression):
        if expr.operator is sa_operators.inv:
            return not _eval(expr.element, instance)
        raise UnsupportedExpressionError(f"Unsupported UnaryExpression operator={expr.operator}")

    # --- BinaryExpression (comparisons, IN) ---
    if isinstance(expr, BinaryExpression):
        return _eval_binary(expr, instance)  # pyright: ignore[reportUnknownArgumentType]  # SA stubs

    raise UnsupportedExpressionError(f"Unsupported expression type: {type(expr).__name__}")


def _eval_binary(expr: BinaryExpression[Any], instance: DeclarativeBase) -> bool:
    """Evaluate a BinaryExpression (=, !=, <, >, IN, IS, etc.)."""
    op = expr.operator

    # --- IN operator ---
    if op is sa_operators.in_op:
        left_val = _resolve_value(expr.left, instance)
        right_vals: list[Any] = _resolve_in_right(expr.right, instance)
        return left_val in right_vals

    if op is sa_operators.not_in_op:
        left_val = _resolve_value(expr.left, instance)
        not_in_vals: list[Any] = _resolve_in_right(expr.right, instance)
        return left_val not in not_in_vals

    # --- LIKE / ILIKE operators ---
    if op is sa_operators.like_op:
        return _sql_like_match(
            _resolve_value(expr.left, instance),
            _resolve_value(expr.right, instance),
            case_sensitive=True,
        )
    if op is sa_operators.ilike_op:
        return _sql_like_match(
            _resolve_value(expr.left, instance),
            _resolve_value(expr.right, instance),
            case_sensitive=False,
        )
    if op is sa_operators.not_like_op:
        return not _sql_like_match(
            _resolve_value(expr.left, instance),
            _resolve_value(expr.right, instance),
            case_sensitive=True,
        )
    if op is sa_operators.not_ilike_op:
        return not _sql_like_match(
            _resolve_value(expr.left, instance),
            _resolve_value(expr.right, instance),
            case_sensitive=False,
        )

    # --- BETWEEN operator ---
    if op is sa_operators.between_op:
        val = _resolve_value(expr.left, instance)
        # SA wraps the two bounds in an ExpressionClauseList (not ClauseList),
        # so extract them via the .clauses attribute.
        right = expr.right
        if hasattr(right, "clauses"):
            bounds: list[Any] = [_resolve_value(c, instance) for c in right.clauses]
        else:
            raw = _resolve_value(right, instance)
            bounds = raw if isinstance(raw, list) else [raw]  # pyright: ignore[reportUnknownVariableType]  # SA stubs
        if len(bounds) == 2:
            return bounds[0] <= val <= bounds[1]  # pyright: ignore[reportUnknownMemberType]  # SA stubs
        return False

    # --- String containment operators ---
    if op is sa_operators.contains_op:
        left_val = _resolve_value(expr.left, instance)
        right_val = _resolve_value(expr.right, instance)
        return isinstance(left_val, str) and isinstance(right_val, str) and right_val in left_val

    if op is sa_operators.startswith_op:
        left_val = _resolve_value(expr.left, instance)
        right_val = _resolve_value(expr.right, instance)
        if isinstance(left_val, str) and isinstance(right_val, str):
            return left_val.startswith(right_val)
        return False

    if op is sa_operators.endswith_op:
        left_val = _resolve_value(expr.left, instance)
        right_val = _resolve_value(expr.right, instance)
        if isinstance(left_val, str) and isinstance(right_val, str):
            return left_val.endswith(right_val)
        return False

    # --- Standard comparison operators (eq, ne, lt, le, gt, ge, is_, is_not) ---
    py_op = _OPERATOR_MAP.get(op)
    if py_op is not None:
        left_val = _resolve_value(expr.left, instance)
        right_val = _resolve_value(expr.right, instance)
        try:
            return bool(py_op(left_val, right_val))
        except TypeError:
            # Incompatible types (e.g., str vs int) -- treat as non-match
            return False

    raise UnsupportedExpressionError(f"Unsupported binary operator: {op}")


def _resolve_in_right(right: Any, instance: DeclarativeBase) -> list[Any]:
    """Resolve the right-hand side of an IN expression to a list of values."""
    if isinstance(right, Grouping):
        right = right.element  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]  # SA stubs
    if isinstance(right, ClauseList):
        return [_resolve_value(c, instance) for c in right.clauses]
    val = _resolve_value(right, instance)
    if isinstance(val, list):
        return val  # pyright: ignore[reportUnknownVariableType]  # SA stubs
    return [val]


# ---------------------------------------------------------------------------
# EXISTS evaluation (.has() / .any())
# ---------------------------------------------------------------------------


def _eval_exists(exists_expr: Exists, instance: DeclarativeBase) -> bool:
    """Evaluate an EXISTS expression from .has() or .any()."""
    # Exists -> ScalarSelect -> Select
    inner = exists_expr.element
    if hasattr(inner, "element"):
        select_stmt = inner.element
    else:
        select_stmt = inner

    mapper = sa_inspect(type(instance))
    instance_state = sa_inspect(instance)

    # Identify which relationship this EXISTS corresponds to by matching
    # the target table in the inner select's FROM clause.
    target_tables = _get_from_tables(select_stmt)

    for prop in mapper.relationships:
        rel_target_table = prop.mapper.local_table

        if rel_target_table.name not in target_tables:  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]  # SA stubs
            continue

        rel_name = prop.key
        attr = instance_state.attrs.get(rel_name)
        if attr is None:
            continue

        loaded_value = attr.loaded_value

        # Check if the relationship is loaded
        if loaded_value is ATTR_EMPTY or loaded_value is NO_VALUE:
            return _handle_unloaded_relationship(type(instance).__name__, rel_name)

        # Extract the user's filter by stripping join conditions
        where = _extract_where(select_stmt)
        user_filter = _strip_join_conditions(where, mapper, prop)

        if prop.uselist:
            # .any() -- check if any related object matches
            if not loaded_value:
                return False
            for related in loaded_value:
                if user_filter is None or _eval(user_filter, related):
                    return True
            return False
        else:
            # .has() -- check the single related object
            if loaded_value is None:
                return False
            if user_filter is None:
                return True
            return _eval(user_filter, loaded_value)

    raise UnsupportedExpressionError(
        f"Could not resolve EXISTS to a relationship on {type(instance).__name__}"
    )


def _get_from_tables(select_stmt: Any) -> set[str]:
    """Extract table names from a Select statement's FROM clause."""
    names: set[str] = set()
    if hasattr(select_stmt, "get_final_froms"):
        for f in select_stmt.get_final_froms():
            if hasattr(f, "name"):
                names.add(f.name)  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]  # SA stubs
    elif hasattr(select_stmt, "froms"):
        for f in select_stmt.froms:
            if hasattr(f, "name"):
                names.add(f.name)  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]  # SA stubs
    return names


def _extract_where(select_stmt: Any) -> Any:
    """Extract the WHERE clause from a Select statement."""
    if hasattr(select_stmt, "whereclause"):
        wc = select_stmt.whereclause
        if wc is not None:
            return wc
    if hasattr(select_stmt, "_where_criteria"):
        criteria = select_stmt._where_criteria
        if criteria:
            from sqlalchemy import and_

            if len(criteria) == 1:
                return criteria[0]
            return and_(*criteria)
    return None


def _strip_join_conditions(where: Any, parent_mapper: Any, prop: Any) -> Any | None:
    """Strip join-condition clauses from a WHERE, leaving only the user filter.

    Uses table name + column key matching rather than object identity,
    because SQLAlchemy annotates columns with new wrapper objects.
    """
    if where is None:
        return None

    # Collect the column signatures involved in the join.
    # For normal relationships: local_remote_pairs gives us the columns.
    # For M2M with secondary: also include the secondary table columns.
    join_sigs = _build_join_signatures(prop)

    return _strip_clauses(where, join_sigs)


def _build_join_signatures(prop: Any) -> set[tuple[str, str]]:
    """Build a set of (table_name, column_key) pairs for all join columns."""
    sigs: set[tuple[str, str]] = set()
    for local_col, remote_col in prop.local_remote_pairs:
        if hasattr(local_col, "table") and hasattr(local_col, "key"):
            sigs.add((local_col.table.name, local_col.key))
        if hasattr(remote_col, "table") and hasattr(remote_col, "key"):
            sigs.add((remote_col.table.name, remote_col.key))
    return sigs


def _col_sig(col: Any) -> tuple[str, str] | None:
    """Get the (table_name, column_key) signature of a column element."""
    unwrapped: Any = col
    if isinstance(unwrapped, Grouping):
        unwrapped = unwrapped.element  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]  # SA stubs
    if hasattr(unwrapped, "table") and hasattr(unwrapped, "key"):
        tbl: Any = unwrapped.table
        if hasattr(tbl, "name"):
            tbl_name: str = tbl.name
            col_key: str = unwrapped.key
            return (tbl_name, col_key)
    return None


def _is_join_binary(clause: BinaryExpression[Any], join_sigs: set[tuple[str, str]]) -> bool:
    """Check if a BinaryExpression is a join condition based on column signatures."""
    left_sig = _col_sig(clause.left)
    right_sig = _col_sig(clause.right)
    # A join condition has columns from two different tables, both in join_sigs
    if left_sig and right_sig:
        if left_sig in join_sigs and right_sig in join_sigs:
            return True
    return False


def _strip_clauses(where: Any, join_sigs: set[tuple[str, str]]) -> Any | None:
    """Recursively strip join-condition clauses from an AND expression."""
    if isinstance(where, BooleanClauseList) and where.operator is sa_operators.and_:
        remaining: list[Any] = []
        for clause in where.clauses:
            stripped = _strip_clauses(clause, join_sigs)
            if stripped is not None:
                remaining.append(stripped)
        if not remaining:
            return None
        if len(remaining) == 1:
            return remaining[0]
        from sqlalchemy import and_

        return and_(*remaining)

    if isinstance(where, BinaryExpression):
        if _is_join_binary(where, join_sigs):  # pyright: ignore[reportUnknownArgumentType]  # SA stubs
            return None

    return where  # pyright: ignore[reportUnknownVariableType]  # SA stubs


def _handle_unloaded_relationship(model_name: str, rel_name: str) -> bool:
    """Handle an unloaded relationship per configuration."""
    config = get_global_config()
    mode = config.on_unloaded_relationship

    if mode == "raise":
        raise UnloadedRelationshipError(model=model_name, relationship=rel_name)
    if mode == "warn":
        logger.warning(
            "Relationship '%s' on %s is not loaded; defaulting to deny.",
            rel_name,
            model_name,
        )
        return False
    # "deny" (default)
    return False
