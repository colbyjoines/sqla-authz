# Plan: Rewrite `can()` / `authorize()` Point Checks

## Problem Statement

The current `can()` implementation in `src/sqla_authz/_checks.py` has two critical issues:

### Issue 1: Performance (325x overhead)

Every `can()` call:
1. Creates a NEW in-memory SQLite engine (`create_engine("sqlite:///:memory:")`)
2. Calls `metadata.create_all(engine)` to create ALL tables from the model's metadata
3. Inserts a single row into the resource table
4. Runs a SELECT query with the policy filter
5. Disposes the engine

Benchmarks show ~1.3ms per call vs ~4us for raw policy evaluation. For 10 point checks per request, that is 13ms of pure waste. The engine/table creation dominates.

### Issue 2: Correctness (false negatives for relationship policies)

`can()` only inserts the resource row into the temp DB. If a policy uses relationship-based filters like:

```python
Post.author.has(User.org_id == actor.org_id)
```

The `users` table is empty in the temp DB, so the EXISTS subquery always returns `false`. This means **relationship-based policies always deny in point checks**, while the same policies work correctly in `authorize_query()`. The two code paths are inconsistent.

---

## Approach Selection

### Option A: Python-side SQLAlchemy expression evaluation (SELECTED)

Walk the `ColumnElement` AST produced by the policy function. Evaluate column references against the resource instance's attributes, resolve literal bind parameters, and compute the boolean result in pure Python. No SQL engine needed at all.

### Option B: Cached/pooled in-memory engine

Cache a single SQLite engine per `Base.metadata`. Reuse it across calls with a connection pool. This fixes performance (~10-50x improvement) but does NOT fix the relationship correctness issue -- you would still need to insert related rows, which means traversing the ORM graph.

### Option C: Hybrid (Python eval for simple, cached engine for complex)

Use Python eval for simple column-equality policies and fall back to a cached engine for relationship policies. Adds code complexity with two code paths. The engine path still has the relationship data problem.

### Option D: Accept optional session parameter, evaluate against real DB

Add `session: Session | None = None` to `can()`. When provided, run the filter query against the real database. When not provided, fall back to another strategy. This is correct for relationships but changes the API contract (point checks may hit the DB) and requires a session to be available.

### Trade-off Analysis

| Criterion              | A (Python eval) | B (Cached engine) | C (Hybrid) | D (Real DB) |
|------------------------|------------------|--------------------|------------|-------------|
| Performance (simple)   | < 10us           | ~100-200us         | < 10us     | ~500us+     |
| Performance (relation) | < 50us           | ~200-500us         | ~200-500us | ~500us+     |
| Relationship correct   | YES (see below)  | NO                 | PARTIAL    | YES         |
| No DB required         | YES              | YES (in-memory)    | YES        | NO          |
| API unchanged          | YES              | YES                | YES        | YES (additive) |
| Code complexity        | MEDIUM           | LOW                | HIGH       | LOW         |
| SQLAlchemy compat risk | MEDIUM           | LOW                | HIGH       | LOW         |

**Decision: Option A (Python-side evaluation) as primary, with Option D as an additive enhancement.**

Rationale:
- Option A eliminates all SQL overhead, hitting the < 50us target for simple policies
- For relationship policies, Option A resolves `has()`/`any()` by inspecting the ORM instance's loaded relationships -- if the relationship is loaded (eagerly or already accessed), evaluate against the Python objects; if not loaded, we can optionally accept a session to lazy-load, or return a conservative result
- Option D is additive: an optional `session` kwarg that, when provided, uses the real DB for maximum correctness (especially for unloaded relationships). This is a non-breaking addition

### How Python-side evaluation handles relationships

For `Post.author.has(User.org_id == actor.org_id)`:

1. The expression AST contains an EXISTS clause wrapping a correlated subquery
2. Instead of executing SQL, we inspect the relationship on the resource instance:
   - `post.author` -- if the relationship is loaded (not a lazy sentinel), we have the `User` object
   - Evaluate `User.org_id == actor.org_id` against that loaded related object
3. For `any()` (one-to-many / many-to-many): iterate the loaded collection
4. If the relationship is NOT loaded and no session is provided, we cannot evaluate it -- we raise an `UnloadedRelationshipError` or return `False` with a warning (configurable)

This is correct because:
- In typical web frameworks, relationships are either eagerly loaded or accessed before the authorization check
- The `session` parameter provides an escape hatch for lazy loading
- It is STILL more correct than the current implementation, which ALWAYS returns false for relationship policies

---

## Detailed Implementation Steps

### Step 1: Create the expression evaluator (`src/sqla_authz/compiler/_eval.py`)

New module that walks a SQLAlchemy `ColumnElement` tree and evaluates it against a model instance.

```
src/sqla_authz/compiler/_eval.py
```

#### Core function signature:

```python
def eval_expression(
    expr: ColumnElement[bool],
    instance: DeclarativeBase,
    *,
    session: Session | None = None,
) -> bool:
    """Evaluate a SQLAlchemy filter expression against a model instance in Python.

    Walks the expression AST and resolves column references against
    the instance's attribute values. No SQL is executed.

    Args:
        expr: The ColumnElement produced by policy evaluation.
        instance: The ORM model instance to check against.
        session: Optional session for lazy-loading unloaded relationships.

    Returns:
        True if the expression matches the instance, False otherwise.

    Raises:
        UnsupportedExpressionError: If the expression contains constructs
            that cannot be evaluated in Python.
    """
```

#### Expression node handlers (visitor pattern):

The evaluator uses `singledispatch` or isinstance-based dispatch on SQLAlchemy clause element types:

| SQLAlchemy Type | Python Evaluation |
|---|---|
| `BinaryExpression` (op `=`) | `getattr(instance, col.key) == right_value` |
| `BinaryExpression` (op `!=`) | `getattr(instance, col.key) != right_value` |
| `BinaryExpression` (op `<`, `>`, `<=`, `>=`) | standard Python comparison |
| `BinaryExpression` (op `IN`) | `value in collection` |
| `BinaryExpression` (op `IS`) | `value is None` |
| `BinaryExpression` (op `IS NOT`) | `value is not None` |
| `BooleanClauseList` (AND) | `all(eval(child) for child in clauses)` |
| `BooleanClauseList` (OR) | `any(eval(child) for child in clauses)` |
| `UnaryExpression` (NOT) | `not eval(child)` |
| `Exists` (from `has()`/`any()`) | resolve relationship, eval inner (see below) |
| `True_` / `true()` | `True` |
| `False_` / `false()` | `False` |
| `BindParameter` | extract `.value` (already resolved by policy fn) |
| `Column` | `getattr(instance, column.key)` |
| `Grouping` | unwrap and eval inner element |

#### Relationship resolution for EXISTS (has/any):

When we encounter an `Exists` node (produced by `relationship.has()` or `relationship.any()`):

1. **Identify the relationship**: Extract the correlated subquery. The FROM clause targets the related table. Match this back to a relationship property on the instance's mapper.

2. **Strategy - direct attribute inspection** (preferred, avoids subquery parsing):
   Rather than parsing the EXISTS subquery, we use a cleaner approach:

   Before calling `eval_expression`, we preprocess the original policy expression. When the policy function returns something like `Post.author.has(User.org_id == actor.org_id)`, the `has()` call on the instrumented attribute produces a specific clause structure. We can intercept at a higher level:

   **Alternative strategy - intercept at policy call site:**
   Instead of evaluating the raw ColumnElement, we introduce a parallel evaluation path that re-interprets the policy function's intent:

   Actually, the cleanest approach is:

   a. Detect `Exists` nodes in the expression tree
   b. For each `Exists`, find the correlated column (the join condition links parent PK to child FK or vice versa)
   c. Identify which relationship property on the mapper corresponds to this join
   d. Load the related object(s) from the instance (or via session if not loaded)
   e. Evaluate the inner WHERE conditions against the related object(s)
   f. For `has()` (MANYTOONE): related object is singular, return `eval(inner_condition, related_obj)`
   g. For `any()` (ONETOMANY/M2M): related objects are a collection, return `any(eval(inner_condition, obj) for obj in collection)`

3. **Unloaded relationships**:
   - Check `instance_state.attrs[rel_name].loaded_value` -- if it is `ATTR_EMPTY` or similar sentinel, the relationship has not been loaded
   - If `session` is provided: `session.refresh(instance, [rel_name])` to load it, then proceed
   - If `session` is None: raise `UnloadedRelationshipError` (or return False with warning, configurable via `sqla_authz.configure()`)

#### Implementation detail - resolving columns to instance attributes:

```python
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import InstanceState

def _get_column_value(instance, column):
    """Resolve a Column element to the instance's attribute value."""
    mapper = sa_inspect(type(instance))
    # column.key or column.name -> find the mapped property
    for prop in mapper.column_attrs:
        for col in prop.columns:
            if col is column or col.key == column.key:
                state: InstanceState = sa_inspect(instance)
                return state.attrs[prop.key].loaded_value
    raise ValueError(f"Column {column} not found on {type(instance)}")
```

#### Implementation detail - resolving BindParameter values:

Policy functions embed actor attributes as `BindParameter` nodes (e.g., `Post.author_id == actor.id` creates a BinaryExpression where the right side is a BindParameter with `value=actor.id`). These are already resolved to concrete Python values at policy evaluation time, so we simply read `.effective_value` or `.value`.

### Step 2: Add new exception type

In `src/sqla_authz/exceptions.py`, add:

```python
class UnloadedRelationshipError(AuthzError):
    """A relationship needed for policy evaluation was not loaded.

    Raised during Python-side point check evaluation when a relationship
    policy (has/any) references a relationship that has not been loaded
    on the instance, and no session was provided to load it.
    """

    def __init__(self, *, model: str, relationship: str) -> None:
        self.model = model
        self.relationship = relationship
        super().__init__(
            f"Relationship '{relationship}' on {model} is not loaded. "
            f"Either eagerly load the relationship or pass session= to can()."
        )
```

Add `"UnloadedRelationshipError"` to the `__all__` list.

### Step 3: Rewrite `can()` in `src/sqla_authz/_checks.py`

```python
def can(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    session: Session | None = None,
) -> bool:
    """Check if *actor* can perform *action* on a specific resource instance.

    Evaluates the policy expression in Python against the resource
    instance's attributes. No database is touched unless a relationship
    policy references an unloaded relationship and a session is provided.

    Args:
        actor: The user/principal performing the action.
        action: The action string (e.g., "read", "update").
        resource: A mapped SQLAlchemy model instance.
        registry: Optional custom registry. Defaults to the global registry.
        session: Optional SQLAlchemy session. Used to lazy-load relationships
            needed by relationship-based policies. If not provided and an
            unloaded relationship is encountered, behavior depends on config.

    Returns:
        True if access is granted, False if denied.
    """
    target_registry = registry if registry is not None else get_default_registry()
    resource_type = type(resource)

    filter_expr = evaluate_policies(target_registry, resource_type, action, actor)

    return eval_expression(filter_expr, resource, session=session)
```

Note: The `session` parameter is **additive** -- existing code that calls `can(actor, action, resource)` or `can(actor, action, resource, registry=reg)` continues to work unchanged.

### Step 4: Update `authorize()` signature

```python
def authorize(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
    session: Session | None = None,
    message: str | None = None,
) -> None:
    """Assert that *actor* is authorized to perform *action* on *resource*."""
    if not can(actor, action, resource, registry=registry, session=session):
        raise AuthorizationDenied(
            actor=actor,
            action=action,
            resource_type=type(resource).__name__,
            message=message,
        )
```

### Step 5: Add configuration option for unloaded relationship behavior

In `src/sqla_authz/config/_config.py`, add a field to the config:

```python
unloaded_relationship_behavior: str = "deny"
# Options:
#   "deny" - return False (safe default, may cause false negatives)
#   "raise" - raise UnloadedRelationshipError
#   "warn" - log a warning and return False
```

This is used in `eval_expression` when an unloaded relationship is encountered and no session is available.

### Step 6: Update `__init__.py` exports

Ensure `UnloadedRelationshipError` is exported from the package. No changes needed for `can`/`authorize` since only a keyword argument was added.

---

## Expression Evaluator Implementation Detail

The core of this rewrite is the expression evaluator. Here is the detailed dispatch logic for `_eval.py`:

```python
# Pseudocode structure

def eval_expression(expr, instance, *, session=None):
    """Top-level entry point."""
    return _eval_node(expr, instance, session)


def _eval_node(node, instance, session):
    """Dispatch on node type."""

    # --- Literal booleans ---
    if isinstance(node, True_):
        return True
    if isinstance(node, False_):
        return False

    # --- Grouping (parentheses) ---
    if isinstance(node, Grouping):
        return _eval_node(node.element, instance, session)

    # --- Boolean clause list (AND / OR) ---
    if isinstance(node, BooleanClauseList):
        if node.operator is operators.and_:
            return all(_eval_node(c, instance, session) for c in node.clauses)
        if node.operator is operators.or_:
            return any(_eval_node(c, instance, session) for c in node.clauses)

    # --- Unary (NOT, IS NULL, IS NOT NULL) ---
    if isinstance(node, UnaryExpression):
        if node.operator is operators.inv:  # NOT / ~
            return not _eval_node(node.element, instance, session)
        if node.operator is operators.is_:
            return _resolve_value(node.element, instance) is None
        if node.operator is operators.is_not:
            return _resolve_value(node.element, instance) is not None

    # --- Binary expression (=, !=, <, >, <=, >=, IN, etc.) ---
    if isinstance(node, BinaryExpression):
        left = _resolve_value(node.left, instance)
        right = _resolve_value(node.right, instance)
        return _apply_operator(node.operator, left, right)

    # --- EXISTS (from has() / any()) ---
    if isinstance(node, Exists):
        return _eval_exists(node, instance, session)

    raise UnsupportedExpressionError(f"Cannot evaluate: {type(node)}")


def _resolve_value(node, instance):
    """Resolve a node to a Python value."""
    if isinstance(node, Column):
        return _get_column_value(instance, node)
    if isinstance(node, BindParameter):
        return node.effective_value
    if isinstance(node, Null):
        return None
    if isinstance(node, Grouping):
        return _resolve_value(node.element, instance)
    # For literal columns, ClauseList in IN expressions, etc.
    ...


def _apply_operator(op, left, right):
    """Apply a SQL operator as a Python operation."""
    OP_MAP = {
        operators.eq: lambda a, b: a == b,
        operators.ne: lambda a, b: a != b,
        operators.lt: lambda a, b: a < b,
        operators.gt: lambda a, b: a > b,
        operators.le: lambda a, b: a <= b,
        operators.ge: lambda a, b: a >= b,
        operators.in_op: lambda a, b: a in b,
        operators.not_in_op: lambda a, b: a not in b,
    }
    return OP_MAP[op](left, right)


def _eval_exists(node, instance, session):
    """Evaluate an EXISTS subquery by inspecting the ORM relationship."""
    # 1. Extract the inner SELECT from the Exists
    # 2. Find the correlated column (join condition)
    # 3. Map back to a relationship property on the instance's mapper
    # 4. Load the related object(s)
    # 5. Evaluate the non-correlation WHERE clauses against related objects
    ...
```

### EXISTS evaluation detailed algorithm:

The `has()` / `any()` methods on SQLAlchemy relationship attributes produce an `Exists` wrapping a correlated subquery. The structure is:

```
Exists(
  Select(literal_column('1'))
    .select_from(related_table)
    .where(
      related_table.c.id == parent_table.c.foreign_key  # correlation
      AND <user_condition>                                # policy condition
    )
    .correlate(parent_table)
)
```

Algorithm for `_eval_exists`:

1. **Extract the inner select**: `exists_node.element` gives the `SelectBase`
2. **Parse the WHERE clause**: Split the AND clauses. Identify which clauses are **correlation conditions** (they reference columns from both the parent and related tables) vs **user conditions** (they reference only the related table)
3. **Identify the relationship**: Using the correlation columns, find which relationship property on the parent mapper joins these tables
4. **Load related data**:
   - Check `sa_inspect(instance).attrs[rel_key].loaded_value`
   - If loaded: use the Python objects directly
   - If not loaded and session provided: `getattr(instance, rel_key)` to trigger lazy load (requires instance to be in session)
   - If not loaded and no session: apply configured behavior (deny/raise/warn)
5. **Evaluate user conditions against related objects**:
   - For `has()` (single object): `_eval_node(user_condition, related_obj, session)`
   - For `any()` (collection): `any(_eval_node(user_condition, obj, session) for obj in collection)`
6. **Handle nested EXISTS** (multi-hop like `Post.author.has(Author.org.has(Org.id == x))`):
   - The user condition itself contains another Exists -- recursion handles this naturally

### Edge cases to handle:

1. **`true()` / `false()` expressions**: Direct boolean return, no column lookup needed
2. **NULL comparisons**: `IS NULL` / `IS NOT NULL` via UnaryExpression
3. **OR of multiple policies**: The `reduce(lambda a, b: a | b, filters)` in `evaluate_policies` produces a `BooleanClauseList` with OR operator
4. **Empty collection for `any()`**: Returns False (correct SQL semantics)
5. **None related object for `has()`**: Returns False (correct SQL semantics -- EXISTS on empty is false)
6. **BindParameter with callable value**: Some BindParameters use `callable_` -- call it to get value
7. **Columns from different tables in same BinaryExpression**: This happens in correlation conditions -- not in user-facing policy conditions
8. **`ClauseList` in IN expressions**: Right side of IN is a collection of BindParameters

---

## New / Modified Test Cases

### New test file: `tests/test_eval.py`

Unit tests for `eval_expression` in isolation (no `can()` wrapper):

1. **test_simple_equality_true** -- `Post.is_published == True` against published post
2. **test_simple_equality_false** -- `Post.is_published == True` against draft post
3. **test_actor_binding_match** -- `Post.author_id == actor.id` where they match
4. **test_actor_binding_no_match** -- `Post.author_id == actor.id` where they differ
5. **test_or_expression** -- `(Post.is_published == True) | (Post.author_id == actor.id)`
6. **test_and_expression** -- `(Post.is_published == True) & (Post.author_id == actor.id)`
7. **test_not_expression** -- `~(Post.is_published == True)`
8. **test_true_literal** -- `true()` returns True
9. **test_false_literal** -- `false()` returns False
10. **test_is_null** -- `Post.author_id == None` (IS NULL)
11. **test_is_not_null** -- `Post.author_id != None` (IS NOT NULL)
12. **test_comparison_operators** -- `<`, `>`, `<=`, `>=`
13. **test_in_operator** -- `Post.author_id.in_([1, 2, 3])`
14. **test_not_in_operator** -- `~Post.author_id.in_([1, 2, 3])`
15. **test_has_relationship_loaded** -- `Post.author.has(User.org_id == 1)` with author loaded
16. **test_has_relationship_not_matching** -- loaded author with wrong org_id
17. **test_has_relationship_none** -- post with no author (None)
18. **test_any_relationship_loaded** -- `Post.tags.any(Tag.visibility == 'public')` with tags loaded
19. **test_any_relationship_empty** -- post with empty tags collection
20. **test_nested_exists** -- `Post.author.has(User.org.has(Org.id == x))` (multi-hop)
21. **test_unloaded_relationship_deny_mode** -- returns False with default config
22. **test_unloaded_relationship_raise_mode** -- raises UnloadedRelationshipError
23. **test_unloaded_relationship_warn_mode** -- returns False with warning logged
24. **test_unloaded_relationship_with_session** -- lazy loads and evaluates correctly
25. **test_unsupported_expression** -- raises UnsupportedExpressionError for unknown node types

### Modified test file: `tests/test_checks.py`

All existing tests MUST continue to pass unchanged (they test the public API). Additional tests:

26. **test_can_with_session_parameter** -- verify `session=` kwarg works
27. **test_can_with_relationship_policy_loaded** -- relationship policy works when related object is loaded
28. **test_can_with_relationship_policy_and_session** -- relationship policy works with session for lazy loading
29. **test_authorize_with_session_parameter** -- verify `session=` kwarg flows through

### Modified test file: `tests/benchmarks/test_benchmarks.py`

Update `TestCanPointCheck` to verify performance improvement. Add:

30. **test_can_check_relationship** -- benchmark `can()` with relationship policy (loaded relationship)
31. **test_can_check_vs_policy_eval** -- compare `can()` overhead vs raw `evaluate_policies()` to verify it is < 10x

### New test file: `tests/test_eval_edge_cases.py`

32. **test_deeply_nested_and_or** -- `(A & B) | (C & D)` complex boolean trees
33. **test_multiple_policies_or_combined_eval** -- multiple registry policies OR'd together
34. **test_none_column_value_comparisons** -- NULL handling in all operators
35. **test_string_column_comparisons** -- string equality, IN with strings
36. **test_mixed_type_comparison** -- string actor.id compared to int column (should not crash, return False)

---

## Migration Notes

### Breaking changes: NONE

- `can(actor, action, resource, registry=...)` signature is unchanged
- `authorize(actor, action, resource, registry=..., message=...)` signature is unchanged
- The `session` parameter is keyword-only and optional with default `None`
- Behavior for simple column-equality policies is identical
- The `UnloadedRelationshipError` is a new exception that only fires in a new code path

### Behavioral changes (improvements):

1. **Relationship policies in point checks**: Previously ALWAYS returned False (silent bug). Now they work correctly when relationships are loaded. This is strictly a correctness improvement -- any code that was "working" was only working because it never relied on relationship policies in `can()`.

2. **No more SQLite dependency for point checks**: The temp DB approach is removed entirely. This eliminates edge cases with SQLite type coercion differing from the production DB.

3. **New `UnloadedRelationshipError`**: Only raised when `unloaded_relationship_behavior="raise"` is configured. Default is `"deny"` which matches current (broken) behavior of returning False for relationship policies.

### Deprecation: None

### Required dependency changes: None

All evaluation uses existing SQLAlchemy introspection APIs (`inspect()`, clause element types from `sqlalchemy.sql.elements`, `sqlalchemy.sql.operators`).

---

## Performance Benchmark Targets

| Scenario | Current | Target | Improvement |
|---|---|---|---|
| Simple policy (`Post.is_published == True`) | ~1,300us | < 20us | > 65x |
| Actor-binding policy (`Post.author_id == actor.id`) | ~1,300us | < 20us | > 65x |
| OR policy (published OR author) | ~1,300us | < 30us | > 40x |
| Relationship policy (1-hop, loaded) | ~1,300us (WRONG result) | < 50us | > 26x + correct |
| Relationship policy (2-hop, loaded) | ~1,300us (WRONG result) | < 100us | > 13x + correct |
| `true()` / `false()` literal | ~1,300us | < 5us | > 260x |
| Multiple policies (5 OR'd) | ~1,300us | < 50us | > 26x |
| `authorize()` (granted) | ~1,300us | < 25us | > 52x |
| `authorize()` (denied, exception) | ~1,300us | < 30us | > 43x |

The evaluate_policies step itself is ~4us (from benchmarks). The expression evaluator adds pure Python AST walking overhead. For a simple BinaryExpression with one column lookup, this should be ~5-15us. Total `can()` should be ~10-20us for simple cases.

---

## File-by-File Summary

| File | Action | Description |
|---|---|---|
| `src/sqla_authz/compiler/_eval.py` | **CREATE** | New expression evaluator module (~200 lines) |
| `src/sqla_authz/_checks.py` | **MODIFY** | Replace temp DB with `eval_expression()`, add `session` kwarg |
| `src/sqla_authz/exceptions.py` | **MODIFY** | Add `UnloadedRelationshipError`, `UnsupportedExpressionError` |
| `src/sqla_authz/config/_config.py` | **MODIFY** | Add `unloaded_relationship_behavior` config field |
| `src/sqla_authz/__init__.py` | **MODIFY** | Export new exception types |
| `tests/test_eval.py` | **CREATE** | Unit tests for expression evaluator (~25 test cases) |
| `tests/test_eval_edge_cases.py` | **CREATE** | Edge case tests (~10 test cases) |
| `tests/test_checks.py` | **MODIFY** | Add relationship + session tests (~4 test cases) |
| `tests/benchmarks/test_benchmarks.py` | **MODIFY** | Add relationship can() benchmarks (~2 test cases) |

---

## Implementation Order

1. Add new exception types to `exceptions.py`
2. Add config field to `config/_config.py`
3. Implement `compiler/_eval.py` (core evaluator, no EXISTS support yet)
4. Write unit tests for simple expression evaluation (`test_eval.py` cases 1-14)
5. Rewrite `can()` and `authorize()` in `_checks.py`
6. Run existing `test_checks.py` -- all must pass
7. Implement EXISTS/relationship evaluation in `_eval.py`
8. Write relationship tests (`test_eval.py` cases 15-25)
9. Write edge case tests (`test_eval_edge_cases.py`)
10. Update benchmark tests and verify performance targets
11. Update exports in `__init__.py`
12. Run full test suite, including benchmarks

---

## Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| SQLAlchemy internal API changes (clause element structure) | LOW | Use only documented/stable clause types. Pin minimum SQLAlchemy version. Add defensive isinstance checks with clear error messages. |
| Missing expression type in evaluator | MEDIUM | The `UnsupportedExpressionError` provides a clear message. Can iteratively add support for new expression types. Log the unsupported type for debugging. |
| Relationship loading side effects | LOW | Document that `session` parameter may trigger lazy loads. Make it opt-in (default None). |
| Performance regression for very complex expressions | LOW | The AST walk is O(n) in expression nodes. Even complex policies have < 50 nodes. Benchmark confirms. |
| EXISTS subquery structure varies across SQLAlchemy versions | MEDIUM | Test against SQLAlchemy 2.0+ minimum. The `has()`/`any()` clause structure has been stable since 1.4. Add version-specific tests if needed. |
