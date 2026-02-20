# Plan 04: Policy Explain / Dry-Run Mode

## Problem

When users get unexpected zero rows from authorized queries, there is no way to
debug *why*. The existing audit logging (`_audit.py`) only logs at INFO/DEBUG
level via the standard `logging` module -- it is not programmatically
accessible, not structured, and does not capture compiled SQL or per-entity
breakdowns. Developers need a first-class explain API that answers:

- Which entities were found in my query?
- Which policies matched (or didn't) for each entity?
- What SQL filter was generated per entity?
- What does the final compiled SQL look like with literal binds?
- Why can't user X do Y on resource Z? (point check explanation)

## Design Principles

1. **Zero overhead on the hot path.** `authorize_query()` and the session
   interceptor must not pay any cost when explain mode is not used. No new
   branches, no data collection, no allocations.
2. **Reuse, don't duplicate.** Explain functions call the same `evaluate_policies()`
   and `authorize_query()` internals. We capture data *around* those calls, not
   by forking the compilation logic.
3. **Structured and serializable.** All output is plain dataclasses that
   convert to dicts/JSON trivially.
4. **Consistent API shape.** `explain_query()` mirrors `authorize_query()`;
   `explain_access()` mirrors `can()`. Same parameters, richer return type.

---

## API Design

### 1. `explain_query()`

```python
# src/sqla_authz/explain/_query.py

def explain_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
) -> AuthzExplanation:
    """Explain how authorization filters would be applied to a SELECT.

    Same parameters as authorize_query(). Returns a structured
    AuthzExplanation instead of a modified statement.
    """
```

**Behavior:** Iterates `stmt.column_descriptions` exactly like
`authorize_query()`, but for each entity it captures:
- The policies looked up from the registry
- The filter expression returned by each policy function
- The combined filter expression (OR'd)
- Whether deny-by-default was triggered (zero policies)

Then it compiles the final authorized statement with `literal_binds` to
produce the full SQL string.

### 2. `explain_access()`

```python
# src/sqla_authz/explain/_access.py

def explain_access(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
) -> AccessExplanation:
    """Explain why actor can/can't perform action on a specific resource.

    Same parameters as can(). Returns a structured AccessExplanation
    with per-policy evaluation results.
    """
```

**Behavior:** Similar to `can()` -- looks up policies, evaluates each filter
function, then evaluates each individual filter against the resource instance
using the in-memory SQLite approach. Reports which policies passed/failed
and the overall result.

### 3. Public surface

```python
# src/sqla_authz/__init__.py additions:
from sqla_authz.explain import explain_query, explain_access

# Also available from:
from sqla_authz.explain import (
    explain_query,
    explain_access,
    AuthzExplanation,
    EntityExplanation,
    PolicyEvaluation,
    AccessExplanation,
    AccessPolicyEvaluation,
)
```

---

## Data Model

### `AuthzExplanation` (for query explanation)

```python
# src/sqla_authz/explain/_models.py

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from sqlalchemy import ColumnElement


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """Result of evaluating a single policy for an entity."""

    name: str
    description: str
    filter_expression: str          # str(expr) -- the SQLAlchemy expression repr
    filter_sql: str                 # compiled SQL fragment with literal_binds

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EntityExplanation:
    """Explanation for a single entity in a query."""

    entity_name: str                # e.g. "Post"
    entity_type: str                # fully qualified: "myapp.models.Post"
    action: str
    policies_found: int
    policies: list[PolicyEvaluation]
    combined_filter_sql: str        # the OR'd expression compiled to SQL
    deny_by_default: bool           # True when policies_found == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_name": self.entity_name,
            "entity_type": self.entity_type,
            "action": self.action,
            "policies_found": self.policies_found,
            "policies": [p.to_dict() for p in self.policies],
            "combined_filter_sql": self.combined_filter_sql,
            "deny_by_default": self.deny_by_default,
        }


@dataclass(frozen=True, slots=True)
class AuthzExplanation:
    """Full explanation of how authorize_query() would filter a SELECT."""

    action: str
    actor_repr: str                 # repr(actor) for display
    entities: list[EntityExplanation]
    authorized_sql: str             # full compiled SQL with literal_binds
    has_deny_by_default: bool       # True if ANY entity triggered deny-by-default

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "actor": self.actor_repr,
            "entities": [e.to_dict() for e in self.entities],
            "authorized_sql": self.authorized_sql,
            "has_deny_by_default": self.has_deny_by_default,
        }

    def __str__(self) -> str:
        """Human-readable summary for terminal/log output."""
        lines = [f"AuthzExplanation(action={self.action!r}, actor={self.actor_repr})"]
        for ent in self.entities:
            status = "DENY (no policies)" if ent.deny_by_default else f"{ent.policies_found} policy(ies)"
            lines.append(f"  {ent.entity_name}: {status}")
            for pol in ent.policies:
                lines.append(f"    - {pol.name}: {pol.filter_sql}")
            if not ent.deny_by_default:
                lines.append(f"    combined: {ent.combined_filter_sql}")
        lines.append(f"  SQL: {self.authorized_sql}")
        return "\n".join(lines)
```

### `AccessExplanation` (for point check explanation)

```python
@dataclass(frozen=True, slots=True)
class AccessPolicyEvaluation:
    """Result of evaluating a single policy against a specific resource."""

    name: str
    description: str
    filter_sql: str                 # compiled SQL fragment
    matched: bool                   # did this policy's filter match the resource?

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AccessExplanation:
    """Explanation of why actor can/can't perform action on resource."""

    actor_repr: str
    action: str
    resource_type: str              # e.g. "Post"
    resource_repr: str              # repr(resource) for display
    allowed: bool                   # overall result (same as can() return)
    deny_by_default: bool           # True if no policies registered
    policies: list[AccessPolicyEvaluation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor_repr,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource": self.resource_repr,
            "allowed": self.allowed,
            "deny_by_default": self.deny_by_default,
            "policies": [p.to_dict() for p in self.policies],
        }

    def __str__(self) -> str:
        verdict = "ALLOWED" if self.allowed else "DENIED"
        lines = [f"AccessExplanation: {self.actor_repr} {self.action} {self.resource_type} -> {verdict}"]
        if self.deny_by_default:
            lines.append("  No policies registered (deny-by-default)")
        for pol in self.policies:
            mark = "PASS" if pol.matched else "FAIL"
            lines.append(f"  [{mark}] {pol.name}: {pol.filter_sql}")
        return "\n".join(lines)
```

---

## Implementation Approach

### Key insight: capture, don't fork

The explain functions do NOT duplicate the compilation logic from
`evaluate_policies()` or `authorize_query()`. Instead they:

1. Call `registry.lookup()` directly (same as `evaluate_policies` does)
2. Call each policy's `fn(actor)` individually to capture per-policy expressions
3. Combine with OR (same as `evaluate_policies`)
4. Compile expressions to SQL strings using `str(expr.compile(compile_kwargs={"literal_binds": True}))`

This is a small amount of code that mirrors the structure of `evaluate_policies`
but captures intermediate results. It does NOT call `evaluate_policies` itself
because that function returns only the final combined expression, losing the
per-policy breakdown.

### File structure

```
src/sqla_authz/explain/
    __init__.py          # public API: explain_query, explain_access, models
    _models.py           # AuthzExplanation, EntityExplanation, etc.
    _query.py            # explain_query()
    _access.py           # explain_access()
```

### `explain_query()` implementation sketch

```python
def explain_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
) -> AuthzExplanation:
    target_registry = registry if registry is not None else get_default_registry()

    entity_explanations: list[EntityExplanation] = []
    authorized_stmt = stmt

    desc_list: list[dict[str, Any]] = stmt.column_descriptions
    for desc in desc_list:
        entity: type | None = desc.get("entity")
        if entity is None:
            continue

        policies = target_registry.lookup(entity, action)

        if not policies:
            # Deny-by-default
            filter_expr = false()
            authorized_stmt = authorized_stmt.where(filter_expr)
            entity_explanations.append(EntityExplanation(
                entity_name=entity.__name__,
                entity_type=f"{entity.__module__}.{entity.__qualname__}",
                action=action,
                policies_found=0,
                policies=[],
                combined_filter_sql=_compile_sql(filter_expr),
                deny_by_default=True,
            ))
            continue

        policy_evals: list[PolicyEvaluation] = []
        filter_exprs: list[ColumnElement[bool]] = []

        for p in policies:
            expr = p.fn(actor)
            filter_exprs.append(expr)
            policy_evals.append(PolicyEvaluation(
                name=p.name,
                description=p.description,
                filter_expression=str(expr),
                filter_sql=_compile_sql(expr),
            ))

        combined = reduce(lambda a, b: a | b, filter_exprs)
        authorized_stmt = authorized_stmt.where(combined)

        entity_explanations.append(EntityExplanation(
            entity_name=entity.__name__,
            entity_type=f"{entity.__module__}.{entity.__qualname__}",
            action=action,
            policies_found=len(policies),
            policies=policy_evals,
            combined_filter_sql=_compile_sql(combined),
            deny_by_default=False,
        ))

    has_deny = any(e.deny_by_default for e in entity_explanations)

    return AuthzExplanation(
        action=action,
        actor_repr=repr(actor),
        entities=entity_explanations,
        authorized_sql=_compile_sql(authorized_stmt),
        has_deny_by_default=has_deny,
    )


def _compile_sql(expr: Any) -> str:
    """Compile a SQLAlchemy expression to SQL with literal binds."""
    return str(expr.compile(compile_kwargs={"literal_binds": True}))
```

### `explain_access()` implementation sketch

```python
def explain_access(
    actor: ActorLike,
    action: str,
    resource: DeclarativeBase,
    *,
    registry: PolicyRegistry | None = None,
) -> AccessExplanation:
    target_registry = registry if registry is not None else get_default_registry()
    resource_type = type(resource)
    policies = target_registry.lookup(resource_type, action)

    if not policies:
        return AccessExplanation(
            actor_repr=repr(actor),
            action=action,
            resource_type=resource_type.__name__,
            resource_repr=repr(resource),
            allowed=False,
            deny_by_default=True,
            policies=[],
        )

    # Build in-memory SQLite for evaluation (same pattern as can())
    engine = create_engine("sqlite:///:memory:")
    resource_type.metadata.create_all(engine)
    mapper = sa_inspect(resource_type)
    table = mapper.local_table
    instance_state = sa_inspect(resource)
    col_values = {}
    for prop in mapper.column_attrs:
        col = prop.columns[0]
        col_values[col.key] = instance_state.attrs[prop.key].loaded_value

    policy_evals: list[AccessPolicyEvaluation] = []
    overall_allowed = False

    with engine.connect() as conn:
        conn.execute(table.insert().values(**col_values))

        for p in policies:
            expr = p.fn(actor)
            check_stmt = select(literal_column("1")).select_from(table).where(expr)
            row = conn.execute(check_stmt).first()
            matched = row is not None
            if matched:
                overall_allowed = True

            policy_evals.append(AccessPolicyEvaluation(
                name=p.name,
                description=p.description,
                filter_sql=_compile_sql(expr),
                matched=matched,
            ))

        conn.rollback()

    engine.dispose()

    return AccessExplanation(
        actor_repr=repr(actor),
        action=action,
        resource_type=resource_type.__name__,
        resource_repr=repr(resource),
        allowed=overall_allowed,
        deny_by_default=False,
        policies=policy_evals,
    )
```

---

## Integration with Existing Audit Logging

The existing `_audit.py` module logs via Python `logging` and is opt-in via
`config.log_policy_decisions`. The explain module does NOT replace this. They
serve different purposes:

| Concern            | `_audit.py`                        | `explain` module                     |
|--------------------|------------------------------------|--------------------------------------|
| Trigger            | Every `evaluate_policies()` call   | Explicit `explain_query()` call      |
| Output             | Python logging (INFO/DEBUG/WARN)   | Structured dataclass                 |
| Use case           | Production audit trail             | Development debugging, API responses |
| Performance cost   | Minimal (string formatting)        | Higher (SQL compilation to strings)  |

### Future: interceptor explain mode

A future enhancement could add an `explain=True` execution option to the
session interceptor. When set, the interceptor would call `explain_query()`
instead of `authorize_query()` and attach the `AuthzExplanation` to the
result via `execution_options` or a context variable. This is explicitly
**out of scope** for the initial implementation to keep it simple and
zero-overhead.

The interceptor integration sketch (for future reference):

```python
# In _apply_authz handler:
if orm_execute_state.execution_options.get("authz_explain", False):
    explanation = explain_query(stmt, actor=actor, action=action_val, registry=target_registry)
    # Attach to execution state for retrieval
    orm_execute_state.execution_options = {
        **orm_execute_state.execution_options,
        "_authz_explanation": explanation,
    }
```

---

## Performance Impact: Zero

The explain module is:
- In a separate subpackage (`sqla_authz/explain/`)
- Never imported by `authorize_query()`, `evaluate_policies()`, or the interceptor
- Only imported when the user explicitly calls `explain_query()` or `explain_access()`

There is no conditional branching, no flag checking, and no data collection on
the hot path. The `authorize_query()` function remains unchanged.

---

## Example Usage and Output

### Query explanation

```python
from sqlalchemy import select
from sqla_authz import explain_query
from myapp.models import Post

stmt = select(Post).where(Post.category == "tech")
explanation = explain_query(stmt, actor=current_user, action="read")

# Structured access
print(explanation.has_deny_by_default)        # False
print(explanation.entities[0].entity_name)    # "Post"
print(explanation.entities[0].policies_found) # 2
for pol in explanation.entities[0].policies:
    print(f"  {pol.name}: {pol.filter_sql}")
print(explanation.authorized_sql)

# Human-readable
print(explanation)
# AuthzExplanation(action='read', actor=User(id=42, role='editor'))
#   Post: 2 policy(ies)
#     - post_read_published: post.is_published = true
#     - post_read_own: post.author_id = 42
#     combined: post.is_published = true OR post.author_id = 42
#   SQL: SELECT post.id, post.title, ... FROM post
#        WHERE post.category = 'tech'
#        AND (post.is_published = true OR post.author_id = 42)

# JSON for API response
import json
print(json.dumps(explanation.to_dict(), indent=2))
```

### Access explanation

```python
from sqla_authz import explain_access

post = session.get(Post, 1)  # a draft post by another author
result = explain_access(current_user, "read", post)

print(result)
# AccessExplanation: User(id=42) read Post -> DENIED
#   [FAIL] post_read_published: post.is_published = true
#   [FAIL] post_read_own: post.author_id = 42

print(result.allowed)        # False
print(result.policies[0].matched)  # False
print(json.dumps(result.to_dict(), indent=2))
```

### Debugging in tests

```python
def test_user_can_read_own_drafts(session, user, draft_post):
    result = explain_access(user, "read", draft_post)
    assert result.allowed, f"Expected access but got:\n{result}"
```

---

## Test Plan

### Unit tests for data models

```
tests/explain/test_models.py
```

- `test_policy_evaluation_to_dict` -- round-trip serialization
- `test_entity_explanation_to_dict` -- nested serialization
- `test_authz_explanation_to_dict` -- full tree serialization
- `test_authz_explanation_str` -- human-readable output format
- `test_access_explanation_to_dict` -- serialization
- `test_access_explanation_str` -- human-readable output format
- `test_frozen_dataclasses` -- immutability

### Unit tests for `explain_query()`

```
tests/explain/test_explain_query.py
```

- `test_single_entity_single_policy` -- basic case
- `test_single_entity_multiple_policies` -- OR combination
- `test_multiple_entities` -- query with joins
- `test_no_policies_deny_by_default` -- entity with no registered policy
- `test_mixed_entities_some_denied` -- one entity has policies, another doesn't
- `test_non_entity_columns_skipped` -- `select(Post.id)` pattern
- `test_custom_registry` -- explicit registry parameter
- `test_compiled_sql_contains_literal_binds` -- no placeholders in output
- `test_authorized_sql_matches_authorize_query` -- ensure explain produces
  the same SQL that `authorize_query()` would produce

### Unit tests for `explain_access()`

```
tests/explain/test_explain_access.py
```

- `test_access_allowed_single_policy` -- policy matches resource
- `test_access_denied_single_policy` -- policy does not match
- `test_access_multiple_policies_one_passes` -- OR semantics (allowed)
- `test_access_multiple_policies_none_pass` -- all fail (denied)
- `test_access_no_policies_deny_by_default` -- no policies registered
- `test_access_result_matches_can` -- `result.allowed == can(...)` for all cases
- `test_per_policy_matched_flags` -- individual policy pass/fail tracking
- `test_custom_registry`

### Integration tests

```
tests/explain/test_explain_integration.py
```

- `test_explain_with_real_session` -- explain + actual query execution, compare results
- `test_explain_serialization_roundtrip` -- `to_dict()` -> JSON -> parse back
- `test_explain_does_not_affect_authorize_query` -- import explain, verify
  `authorize_query` behavior unchanged

---

## Documentation Plan

### API reference (docstrings)

Every public class and function gets full Google-style docstrings with:
- Summary line
- Args/Returns/Raises sections
- Example block

### Guide page

Add a new documentation page `docs/guides/debugging-policies.md` covering:

1. **When to use explain mode** -- zero rows, unexpected filtering, policy auditing
2. **`explain_query()` usage** -- with code examples and sample output
3. **`explain_access()` usage** -- point check debugging
4. **JSON output in API responses** -- pattern for exposing explain data in
   development/staging environments
5. **Comparison with audit logging** -- when to use which

### Changelog entry

```
### Added
- `explain_query()` -- structured explanation of how authorization filters
  are applied to SELECT statements
- `explain_access()` -- structured explanation of why an actor can/can't
  perform an action on a specific resource
- `AuthzExplanation`, `EntityExplanation`, `PolicyEvaluation`,
  `AccessExplanation`, `AccessPolicyEvaluation` dataclasses for
  programmatic access to explain results
```

---

## Implementation Order

1. **`_models.py`** -- dataclasses only, no dependencies on SQLAlchemy internals.
   Can be written and tested immediately.
2. **`_query.py`** (`explain_query`) -- depends on models + registry. Mirror of
   `authorize_query` with capture.
3. **`_access.py`** (`explain_access`) -- depends on models + registry + in-memory
   SQLite pattern from `_checks.py`.
4. **`__init__.py`** -- wire up public API.
5. **Top-level `__init__.py`** -- add `explain_query` and `explain_access` to
   the main package exports.
6. **Tests** -- in order above.
7. **Documentation** -- guide page + changelog.

Estimated scope: ~250 lines of production code, ~400 lines of tests.

---

## Open Questions / Future Work

1. **Dialect-specific SQL output.** The initial implementation compiles SQL
   without a specific dialect (SQLAlchemy default). A future enhancement could
   accept an optional `dialect` or `engine` parameter to produce
   PostgreSQL/MySQL-specific SQL.

2. **Interceptor integration.** The `authz_explain` execution option pattern
   is sketched above but deferred to a follow-up. It requires careful design
   around how to surface the explanation from the event handler back to the
   caller.

3. **Async support.** `explain_access()` uses synchronous in-memory SQLite
   (same as `can()`). This is fine for debugging but a future async variant
   could be considered alongside the broader `can()` rewrite (Plan 01).

4. **Relationship load explanations.** The interceptor applies
   `with_loader_criteria()` for relationship loads. Explaining those is
   significantly more complex and deferred.
