# Plan 06: Advanced Features Roadmap

## Status: DRAFT
## Priority: MEDIUM — differentiation features (post-stabilization)
## Depends On: Plans 01-05 (critical fixes land first)

---

## Executive Summary

Plans 01-05 fix what is broken. This plan builds what makes sqla-authz **indispensable** -- features that justify choosing this library over writing manual WHERE clauses. Each feature deepens the moat of in-process, SQLAlchemy-native, SQL filter generation. The features are ordered by impact-to-effort ratio and designed to build on each other.

---

## 1. Multi-tenancy Support

### Problem

Multi-tenant SaaS applications are the primary audience for row-level authorization. Currently, every policy function must manually include tenant scoping:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return (Post.is_published == True) & (Post.tenant_id == actor.tenant_id)

@policy(Comment, "read")
def comment_read(actor: User) -> ColumnElement[bool]:
    return Comment.tenant_id == actor.tenant_id

@policy(Tag, "read")
def tag_read(actor: User) -> ColumnElement[bool]:
    return Tag.tenant_id == actor.tenant_id
```

This is repetitive, error-prone (forget one model and you have a cross-tenant data leak), and violates DRY. Tenant isolation is a cross-cutting concern that should be declarative, not duplicated across every policy function.

### Proposed Design

#### 1.1 Tenant Configuration

Add first-class tenant support to `AuthzConfig`:

```python
# src/sqla_authz/config/_config.py additions

@dataclass(frozen=True, slots=True)
class TenantConfig:
    """Configuration for automatic tenant isolation.

    Attributes:
        tenant_column: The column name on models that holds the tenant ID.
            Models without this column are treated as shared/global.
        tenant_resolver: A callable returning the current tenant ID.
            Called once per query execution (same pattern as actor_provider).
        shared_models: Set of model classes that are NOT tenant-scoped
            (e.g., lookup tables, system config). These skip tenant filtering.
        shared_row_filter: Optional callable that returns a filter expression
            for rows that should be visible to ALL tenants regardless of
            tenant_id. Used for "global" rows within a tenant-scoped table.
    """
    tenant_column: str = "tenant_id"
    tenant_resolver: Callable[[], int | str] | None = None
    shared_models: frozenset[type] = frozenset()
    shared_row_filter: Callable[[type], ColumnElement[bool]] | None = None
```

#### 1.2 Configure API

```python
from sqla_authz import configure

configure(
    tenant=TenantConfig(
        tenant_column="tenant_id",
        tenant_resolver=lambda: get_current_tenant(),
        shared_models=frozenset({SystemConfig, LookupTable}),
        shared_row_filter=lambda model: getattr(model, "is_global", None) == True,
    ),
)
```

#### 1.3 Interceptor Integration

The interceptor (`src/sqla_authz/session/_interceptor.py`) applies tenant filtering as a **pre-policy** step -- before any user-defined policies are evaluated:

```python
# In _apply_authz, after the skip checks and before policy evaluation:

def _apply_tenant_filter(
    stmt: Select[Any],
    entity: type,
    tenant_config: TenantConfig,
) -> Select[Any]:
    """Apply automatic tenant isolation to a query entity."""
    if tenant_config.tenant_resolver is None:
        return stmt  # tenant filtering not configured

    if entity in tenant_config.shared_models:
        return stmt  # explicitly shared model

    # Check if the model has the tenant column
    mapper = sa_inspect(entity)
    tenant_col = None
    for prop in mapper.column_attrs:
        if prop.columns[0].key == tenant_config.tenant_column:
            tenant_col = getattr(entity, prop.key)
            break

    if tenant_col is None:
        return stmt  # model has no tenant column, treat as shared

    tenant_id = tenant_config.tenant_resolver()
    tenant_filter = tenant_col == tenant_id

    # Apply shared row filter if configured
    if tenant_config.shared_row_filter is not None:
        shared_expr = tenant_config.shared_row_filter(entity)
        if shared_expr is not None:
            tenant_filter = tenant_filter | shared_expr

    return stmt.where(tenant_filter)
```

#### 1.4 Interaction with User Policies

Tenant filtering and user policies compose via AND:

```
Final WHERE = (tenant_id = :current_tenant OR is_global = true)
              AND (user_policy_filter)
```

This means tenant isolation is **always enforced** even if a user policy is overly permissive. A user-defined policy cannot accidentally grant cross-tenant access because the tenant filter is applied independently.

#### 1.5 Tenant-Aware `@policy` Decorator

For policies that need to reference the current tenant (beyond simple column equality), provide the tenant ID via the actor or a context variable:

```python
# Option A: Enrich the actor with tenant info (recommended)
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True
    # Tenant filtering is automatic -- no need to add Post.tenant_id == actor.tenant_id

# Option B: For cross-tenant queries (admin dashboards), opt out:
stmt = select(Post).execution_options(skip_tenant=True)
```

#### 1.6 `skip_tenant` Escape Hatch

Add `skip_tenant` execution option (parallel to `skip_authz`):

```python
# In _apply_authz:
if orm_execute_state.execution_options.get("skip_tenant", False):
    # Skip tenant filtering but still apply user policies
    ...
```

This allows admin dashboards or background jobs to query across tenants while still respecting row-level policies.

### Implementation Steps

1. Add `TenantConfig` dataclass to `src/sqla_authz/config/_config.py`
2. Add `tenant` field to `AuthzConfig` (type: `TenantConfig | None = None`)
3. Update `configure()` and `merge()` to accept tenant config
4. Create `src/sqla_authz/session/_tenant.py` with `_apply_tenant_filter()` function
5. Modify `_apply_authz` in `src/sqla_authz/session/_interceptor.py` to call `_apply_tenant_filter()` before policy evaluation for each entity
6. Add `skip_tenant` execution option handling
7. Add `with_loader_criteria` tenant filter for relationship loads (same pattern as existing policy loader criteria)
8. Update `__init__.py` to export `TenantConfig`
9. Write tests in `tests/test_session/test_tenant.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_tenant_filter_applied` | Queries return only current tenant's rows |
| `test_cross_tenant_denied` | Rows from other tenants are invisible |
| `test_shared_model_no_filter` | Models in `shared_models` are unfiltered |
| `test_no_tenant_column_unfiltered` | Models without `tenant_id` column are unfiltered |
| `test_shared_row_filter` | Global rows (e.g., `is_global=True`) visible to all tenants |
| `test_skip_tenant_option` | `skip_tenant=True` bypasses tenant filtering |
| `test_tenant_plus_policy_compose` | Tenant AND policy filters compose correctly |
| `test_relationship_loads_filtered` | Eager/lazy loaded relationships respect tenant isolation |
| `test_no_tenant_config_noop` | No tenant config = no tenant filtering (backward compat) |
| `test_tenant_resolver_called_per_query` | Resolver is called each execution, not cached |

### Migration / Backwards Compatibility

- **Zero breaking changes.** `TenantConfig` defaults to `None` (disabled). Existing code is unaffected.
- **Additive API.** `configure(tenant=TenantConfig(...))` is opt-in.
- Users currently manually adding tenant filters in policies can remove them after enabling tenant config.

### Estimated Complexity: **M** (~300 LOC production, ~200 LOC tests)

---

## 2. Policy Composition & Inheritance

### Problem

The current policy model is flat: multiple `@policy` decorators for the same `(model, action)` pair are OR'd together. There is no support for:

1. **Hierarchical policies** -- org-level rules that apply to all models, overridden by team-level or user-level rules.
2. **Role hierarchies** -- `admin` inherits all `manager` permissions, which inherits all `viewer` permissions.
3. **AND composition** -- requiring multiple conditions to all pass (e.g., "must be in the same org AND must have editor role").
4. **Priority/conflict resolution** -- when two policies conflict, which wins?

These limitations force users to encode all composition logic inside individual policy functions, leading to complex, hard-to-test functions.

### Proposed Design

#### 2.1 Registry Inheritance (Parent-Child Registries)

Add a `parent` parameter to `PolicyRegistry`:

```python
# src/sqla_authz/policy/_registry.py modifications

class PolicyRegistry:
    def __init__(self, *, parent: PolicyRegistry | None = None) -> None:
        self._policies: dict[tuple[type, str], list[PolicyRegistration]] = {}
        self._parent = parent

    def lookup(self, resource_type: type, action: str) -> list[PolicyRegistration]:
        """Look up policies, falling back to parent if no local policies exist."""
        local = list(self._policies.get((resource_type, action), []))
        if local:
            return local
        if self._parent is not None:
            return self._parent.lookup(resource_type, action)
        return []

    def fork(self) -> PolicyRegistry:
        """Create a child registry that inherits from this one.

        The child sees all parent policies but can override them
        by registering policies for the same (model, action) key.
        Local policies completely replace parent policies for a key.
        """
        return PolicyRegistry(parent=self)
```

**Inheritance semantics**: Child **overrides** parent completely for a given `(model, action)` key. No merging. If the child has zero policies for a key, it falls through to the parent. This is simple and predictable -- no surprising interaction between parent and child policies.

**Use case: multi-tenant policy isolation:**

```python
base_registry = PolicyRegistry()

@policy(Post, "read", registry=base_registry)
def public_post_read(actor):
    return Post.is_published == True

# Per-tenant override:
tenant_a_registry = base_registry.fork()

@policy(Post, "read", registry=tenant_a_registry)
def tenant_a_post_read(actor):
    # Tenant A has a more permissive read policy
    return Post.is_published == True | (Post.author_id == actor.id)
```

#### 2.2 Role Hierarchy

Provide a `RoleHierarchy` helper that expands a role into its implied roles:

```python
# New file: src/sqla_authz/policy/_roles.py

from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class RoleHierarchy:
    """Defines a role inheritance chain.

    Higher roles inherit all permissions of lower roles.
    Roles are ordered from most privileged to least privileged.

    Example::

        roles = RoleHierarchy(["admin", "manager", "editor", "viewer"])
        roles.implies("manager")  # {"manager", "editor", "viewer"}
        roles.implies("admin")    # {"admin", "manager", "editor", "viewer"}
        roles.implies("viewer")   # {"viewer"}
    """
    _levels: list[str]
    _index: dict[str, int] = field(init=False)

    def __post_init__(self) -> None:
        self._index = {role: i for i, role in enumerate(self._levels)}

    def implies(self, role: str) -> frozenset[str]:
        """Return the set of roles implied by the given role (including itself)."""
        if role not in self._index:
            return frozenset({role})
        level = self._index[role]
        return frozenset(self._levels[level:])

    def has_at_least(self, actor_role: str, required_role: str) -> bool:
        """Check if actor_role is at or above required_role in the hierarchy."""
        if actor_role not in self._index or required_role not in self._index:
            return False
        return self._index[actor_role] <= self._index[required_role]
```

**Usage in policies:**

```python
roles = RoleHierarchy(["admin", "manager", "editor", "viewer"])

@policy(Post, "update")
def post_update(actor: User) -> ColumnElement[bool]:
    if roles.has_at_least(actor.role, "editor"):
        return Post.author_id == actor.id
    if roles.has_at_least(actor.role, "admin"):
        return true()
    return false()
```

The `RoleHierarchy` is a pure Python helper -- it does not modify the policy system. It simply makes role checks readable and consistent.

#### 2.3 AND Composition via `@policy` with `compose` Parameter

Currently, multiple policies for the same `(model, action)` are always OR'd. Add an optional `compose` parameter:

```python
# src/sqla_authz/policy/_decorator.py modifications

def policy(
    resource_type: type,
    action: str,
    *,
    predicate: Predicate | None = None,
    registry: PolicyRegistry | None = None,
    compose: Literal["or", "and"] = "or",  # NEW
) -> Callable[[F], F]:
```

**Storage**: Add a `compose` field to `PolicyRegistration`:

```python
# src/sqla_authz/policy/_base.py modifications

@dataclass(frozen=True, slots=True)
class PolicyRegistration:
    resource_type: type
    action: str
    fn: Callable[..., ColumnElement[bool]]
    name: str
    description: str
    compose: str = "or"  # NEW: "or" or "and"
```

**Evaluation change** in `src/sqla_authz/compiler/_expression.py`:

```python
def evaluate_policies(
    registry: PolicyRegistry,
    resource_type: type,
    action: str,
    actor: ActorLike,
) -> ColumnElement[bool]:
    policies = registry.lookup(resource_type, action)

    if not policies:
        # ... existing deny-by-default logic ...
        return false()

    # Separate AND and OR policies
    or_filters: list[ColumnElement[bool]] = []
    and_filters: list[ColumnElement[bool]] = []

    for p in policies:
        expr = p.fn(actor)
        if p.compose == "and":
            and_filters.append(expr)
        else:
            or_filters.append(expr)

    # Build: (or_policy_1 OR or_policy_2 ...) AND and_policy_1 AND and_policy_2 ...
    parts: list[ColumnElement[bool]] = []

    if or_filters:
        parts.append(reduce(lambda a, b: a | b, or_filters))

    parts.extend(and_filters)

    if not parts:
        return false()

    return reduce(lambda a, b: a & b, parts)
```

**Semantics**: OR policies grant access (any one is sufficient). AND policies restrict access (all must pass). The combined expression is:

```
(any OR policy passes) AND (all AND policies pass)
```

**Use case**: Tenant isolation as an AND policy, business rules as OR policies:

```python
@policy(Post, "read", compose="and")
def same_org(actor: User) -> ColumnElement[bool]:
    """AND: must be in the same org (always required)."""
    return Post.org_id == actor.org_id

@policy(Post, "read")  # compose="or" (default)
def published(actor: User) -> ColumnElement[bool]:
    """OR: published posts are readable."""
    return Post.is_published == True

@policy(Post, "read")  # compose="or" (default)
def own_post(actor: User) -> ColumnElement[bool]:
    """OR: authors can read their own posts."""
    return Post.author_id == actor.id

# Result: (published OR own_post) AND same_org
```

#### 2.4 Priority for Conflict Resolution

Add an optional `priority` parameter (integer, default 0) to `@policy`. Higher priority policies are evaluated first. When policies at different priority levels conflict, the highest-priority result wins.

**Decision: Defer priority to v1.0.** The AND/OR composition model handles most conflict scenarios. True priority-based override (where a high-priority DENY overrides a lower-priority ALLOW) requires a fundamentally different evaluation model (deny-override vs allow-override) that adds significant complexity. For now, AND composition provides the "always restrict" pattern, and OR composition provides the "any grants" pattern.

### Implementation Steps

1. Add `parent` parameter to `PolicyRegistry.__init__()` in `src/sqla_authz/policy/_registry.py`
2. Modify `PolicyRegistry.lookup()` to fall back to parent
3. Add `PolicyRegistry.fork()` method
4. Add `compose` field to `PolicyRegistration` in `src/sqla_authz/policy/_base.py`
5. Add `compose` parameter to `@policy` decorator in `src/sqla_authz/policy/_decorator.py`
6. Modify `evaluate_policies()` in `src/sqla_authz/compiler/_expression.py` to handle AND/OR grouping
7. Create `src/sqla_authz/policy/_roles.py` with `RoleHierarchy`
8. Update `policy/__init__.py` and `__init__.py` exports
9. Write tests in `tests/test_policy/test_composition.py` and `tests/test_policy/test_roles.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_parent_registry_fallback` | Child with no local policy delegates to parent |
| `test_child_overrides_parent` | Local policy replaces parent for same key |
| `test_fork_creates_child` | `fork()` returns a registry with the parent set |
| `test_deep_inheritance_chain` | grandchild -> child -> parent lookup works |
| `test_and_composition_all_pass` | AND policies: all pass = granted |
| `test_and_composition_one_fails` | AND policies: one fails = denied |
| `test_or_and_mixed` | `(OR_a \| OR_b) & AND_c` produces correct SQL |
| `test_all_and_policies` | Only AND policies: all must pass |
| `test_all_or_policies` | Only OR policies: existing behavior unchanged |
| `test_role_hierarchy_implies` | `admin` implies all lower roles |
| `test_role_hierarchy_has_at_least` | Level comparison works correctly |
| `test_role_hierarchy_unknown_role` | Unknown roles handled gracefully |
| `test_backward_compat_no_compose` | Existing policies without `compose` default to OR |

### Migration / Backwards Compatibility

- **Zero breaking changes.** `parent=None` and `compose="or"` are defaults. Existing code produces identical behavior.
- `PolicyRegistration` gains a `compose` field with default `"or"` -- frozen dataclass, so existing code constructing it without the field will use the default.
- `PolicyRegistry` gains `parent` and `fork()` -- additive, no existing behavior changes.

### Estimated Complexity: **M** (~350 LOC production, ~250 LOC tests)

---

## 3. Field-Level Authorization

### Problem

Row-level authorization answers "can this user see this row?" Field-level authorization answers "can this user see this column?" This is critical for:

- **HR/Payroll**: Non-HR users should not see `salary`, `ssn`, `bank_account`
- **PII compliance**: GDPR requires restricting access to personal data fields
- **API responses**: Different API consumers need different field visibility
- **Internal tools**: Support staff sees different columns than engineering

Currently, field masking must be implemented in the application layer (serializers, view models), which is error-prone and disconnected from the authorization system.

### Proposed Design

#### 3.1 `@field_policy` Decorator

```python
# New file: src/sqla_authz/policy/_field_decorator.py

def field_policy(
    resource_type: type,
    columns: str | list[str],
    action: str = "read",
    *,
    registry: PolicyRegistry | None = None,
) -> Callable[[F], F]:
    """Register a field-level policy that controls column visibility.

    The decorated function receives an actor and returns a Python bool
    (not a ColumnElement). If False, the specified columns are deferred
    (not loaded) for this query.

    Args:
        resource_type: The SQLAlchemy model class.
        columns: Column name(s) to protect.
        action: The action string.
        registry: Optional custom registry.

    Example::

        @field_policy(Employee, ["salary", "ssn"])
        def hr_only_fields(actor: User) -> bool:
            return actor.role == "hr"

        # Non-HR users: salary and ssn columns are deferred (not loaded)
        # HR users: all columns loaded normally
    """
```

**Key design decision**: Field policies return `bool`, not `ColumnElement[bool]`. This is because column visibility is a structural query decision (which columns to SELECT), not a row filter (WHERE clause). The decision must be made before the query executes, so it evaluates against the Python actor object, not against SQL expressions.

#### 3.2 Field Policy Registration

```python
# New file: src/sqla_authz/policy/_field_base.py

@dataclass(frozen=True, slots=True)
class FieldPolicyRegistration:
    """A registered field-level policy."""
    resource_type: type
    columns: tuple[str, ...]
    action: str
    fn: Callable[..., bool]  # Returns bool, not ColumnElement
    name: str
    description: str
```

Add field policy storage to `PolicyRegistry`:

```python
class PolicyRegistry:
    def __init__(self, *, parent: PolicyRegistry | None = None) -> None:
        self._policies: dict[tuple[type, str], list[PolicyRegistration]] = {}
        self._field_policies: dict[tuple[type, str], list[FieldPolicyRegistration]] = {}
        self._parent = parent

    def register_field_policy(
        self,
        resource_type: type,
        columns: tuple[str, ...],
        action: str,
        fn: Callable[..., bool],
        *,
        name: str,
        description: str,
    ) -> None:
        """Register a field-level policy."""
        ...

    def lookup_field_policies(
        self, resource_type: type, action: str,
    ) -> list[FieldPolicyRegistration]:
        """Look up field policies, with parent fallback."""
        ...
```

#### 3.3 Interceptor Integration via `defer()`

The interceptor applies field policies using SQLAlchemy's `defer()` option:

```python
# In _apply_authz, after row-level policy application:

from sqlalchemy.orm import defer

field_policies = target_registry.lookup_field_policies(entity, action_val)
for fp in field_policies:
    if not fp.fn(actor):  # Actor does NOT have access to these columns
        for col_name in fp.columns:
            col_attr = getattr(entity, col_name, None)
            if col_attr is not None:
                stmt = stmt.options(defer(col_attr))
```

#### 3.4 Deferred Column Access Behavior

When a non-authorized user accesses a deferred column on a loaded instance:

**Default behavior (SQLAlchemy default)**: Accessing the attribute triggers a lazy load, which loads the column value. This defeats the purpose of field-level authorization.

**Secure behavior**: Override the lazy load by configuring a `raiseload` for unauthorized columns:

```python
from sqlalchemy.orm import defer
from sqlalchemy.orm.strategy_options import _DeferredOption

# Use defer with raiseload to prevent lazy loading of unauthorized columns
stmt = stmt.options(defer(col_attr, raiseload=True))
```

When `raiseload=True`, accessing the deferred column raises `sqlalchemy.exc.InvalidRequestError`. This is the safe default -- it prevents accidental data leakage through lazy loading.

**Alternative: Return None/sentinel**: A custom descriptor on the model could return `None` instead of raising. This is configurable:

```python
# src/sqla_authz/config/_config.py addition
class AuthzConfig:
    field_policy_on_access: str = "raise"  # "raise" | "none" | "lazy"
    # "raise": raiseload, accessing raises an error
    # "none": return None for deferred unauthorized columns
    # "lazy": allow lazy load (no protection, just initial query optimization)
```

#### 3.5 Integration with `can()` / `authorize()`

For point checks, field policies are informational -- `can()` checks row-level access, not field-level. Add a separate helper:

```python
# src/sqla_authz/_checks.py addition

def visible_fields(
    actor: ActorLike,
    resource_type: type,
    action: str = "read",
    *,
    registry: PolicyRegistry | None = None,
) -> set[str]:
    """Return the set of column names visible to the actor.

    Evaluates all field policies and returns the columns that the
    actor is authorized to see.
    """
    target_registry = registry if registry is not None else get_default_registry()
    mapper = sa_inspect(resource_type)
    all_columns = {prop.key for prop in mapper.column_attrs}

    restricted: set[str] = set()
    for fp in target_registry.lookup_field_policies(resource_type, action):
        if not fp.fn(actor):
            restricted.update(fp.columns)

    return all_columns - restricted
```

**Usage in API serialization:**

```python
fields = visible_fields(current_user, Employee, "read")
# {"id", "name", "department", "email"}  -- salary, ssn excluded

# Use in Pydantic serialization:
employee_dict = {k: v for k, v in employee.__dict__.items() if k in fields}
```

### Implementation Steps

1. Create `src/sqla_authz/policy/_field_base.py` with `FieldPolicyRegistration`
2. Create `src/sqla_authz/policy/_field_decorator.py` with `@field_policy`
3. Add `_field_policies` storage and `register_field_policy()`/`lookup_field_policies()` to `PolicyRegistry` in `src/sqla_authz/policy/_registry.py`
4. Add field policy application to `_apply_authz` in `src/sqla_authz/session/_interceptor.py`
5. Add `field_policy_on_access` config to `AuthzConfig` in `src/sqla_authz/config/_config.py`
6. Add `visible_fields()` to `src/sqla_authz/_checks.py`
7. Update `__init__.py` exports: `field_policy`, `visible_fields`, `FieldPolicyRegistration`
8. Write tests in `tests/test_policy/test_field_policy.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_field_policy_defers_columns` | Unauthorized columns are deferred in query |
| `test_field_policy_authorized_loads_all` | Authorized actor loads all columns |
| `test_field_policy_raiseload` | Accessing deferred column raises error |
| `test_field_policy_multiple_columns` | Single policy can protect multiple columns |
| `test_field_policy_multiple_policies` | Multiple field policies on same model compose (union of restrictions) |
| `test_field_policy_plus_row_policy` | Field and row policies compose independently |
| `test_visible_fields_returns_correct_set` | `visible_fields()` returns authorized column names |
| `test_visible_fields_no_field_policies` | Returns all columns when no field policies registered |
| `test_field_policy_with_relationship_loads` | Deferred columns on eagerly loaded relationships |
| `test_field_policy_backward_compat` | No field policies = all columns loaded (existing behavior) |

### Migration / Backwards Compatibility

- **Zero breaking changes.** Field policies are additive. No existing APIs change.
- `PolicyRegistry` gains new methods (`register_field_policy`, `lookup_field_policies`) -- additive.
- No existing query behavior changes unless `@field_policy` is registered.

### Estimated Complexity: **L** (~500 LOC production, ~300 LOC tests)

---

## 4. Audit Trail Integration

### Problem

The current `_audit.py` module (73 LOC) provides basic Python `logging`-based audit:
- INFO: Summary of policy evaluation (entity, action, policy count)
- DEBUG: Which policies matched, filter expression
- WARNING: No policy found (deny-by-default)

This is adequate for development but insufficient for production audit requirements:

1. **Not structured** -- log messages are formatted strings, not queryable data
2. **Not persistent** -- logs are ephemeral, depend on log infrastructure
3. **Not compliant** -- SOC2/HIPAA require demonstrable access control audit trails with specific fields (who, what, when, which policy, decision)
4. **No write audit** -- only covers read queries, not point checks or write operations
5. **Not programmatically accessible** -- cannot query "who accessed Employee.salary in the last 30 days?"

### Proposed Design

#### 4.1 Structured Audit Events

```python
# New file: src/sqla_authz/audit/_events.py

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

@dataclass(frozen=True, slots=True)
class AuthzAuditEvent:
    """Structured audit event for an authorization decision.

    Designed for compliance-ready logging (SOC2, HIPAA patterns).
    All fields are serializable to JSON.
    """
    timestamp: str                          # ISO 8601 UTC
    event_type: str                         # "query_filter" | "point_check" | "write_filter"
    actor_id: int | str
    actor_repr: str
    resource_type: str                      # Model class name
    action: str
    decision: Literal["grant", "deny"]
    policies_evaluated: tuple[str, ...]     # Policy names that were evaluated
    policies_matched: tuple[str, ...]       # Policy names that matched (granted)
    sql_fragment: str | None                # Compiled WHERE clause (optional)
    context: dict[str, Any]                 # User-provided context (request ID, IP, etc.)
    duration_us: int                        # Evaluation time in microseconds

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON encoding."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_repr": self.actor_repr,
            "resource_type": self.resource_type,
            "action": self.action,
            "decision": self.decision,
            "policies_evaluated": list(self.policies_evaluated),
            "policies_matched": list(self.policies_matched),
            "sql_fragment": self.sql_fragment,
            "context": self.context,
            "duration_us": self.duration_us,
        }
```

#### 4.2 Pluggable Audit Handlers

```python
# New file: src/sqla_authz/audit/_handlers.py

from __future__ import annotations
from typing import Protocol

class AuditHandler(Protocol):
    """Protocol for audit event handlers."""
    def handle(self, event: AuthzAuditEvent) -> None: ...


class LoggingAuditHandler:
    """Audit handler that logs events via Python logging (default).

    Replaces the current _audit.py behavior with structured fields.
    """
    def __init__(self, logger_name: str = "sqla_authz.audit") -> None:
        self._logger = logging.getLogger(logger_name)

    def handle(self, event: AuthzAuditEvent) -> None:
        self._logger.info(
            "authz.%s actor=%s resource=%s action=%s decision=%s policies=%s duration=%dus",
            event.event_type,
            event.actor_id,
            event.resource_type,
            event.action,
            event.decision,
            ",".join(event.policies_evaluated),
            event.duration_us,
        )


class CallbackAuditHandler:
    """Audit handler that calls a user-provided function.

    Useful for custom integrations (webhooks, message queues, etc.).
    """
    def __init__(self, callback: Callable[[AuthzAuditEvent], None]) -> None:
        self._callback = callback

    def handle(self, event: AuthzAuditEvent) -> None:
        self._callback(event)


class DatabaseAuditHandler:
    """Audit handler that stores events in a SQLAlchemy table.

    Creates an audit_events table and inserts events. Uses a
    SEPARATE engine/session from the application to avoid
    circular authorization issues (auditing the audit query).
    """
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._table = self._ensure_table()

    def _ensure_table(self) -> Table:
        """Create the audit table if it doesn't exist."""
        metadata = MetaData()
        table = Table(
            "sqla_authz_audit_events",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("timestamp", String, nullable=False),
            Column("event_type", String(50), nullable=False),
            Column("actor_id", String(255), nullable=False),
            Column("resource_type", String(255), nullable=False),
            Column("action", String(100), nullable=False),
            Column("decision", String(10), nullable=False),
            Column("policies_evaluated", Text),  # JSON array
            Column("policies_matched", Text),     # JSON array
            Column("sql_fragment", Text),
            Column("context", Text),              # JSON object
            Column("duration_us", Integer),
        )
        metadata.create_all(self._engine)
        return table

    def handle(self, event: AuthzAuditEvent) -> None:
        with self._engine.connect() as conn:
            conn.execute(self._table.insert().values(**event.to_dict()))
            conn.commit()
```

#### 4.3 Audit Dispatcher

```python
# New file: src/sqla_authz/audit/_dispatcher.py

class AuditDispatcher:
    """Central dispatcher for audit events.

    Registered on the config. Handlers are called synchronously
    in registration order.
    """
    def __init__(self) -> None:
        self._handlers: list[AuditHandler] = []

    def add_handler(self, handler: AuditHandler) -> None:
        self._handlers.append(handler)

    def dispatch(self, event: AuthzAuditEvent) -> None:
        for handler in self._handlers:
            try:
                handler.handle(event)
            except Exception:
                # Audit failures must never break authorization
                logging.getLogger("sqla_authz.audit").exception(
                    "Audit handler %r failed for event %s",
                    handler, event.event_type,
                )
```

#### 4.4 Integration with Config

```python
# src/sqla_authz/config/_config.py additions

@dataclass(frozen=True, slots=True)
class AuthzConfig:
    # ... existing fields ...
    audit_dispatcher: AuditDispatcher | None = None
    audit_context_provider: Callable[[], dict[str, Any]] | None = None
    # audit_context_provider returns per-request context (request_id, IP, etc.)
```

#### 4.5 Integration Points

Events are emitted from:

1. **`evaluate_policies()`** in `src/sqla_authz/compiler/_expression.py` -- for query filtering
2. **`can()` / `authorize()`** in `src/sqla_authz/_checks.py` -- for point checks
3. **Write interceptor** (from section 3.3 of existing plan) -- for UPDATE/DELETE decisions

Each integration point wraps its core logic with timing and event emission:

```python
# In evaluate_policies:
if config.audit_dispatcher is not None:
    start = time.perf_counter_ns()
    # ... evaluate ...
    duration_us = (time.perf_counter_ns() - start) // 1000
    context = config.audit_context_provider() if config.audit_context_provider else {}
    event = AuthzAuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="query_filter",
        actor_id=actor.id,
        actor_repr=repr(actor),
        resource_type=resource_type.__name__,
        action=action,
        decision="grant" if policies else "deny",
        policies_evaluated=tuple(p.name for p in policies),
        policies_matched=tuple(p.name for p in policies),  # all matched (OR semantics)
        sql_fragment=str(result) if config.log_policy_decisions else None,
        context=context,
        duration_us=duration_us,
    )
    config.audit_dispatcher.dispatch(event)
```

**Performance guard**: Audit event construction and dispatch only occur when `audit_dispatcher is not None`. The hot path (no audit configured) pays zero cost -- a single `is not None` check.

### Implementation Steps

1. Create `src/sqla_authz/audit/` package with `__init__.py`
2. Create `src/sqla_authz/audit/_events.py` with `AuthzAuditEvent`
3. Create `src/sqla_authz/audit/_handlers.py` with `LoggingAuditHandler`, `CallbackAuditHandler`, `DatabaseAuditHandler`
4. Create `src/sqla_authz/audit/_dispatcher.py` with `AuditDispatcher`
5. Add `audit_dispatcher` and `audit_context_provider` fields to `AuthzConfig`
6. Integrate event emission into `evaluate_policies()` in `src/sqla_authz/compiler/_expression.py`
7. Integrate event emission into `can()` in `src/sqla_authz/_checks.py`
8. Deprecate existing `log_policy_evaluation()` in `src/sqla_authz/_audit.py` (replaced by `LoggingAuditHandler`)
9. Update `__init__.py` exports
10. Write tests in `tests/test_audit/test_events.py`, `tests/test_audit/test_handlers.py`, `tests/test_audit/test_dispatcher.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_audit_event_to_dict_roundtrip` | Serialization produces valid JSON-serializable dict |
| `test_logging_handler_emits_structured_log` | LoggingAuditHandler produces expected log output |
| `test_callback_handler_invoked` | CallbackAuditHandler calls the user function |
| `test_database_handler_inserts_row` | DatabaseAuditHandler writes to the audit table |
| `test_database_handler_creates_table` | Table auto-created if not exists |
| `test_dispatcher_calls_all_handlers` | Multiple handlers all receive the event |
| `test_dispatcher_handler_failure_isolated` | One handler failing does not break others |
| `test_audit_on_evaluate_policies` | Event emitted during query authorization |
| `test_audit_on_can_check` | Event emitted during point check |
| `test_no_audit_zero_overhead` | No dispatcher configured = no timing/allocation |
| `test_audit_context_provider` | Request context included in events |
| `test_audit_event_duration_measured` | `duration_us` is populated and reasonable |

### Migration / Backwards Compatibility

- **Zero breaking changes.** `audit_dispatcher=None` by default. Existing `log_policy_decisions=True` continues to work via the existing `_audit.py` logger.
- The `LoggingAuditHandler` replaces `log_policy_evaluation()` functionally but the old function remains available (deprecated, not removed).
- Users can migrate from `log_policy_decisions=True` to `audit_dispatcher=AuditDispatcher()` with a `LoggingAuditHandler` for identical behavior plus structured data.

### Estimated Complexity: **M** (~400 LOC production, ~300 LOC tests)

---

## 5. Policy Testing & Simulation Tools

### Problem

Testing authorization policies currently requires:
1. Setting up a database (SQLite in-memory at minimum)
2. Creating ORM model instances with valid relationships
3. Running actual queries to verify filter behavior
4. No way to generate a "coverage matrix" of (model x action x role) combinations
5. No way to compare policy behavior across code changes (regression detection)

Users need fast, database-free tools to verify policy correctness, detect regressions, and understand policy coverage.

### Proposed Design

#### 5.1 `policy_matrix()` -- Coverage Matrix

```python
# New file: src/sqla_authz/testing/_matrix.py

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True, slots=True)
class PolicyCoverage:
    """Coverage entry for a single (model, action) pair."""
    resource_type: str
    action: str
    policy_count: int
    policy_names: tuple[str, ...]
    has_field_policies: bool

@dataclass
class PolicyMatrix:
    """Full coverage matrix for a registry."""
    entries: list[PolicyCoverage] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """Human-readable coverage table."""
        lines = ["Model           | Action  | Policies | Names"]
        lines.append("-" * 60)
        for e in sorted(self.entries, key=lambda x: (x.resource_type, x.action)):
            names = ", ".join(e.policy_names) if e.policy_names else "(none)"
            lines.append(
                f"{e.resource_type:<15} | {e.action:<7} | {e.policy_count:<8} | {names}"
            )
        return "\n".join(lines)

    @property
    def uncovered(self) -> list[PolicyCoverage]:
        """Return entries with zero policies (gaps)."""
        return [e for e in self.entries if e.policy_count == 0]


def policy_matrix(
    registry: PolicyRegistry,
    *,
    models: list[type] | None = None,
    actions: list[str] | None = None,
) -> PolicyMatrix:
    """Generate a coverage matrix showing which (model, action) pairs have policies.

    If models or actions are not provided, they are inferred from the
    registry's registered policies.

    Args:
        registry: The policy registry to analyze.
        models: Optional explicit list of models to check. If None,
            uses all models found in the registry.
        actions: Optional explicit list of actions to check. If None,
            uses all actions found in the registry.

    Returns:
        A PolicyMatrix with one entry per (model, action) combination.

    Example::

        matrix = policy_matrix(registry, actions=["read", "update", "delete"])
        print(matrix.summary)
        assert len(matrix.uncovered) == 0, f"Uncovered: {matrix.uncovered}"
    """
    if models is None:
        models = list({rt for rt, _ in registry._policies.keys()})
    if actions is None:
        actions = list({act for _, act in registry._policies.keys()})

    entries = []
    for model in models:
        for action in actions:
            policies = registry.lookup(model, action)
            entries.append(PolicyCoverage(
                resource_type=model.__name__,
                action=action,
                policy_count=len(policies),
                policy_names=tuple(p.name for p in policies),
                has_field_policies=bool(
                    registry.lookup_field_policies(model, action)
                ) if hasattr(registry, 'lookup_field_policies') else False,
            ))

    return PolicyMatrix(entries=entries)
```

#### 5.2 `simulate_query()` -- SQL Preview Without Execution

```python
# New file: src/sqla_authz/testing/_simulate.py

def simulate_query(
    stmt: Select[Any],
    *,
    actor: ActorLike,
    action: str,
    registry: PolicyRegistry | None = None,
    dialect: str | None = None,
) -> SimulationResult:
    """Show the SQL that would be produced by authorize_query, without executing.

    Args:
        stmt: The SELECT statement to authorize.
        actor: The actor to simulate as.
        action: The action string.
        registry: Optional custom registry.
        dialect: Optional SQL dialect name ("postgresql", "mysql", "sqlite").
            If None, uses SQLAlchemy's default dialect.

    Returns:
        A SimulationResult containing the authorized SQL and metadata.

    Example::

        result = simulate_query(
            select(Post).where(Post.category == "tech"),
            actor=MockActor(id=42, role="editor"),
            action="read",
            registry=registry,
        )
        print(result.sql)
        # SELECT post.id, ... FROM post
        # WHERE post.category = 'tech'
        # AND (post.is_published = true OR post.author_id = 42)
    """
    target_registry = registry if registry is not None else get_default_registry()
    authorized_stmt = authorize_query(
        stmt, actor=actor, action=action, registry=target_registry,
    )

    compile_kwargs: dict[str, Any] = {"literal_binds": True}
    if dialect is not None:
        from sqlalchemy import create_engine
        engine = create_engine(f"{dialect}://", strategy="mock", executor=lambda *a, **kw: None)
        compiled = authorized_stmt.compile(dialect=engine.dialect, compile_kwargs=compile_kwargs)
    else:
        compiled = authorized_stmt.compile(compile_kwargs=compile_kwargs)

    return SimulationResult(
        original_sql=str(stmt.compile(compile_kwargs=compile_kwargs)),
        authorized_sql=str(compiled),
        actor_repr=repr(actor),
        action=action,
        policies_applied=_extract_applied_policies(target_registry, stmt, action),
    )


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """Result of a query simulation."""
    original_sql: str
    authorized_sql: str
    actor_repr: str
    action: str
    policies_applied: dict[str, list[str]]  # {entity_name: [policy_names]}

    def __str__(self) -> str:
        lines = [f"Simulation(actor={self.actor_repr}, action={self.action!r})"]
        lines.append(f"  Original:   {self.original_sql}")
        lines.append(f"  Authorized: {self.authorized_sql}")
        for entity, policies in self.policies_applied.items():
            lines.append(f"  {entity}: {', '.join(policies)}")
        return "\n".join(lines)
```

#### 5.3 `diff_policies()` -- Policy Change Detection

```python
# New file: src/sqla_authz/testing/_diff.py

@dataclass(frozen=True, slots=True)
class PolicyDiff:
    """Difference between two policy registries."""
    added: list[tuple[str, str, str]]      # (model_name, action, policy_name)
    removed: list[tuple[str, str, str]]    # (model_name, action, policy_name)
    changed_models: set[str]               # Models with any policy changes

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)

    def __str__(self) -> str:
        lines = []
        for model, action, name in self.added:
            lines.append(f"  + {model}.{action}: {name}")
        for model, action, name in self.removed:
            lines.append(f"  - {model}.{action}: {name}")
        return "\n".join(lines) if lines else "  (no changes)"


def diff_policies(
    old: PolicyRegistry,
    new: PolicyRegistry,
) -> PolicyDiff:
    """Compare two registries and return the differences.

    Useful for CI/CD pipelines to detect policy changes across
    deployments or code reviews.

    Args:
        old: The baseline registry (e.g., from main branch).
        new: The updated registry (e.g., from feature branch).

    Returns:
        A PolicyDiff describing added and removed policies.

    Example::

        diff = diff_policies(old_registry, new_registry)
        if diff.has_changes:
            print(f"Policy changes detected:\\n{diff}")
    """
    old_keys = set(old._policies.keys())
    new_keys = set(new._policies.keys())

    added = []
    removed = []
    changed_models = set()

    # Removed keys
    for key in old_keys - new_keys:
        model_name, action = key[0].__name__, key[1]
        for p in old.lookup(*key):
            removed.append((model_name, action, p.name))
            changed_models.add(model_name)

    # Added keys
    for key in new_keys - old_keys:
        model_name, action = key[0].__name__, key[1]
        for p in new.lookup(*key):
            added.append((model_name, action, p.name))
            changed_models.add(model_name)

    # Changed keys (same key, different policies)
    for key in old_keys & new_keys:
        model_name, action = key[0].__name__, key[1]
        old_names = {p.name for p in old.lookup(*key)}
        new_names = {p.name for p in new.lookup(*key)}
        for name in new_names - old_names:
            added.append((model_name, action, name))
            changed_models.add(model_name)
        for name in old_names - new_names:
            removed.append((model_name, action, name))
            changed_models.add(model_name)

    return PolicyDiff(added=added, removed=removed, changed_models=changed_models)
```

#### 5.4 Snapshot Testing Helper

```python
# New file: src/sqla_authz/testing/_snapshot.py

def assert_policy_sql_snapshot(
    registry: PolicyRegistry,
    resource_type: type,
    action: str,
    actor: ActorLike,
    *,
    snapshot: str,
    normalize_whitespace: bool = True,
) -> None:
    """Assert that the policy SQL matches a snapshot string.

    Useful for detecting unintended changes to generated SQL
    across code modifications.

    Args:
        registry: The policy registry.
        resource_type: The model class.
        action: The action string.
        actor: The actor to evaluate against.
        snapshot: The expected SQL string.
        normalize_whitespace: If True, collapse whitespace for comparison.

    Example::

        assert_policy_sql_snapshot(
            registry, Post, "read", MockActor(id=1),
            snapshot="post.is_published = true OR post.author_id = 1",
        )
    """
    filter_expr = evaluate_policies(registry, resource_type, action, actor)
    actual = str(filter_expr.compile(compile_kwargs={"literal_binds": True}))

    if normalize_whitespace:
        import re
        actual = re.sub(r'\s+', ' ', actual).strip()
        snapshot = re.sub(r'\s+', ' ', snapshot).strip()

    if actual != snapshot:
        raise AssertionError(
            f"Policy SQL snapshot mismatch:\n"
            f"  Expected: {snapshot}\n"
            f"  Actual:   {actual}"
        )
```

#### 5.5 Property-Based Testing Helper

```python
# New file: src/sqla_authz/testing/_properties.py

def assert_policy_invariant(
    registry: PolicyRegistry,
    resource_type: type,
    action: str,
    *,
    actors: list[ActorLike],
    invariant: Callable[[ActorLike, ColumnElement[bool]], bool],
    description: str = "",
) -> None:
    """Assert that a policy invariant holds for all given actors.

    Args:
        registry: The policy registry.
        resource_type: The model class.
        action: The action string.
        actors: List of actors to test against.
        invariant: A callable (actor, filter_expr) -> bool that must
            return True for all actors.
        description: Human-readable description of the invariant.

    Example::

        # Invariant: admin policies always produce true()
        assert_policy_invariant(
            registry, Post, "read",
            actors=[MockActor(id=i, role="admin") for i in range(100)],
            invariant=lambda actor, expr: "true" in str(expr).lower(),
            description="Admin read policy always grants access",
        )
    """
    for actor in actors:
        expr = evaluate_policies(registry, resource_type, action, actor)
        if not invariant(actor, expr):
            raise AssertionError(
                f"Policy invariant violated: {description}\n"
                f"  Actor: {actor!r}\n"
                f"  Expression: {expr}"
            )
```

### Implementation Steps

1. Create `src/sqla_authz/testing/_matrix.py` with `policy_matrix()`, `PolicyMatrix`, `PolicyCoverage`
2. Create `src/sqla_authz/testing/_simulate.py` with `simulate_query()`, `SimulationResult`
3. Create `src/sqla_authz/testing/_diff.py` with `diff_policies()`, `PolicyDiff`
4. Create `src/sqla_authz/testing/_snapshot.py` with `assert_policy_sql_snapshot()`
5. Create `src/sqla_authz/testing/_properties.py` with `assert_policy_invariant()`
6. Update `src/sqla_authz/testing/__init__.py` to export all new symbols
7. Write tests in `tests/test_testing/test_matrix.py`, `tests/test_testing/test_simulate.py`, `tests/test_testing/test_diff.py`, `tests/test_testing/test_snapshot.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_policy_matrix_all_covered` | Matrix shows all (model, action) pairs |
| `test_policy_matrix_uncovered_detected` | `uncovered` property lists gaps |
| `test_policy_matrix_explicit_models_actions` | Custom models/actions list works |
| `test_simulate_query_produces_sql` | Simulation returns authorized SQL string |
| `test_simulate_query_with_dialect` | PostgreSQL dialect produces pg-specific SQL |
| `test_simulate_shows_applied_policies` | Policy names listed per entity |
| `test_diff_detects_added_policy` | New policy detected as added |
| `test_diff_detects_removed_policy` | Removed policy detected |
| `test_diff_no_changes` | Identical registries produce empty diff |
| `test_diff_changed_same_key` | Different policies for same key detected |
| `test_snapshot_match` | Matching SQL passes |
| `test_snapshot_mismatch_error` | Non-matching SQL raises AssertionError |
| `test_snapshot_whitespace_normalized` | Whitespace differences ignored |
| `test_invariant_passes` | All actors satisfy invariant |
| `test_invariant_violation_error` | Violating actor produces clear error |

### Migration / Backwards Compatibility

- **Zero breaking changes.** All new exports. No existing APIs modified.
- The existing `assert_authorized`, `assert_denied`, `assert_query_contains` remain unchanged.

### Estimated Complexity: **M** (~400 LOC production, ~300 LOC tests)

---

## 6. Performance Optimization

### Problem

For applications with many policies or high query volume, several performance opportunities exist:

1. **Repeated policy evaluation**: The same policy function is called with the same actor on every query in a request. For a page that runs 10 queries, the same `post_read(actor)` is evaluated 10 times, producing the same `ColumnElement` each time.
2. **No batch authorization**: Checking `can(actor, "read", post)` for 50 posts means 50 separate calls, each re-evaluating the policy function and (currently) creating an in-memory SQLite engine.
3. **Redundant WHERE clauses**: If a user's query already contains `WHERE Post.author_id = :user_id`, and the policy would add the same filter, the duplicate clause wastes query planner time.

### Proposed Design

#### 6.1 Per-Request Policy Expression Cache

Cache the `ColumnElement` returned by a policy function for a given `(policy_name, actor_id)` pair within a single request. This avoids re-calling the policy function when the same actor queries the same model multiple times.

```python
# New file: src/sqla_authz/compiler/_cache.py

from __future__ import annotations
import contextvars
from typing import Any
from sqlalchemy import ColumnElement

_policy_cache: contextvars.ContextVar[dict[tuple[str, Any], ColumnElement[bool]]] = (
    contextvars.ContextVar("_policy_cache", default=None)
)


class PolicyCache:
    """Per-request cache for policy evaluation results.

    Uses contextvars for request-scoped isolation. Caches the
    ColumnElement returned by policy functions, keyed by
    (policy_name, actor_id).

    Usage::

        # In middleware/request handler:
        with PolicyCache.request_scope():
            # All queries in this scope share cached policy expressions
            session.execute(select(Post))
            session.execute(select(Post).where(...))  # same policy, cached
    """

    @staticmethod
    @contextmanager
    def request_scope() -> Generator[None, None, None]:
        """Context manager that creates a fresh cache for the request."""
        token = _policy_cache.set({})
        try:
            yield
        finally:
            _policy_cache.reset(token)

    @staticmethod
    def get(policy_name: str, actor_id: Any) -> ColumnElement[bool] | None:
        """Look up a cached policy expression."""
        cache = _policy_cache.get(None)
        if cache is None:
            return None
        return cache.get((policy_name, actor_id))

    @staticmethod
    def put(policy_name: str, actor_id: Any, expr: ColumnElement[bool]) -> None:
        """Store a policy expression in the cache."""
        cache = _policy_cache.get(None)
        if cache is not None:
            cache[(policy_name, actor_id)] = expr
```

**Integration in `evaluate_policies()`:**

```python
def evaluate_policies(registry, resource_type, action, actor):
    policies = registry.lookup(resource_type, action)
    if not policies:
        return false()

    filters = []
    for p in policies:
        cached = PolicyCache.get(p.name, actor.id)
        if cached is not None:
            filters.append(cached)
        else:
            expr = p.fn(actor)
            PolicyCache.put(p.name, actor.id, expr)
            filters.append(expr)

    return reduce(lambda a, b: a | b, filters)
```

**Performance impact**: The cache check is a dict lookup (~50ns). For a request that runs 10 queries against the same model, this saves 9 policy function calls per policy. If each policy function call takes ~1-5us (SQLAlchemy expression construction), the savings are ~10-50us per request -- modest but free.

**Safety**: The cache is request-scoped via `contextvars`. No cross-request leakage. If no `request_scope()` context is active, caching is silently disabled (get returns None, put is a no-op).

#### 6.2 Batch Authorization

Add `can_many()` that checks authorization for multiple resources in a single evaluation:

```python
# src/sqla_authz/_checks.py addition

def can_many(
    actor: ActorLike,
    action: str,
    resources: Sequence[DeclarativeBase],
    *,
    registry: PolicyRegistry | None = None,
    session: Session | None = None,
) -> dict[int | str, bool]:
    """Check authorization for multiple resources in one call.

    Evaluates the policy expression once (not once per resource)
    and applies it to all resources. Returns a dict mapping
    each resource's PK to its authorization result.

    After plan #1 (can() rewrite) is implemented, this uses the
    Python expression evaluator for all resources with a single
    policy evaluation.

    Args:
        actor: The actor performing the action.
        action: The action string.
        resources: A sequence of ORM model instances.
        registry: Optional custom registry.
        session: Optional session for relationship loading.

    Returns:
        Dict mapping resource primary key to authorized (True/False).

    Example::

        posts = session.execute(select(Post)).scalars().all()
        results = can_many(current_user, "read", posts)
        # {1: True, 2: False, 3: True, ...}
        authorized_posts = [p for p in posts if results[p.id]]
    """
    if not resources:
        return {}

    target_registry = registry if registry is not None else get_default_registry()
    resource_type = type(resources[0])

    # Evaluate policy expression ONCE
    filter_expr = evaluate_policies(target_registry, resource_type, action, actor)

    # Apply to each resource using the expression evaluator (plan #1)
    # After plan #1: uses eval_expression() from compiler/_eval.py
    results = {}
    for resource in resources:
        pk = sa_inspect(resource).identity[0]  # primary key value
        results[pk] = eval_expression(filter_expr, resource, session=session)

    return results
```

**Performance gain**: For 50 resources, `can_many` calls the policy function once (vs 50 times for individual `can()` calls). After plan #1, each `eval_expression` call is ~10-20us, so 50 resources take ~500-1000us total vs ~65,000us with the current `can()` implementation (50 * 1300us).

#### 6.3 Compiled Policy Cache (Persistent Across Requests)

For policies that are truly static (no actor-dependent values), cache the compiled SQL string to avoid repeated expression construction:

**Decision: Defer to v1.0.** Most policies are actor-dependent (`Post.author_id == actor.id`), so the expression changes per actor. Caching the ColumnElement is more useful than caching compiled SQL. The per-request cache (6.1) handles the common case. A persistent compiled cache would only benefit the rare case of actor-independent policies (e.g., `Post.is_published == True`), which are already cheap to evaluate.

#### 6.4 Lazy Policy Evaluation (Deduplication)

**Decision: Defer to v1.0.** Detecting that a user's query already contains an equivalent WHERE clause requires comparing SQLAlchemy expression trees, which is complex and error-prone. The SQL query planner already optimizes redundant conditions. The marginal benefit does not justify the implementation complexity.

### Implementation Steps

1. Create `src/sqla_authz/compiler/_cache.py` with `PolicyCache`
2. Integrate `PolicyCache.get()`/`put()` into `evaluate_policies()` in `src/sqla_authz/compiler/_expression.py`
3. Add `PolicyCache.request_scope()` context manager integration in framework middleware examples
4. Add `can_many()` to `src/sqla_authz/_checks.py` (depends on plan #1 for `eval_expression`)
5. Update `__init__.py` to export `can_many`, `PolicyCache`
6. Write tests in `tests/test_compiler/test_cache.py`, `tests/test_checks_batch.py`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_cache_hit_returns_same_expression` | Second call returns cached expression |
| `test_cache_miss_calls_policy_fn` | First call invokes the policy function |
| `test_cache_scoped_to_request` | Different requests get different caches |
| `test_cache_disabled_without_scope` | No active scope = caching silently disabled |
| `test_cache_different_actors_separate_entries` | Different actor IDs produce separate cache entries |
| `test_can_many_returns_correct_results` | Batch check matches individual can() results |
| `test_can_many_empty_list` | Empty input returns empty dict |
| `test_can_many_single_policy_eval` | Policy function called only once for all resources |
| `test_can_many_mixed_results` | Some granted, some denied |

### Migration / Backwards Compatibility

- **Zero breaking changes.** `PolicyCache` is opt-in via `request_scope()`. Without it, behavior is identical to current code.
- `can_many()` is a new function, fully additive.
- No existing function signatures change.

### Estimated Complexity: **S** (~200 LOC production, ~150 LOC tests)

---

## 7. Migration Tooling (Oso/Polar to sqla-authz)

### Problem

Oso (the in-process authorization library with Polar DSL) was deprecated in December 2023. Its users need a migration path. sqla-authz is the closest replacement: in-process, SQLAlchemy-native, SQL filter generation. But Oso users have Polar files (`.polar`) with rules written in a custom DSL, and there is no automated way to convert them to sqla-authz `@policy` decorators.

### Proposed Design

#### 7.1 Polar Parser and Converter

Create a best-effort Polar-to-Python converter that handles the most common patterns. It does NOT attempt to parse all of Polar (which is Turing-complete) -- it handles the 80% case and flags unsupported constructs for manual conversion.

```python
# New file: src/sqla_authz/migration/_polar_parser.py

@dataclass
class PolarRule:
    """Parsed representation of a single Polar allow/deny rule."""
    rule_type: str              # "allow" or "deny"
    actor_type: str             # e.g., "User"
    action: str                 # e.g., "read"
    resource_type: str          # e.g., "Post"
    conditions: list[str]       # Polar condition expressions
    source_line: int            # Line number in .polar file


@dataclass
class ConversionResult:
    """Result of converting a .polar file."""
    python_code: str            # Generated Python source code
    converted_rules: int        # Number of successfully converted rules
    skipped_rules: list[tuple[int, str, str]]  # (line, rule_text, reason)
    warnings: list[str]


def parse_polar_file(path: str | Path) -> list[PolarRule]:
    """Parse a .polar file into a list of PolarRule objects.

    Handles:
    - allow(actor, action, resource) rules
    - Simple field comparisons (resource.field = value)
    - Actor field comparisons (actor.role = "admin")
    - Relationship traversals (resource.author.org)
    - String, integer, and boolean literals
    - Logical AND (implicit in Polar comma-separated conditions)
    - Logical OR (separate rules for same actor/action/resource)

    Does NOT handle:
    - Custom Polar classes and methods
    - Polar inline queries
    - Polar cuts and negation
    - Recursive rules
    - Specializers beyond simple type matching
    """
    ...
```

#### 7.2 Code Generator

```python
# New file: src/sqla_authz/migration/_codegen.py

def polar_to_python(
    rules: list[PolarRule],
    *,
    model_module: str = "myapp.models",
    actor_type: str = "User",
) -> ConversionResult:
    """Convert parsed Polar rules to sqla-authz @policy decorators.

    Args:
        rules: Parsed Polar rules from parse_polar_file().
        model_module: The Python module path for model imports.
        actor_type: The actor type name for type annotations.

    Returns:
        A ConversionResult with generated Python code.

    Example output::

        from sqlalchemy import ColumnElement, true, false
        from sqla_authz import policy
        from myapp.models import Post, User

        @policy(Post, "read")
        def post_read_published(actor: User) -> ColumnElement[bool]:
            \"\"\"Converted from: allow(actor: User, "read", post: Post) if
                post.is_published = true;\"\"\"
            return Post.is_published == True

        @policy(Post, "read")
        def post_read_own(actor: User) -> ColumnElement[bool]:
            \"\"\"Converted from: allow(actor: User, "read", post: Post) if
                post.author = actor;\"\"\"
            return Post.author_id == actor.id
    """
```

#### 7.3 Pattern Translation Table

| Polar Pattern | sqla-authz Translation |
|---|---|
| `resource.field = value` | `Model.field == value` |
| `resource.field = actor.field` | `Model.field == actor.field` |
| `actor.role = "admin"` | `true() if actor.role == "admin" else false()` |
| `resource.relation.field = value` | `traverse_relationship_path(Model, ["relation"], Related.field == value)` |
| `not condition` | `~(translated_condition)` |
| Multiple conditions (AND) | `and_(cond1, cond2)` |
| Multiple rules same key (OR) | Separate `@policy` decorators (auto-OR'd) |
| `actor.role in ["admin", "editor"]` | `true() if actor.role in {"admin", "editor"} else false()` |

#### 7.4 CLI Command

```python
# New file: src/sqla_authz/migration/_cli.py (or integrate with existing CLI)

def migrate_from_oso(
    polar_file: str | Path,
    output_file: str | Path | None = None,
    *,
    model_module: str = "myapp.models",
    actor_type: str = "User",
) -> ConversionResult:
    """Convert an Oso .polar file to sqla-authz policies.

    Args:
        polar_file: Path to the .polar file.
        output_file: Path to write the generated Python file.
            If None, prints to stdout.
        model_module: Import path for model classes.
        actor_type: The actor type name.

    Returns:
        ConversionResult with statistics and any warnings.

    Example::

        result = migrate_from_oso(
            "authorization.polar",
            "policies.py",
            model_module="myapp.models",
        )
        print(f"Converted {result.converted_rules} rules")
        if result.skipped_rules:
            print(f"Skipped {len(result.skipped_rules)} rules (manual conversion needed)")
    """
    rules = parse_polar_file(polar_file)
    result = polar_to_python(rules, model_module=model_module, actor_type=actor_type)

    if output_file is not None:
        Path(output_file).write_text(result.python_code)
    else:
        print(result.python_code)

    return result
```

#### 7.5 Validation Helper

```python
# New file: src/sqla_authz/migration/_validate.py

def validate_migration(
    *,
    polar_file: str | Path,
    sqla_authz_registry: PolicyRegistry,
    test_actors: list[ActorLike],
    test_resources: dict[type, list[dict[str, Any]]],
) -> ValidationReport:
    """Validate that migrated policies produce equivalent results.

    Runs both the Oso evaluation (if oso is installed) and the
    sqla-authz evaluation against the same actors and resources,
    comparing results.

    This is a best-effort check -- it cannot verify equivalence for
    all possible inputs, only the provided test cases.
    """
    ...
```

**Note**: The validation helper requires `oso` to be installed (optional dependency). If not installed, it skips the comparison and only validates that the sqla-authz policies compile without errors.

### Implementation Steps

1. Create `src/sqla_authz/migration/` package with `__init__.py`
2. Create `src/sqla_authz/migration/_polar_parser.py` with basic Polar tokenizer and parser
3. Create `src/sqla_authz/migration/_codegen.py` with `polar_to_python()`
4. Create `src/sqla_authz/migration/_cli.py` with `migrate_from_oso()`
5. Create `src/sqla_authz/migration/_validate.py` with `validate_migration()`
6. Create `docs/guides/oso-migration.md` with step-by-step migration guide
7. Update `__init__.py` to export migration tools (optional, behind import guard)
8. Write tests using sample `.polar` files in `tests/test_migration/`

### Testing Strategy

| Test Case | Description |
|-----------|-------------|
| `test_parse_simple_allow_rule` | Basic `allow(actor, "read", resource)` parses correctly |
| `test_parse_field_comparison` | `resource.field = value` condition parsed |
| `test_parse_actor_field` | `actor.role = "admin"` condition parsed |
| `test_parse_relationship_traversal` | `resource.author.org` parsed as path |
| `test_parse_multiple_conditions` | AND conditions (comma-separated) parsed |
| `test_parse_multiple_rules_same_key` | Multiple rules for same (model, action) |
| `test_codegen_simple_policy` | Generates valid `@policy` decorator code |
| `test_codegen_relationship_policy` | Generates `traverse_relationship_path` call |
| `test_codegen_role_check` | Actor role check generates conditional `true()`/`false()` |
| `test_codegen_unsupported_rule_skipped` | Complex Polar constructs produce warnings |
| `test_generated_code_compiles` | Generated Python code is valid (exec() succeeds) |
| `test_generated_code_registers_policies` | Executing generated code registers policies in registry |
| `test_migrate_from_oso_end_to_end` | Full .polar file -> Python file conversion |

### Migration / Backwards Compatibility

- **Zero breaking changes.** Entirely new package. No existing code modified.
- `oso` is an optional dependency for the validation helper only.
- The migration tools can be excluded from the core package if desired (separate entry point or extras_require).

### Estimated Complexity: **L** (~600 LOC production, ~400 LOC tests)

---

## 8. Recommended Priority Order

### Priority Ranking

| Priority | Feature | Complexity | Depends On | Rationale |
|----------|---------|------------|------------|-----------|
| **1** | Policy Testing & Simulation (5) | M | None | Highest impact-to-effort. Makes every other feature testable. Users need this before trusting the library with production data. |
| **2** | Policy Composition & Inheritance (2) | M | None | Enables multi-tenant patterns and complex permission models. Foundation for tenant isolation. |
| **3** | Multi-tenancy Support (1) | M | Composition (2) | Largest addressable market. SaaS apps need this. Builds on composition for registry forking. |
| **4** | Audit Trail Integration (4) | M | None | Enterprise requirement for compliance. Moderate effort with clear API boundaries. |
| **5** | Performance Optimization (6) | S | Plan #1 (can rewrite) | `can_many` depends on plan #1. Cache is independent but lower priority since current perf is adequate for most use cases. |
| **6** | Field-Level Authorization (3) | L | None | Differentiating feature but high complexity. Requires careful design around `defer()`/`raiseload` interaction. |
| **7** | Migration Tooling (7) | L | Testing (5) | Important for adoption but the migration guide (documentation) delivers 80% of the value. Automated converter is nice-to-have. |

### Version Mapping

| Version | Features | Theme |
|---------|----------|-------|
| **v0.2** | Policy Testing (5), Composition (2) | "Testable and Composable" |
| **v0.3** | Multi-tenancy (1), Audit Trail (4), Performance Cache (6.1) | "Enterprise-Ready" |
| **v1.0** | Field-Level Auth (3), Batch Auth (6.2), Migration Tooling (7) | "Complete Platform" |

### Total Estimated LOC

| Version | Production Code | Test Code | Documentation |
|---------|----------------|-----------|---------------|
| v0.2 | ~750 | ~550 | ~200 |
| v0.3 | ~900 | ~650 | ~300 |
| v1.0 | ~1300 | ~850 | ~400 |
| **Total** | **~2950** | **~2050** | **~900** |

This roughly doubles the current codebase (~1980 LOC) to reach v1.0.

---

## 9. Cross-Plan Dependencies

| This Feature | Depends On (Other Plans) | Nature |
|---|---|---|
| Multi-tenancy (1) | Plan #2 (security model) -- tenant bypass handling | Soft: tenant `skip_tenant` should follow the same strict mode patterns |
| Policy Composition (2) | None | Independent |
| Field-Level Auth (3) | Plan #4 (explain mode) -- explain field policy decisions | Soft: explain mode should report deferred columns |
| Audit Trail (4) | Plan #2 (security model) -- audit bypass events | Soft: bypass audit events from plan #2 should use the new audit dispatcher |
| Policy Testing (5) | Plan #4 (explain mode) -- shares SQL compilation utilities | Soft: `simulate_query` and `explain_query` can share compilation logic |
| Performance Cache (6) | Plan #1 (can rewrite) -- `can_many` uses `eval_expression` | Hard: batch authorization requires the Python expression evaluator |
| Migration Tooling (7) | Policy Testing (5) -- validates converted policies | Soft: migration validation uses PolicyTester |

---

## 10. File-by-File Summary

### New Files

| File | Feature | Est. LOC |
|------|---------|----------|
| `src/sqla_authz/session/_tenant.py` | Multi-tenancy | ~120 |
| `src/sqla_authz/policy/_roles.py` | Role hierarchy | ~60 |
| `src/sqla_authz/policy/_field_base.py` | Field policy registration | ~30 |
| `src/sqla_authz/policy/_field_decorator.py` | `@field_policy` decorator | ~60 |
| `src/sqla_authz/audit/__init__.py` | Audit package | ~20 |
| `src/sqla_authz/audit/_events.py` | Audit event dataclass | ~80 |
| `src/sqla_authz/audit/_handlers.py` | Audit handlers | ~120 |
| `src/sqla_authz/audit/_dispatcher.py` | Audit dispatcher | ~50 |
| `src/sqla_authz/compiler/_cache.py` | Policy expression cache | ~80 |
| `src/sqla_authz/testing/_matrix.py` | Coverage matrix | ~100 |
| `src/sqla_authz/testing/_simulate.py` | Query simulation | ~80 |
| `src/sqla_authz/testing/_diff.py` | Policy diff | ~80 |
| `src/sqla_authz/testing/_snapshot.py` | Snapshot testing | ~40 |
| `src/sqla_authz/testing/_properties.py` | Property-based testing | ~40 |
| `src/sqla_authz/migration/__init__.py` | Migration package | ~10 |
| `src/sqla_authz/migration/_polar_parser.py` | Polar file parser | ~250 |
| `src/sqla_authz/migration/_codegen.py` | Python code generator | ~200 |
| `src/sqla_authz/migration/_cli.py` | Migration CLI | ~60 |
| `src/sqla_authz/migration/_validate.py` | Migration validator | ~80 |

### Modified Files

| File | Features | Changes |
|------|----------|---------|
| `src/sqla_authz/config/_config.py` | Tenant, Audit, Field | Add `TenantConfig`, `audit_dispatcher`, `field_policy_on_access` fields |
| `src/sqla_authz/policy/_registry.py` | Composition, Field | Add `parent`, `fork()`, `_field_policies`, field policy methods, thread-safe parent lookup |
| `src/sqla_authz/policy/_base.py` | Composition | Add `compose` field to `PolicyRegistration` |
| `src/sqla_authz/policy/_decorator.py` | Composition | Add `compose` parameter |
| `src/sqla_authz/compiler/_expression.py` | Composition, Cache, Audit | AND/OR grouping, cache integration, audit event emission |
| `src/sqla_authz/session/_interceptor.py` | Tenant, Field | Pre-policy tenant filter, field policy defer options |
| `src/sqla_authz/_checks.py` | Performance, Audit | Add `can_many()`, `visible_fields()`, audit emission in `can()` |
| `src/sqla_authz/testing/__init__.py` | Testing | Export new testing tools |
| `src/sqla_authz/__init__.py` | All | Export new public APIs |

---

## 11. What NOT to Build

### Admin UI -- NEVER

A web interface for defining policies contradicts the library's core design principle: policies are code, living in version control, reviewed in PRs, tested in CI. A visual editor works against this.

### Custom Policy DSL -- NEVER

Oso had Polar. We explicitly chose Python-native policies as a differentiator. Python IS our DSL. SQLAlchemy expressions ARE our query language. This eliminates the need for a parser, compiler, custom runtime, and DSL-specific documentation.

### Distributed Authorization -- NEVER (in this library)

sqla-authz is explicitly an in-process library. Its value proposition is "no external servers, no network round-trips." If users need graph-based authorization (SpiceDB/Zanzibar), they should use a dedicated service. sqla-authz handles the SQL-level filtering complement.

### Policy Priority/Override System -- DEFER to v1.0+

True priority-based conflict resolution (where a high-priority DENY overrides a lower-priority ALLOW) requires a fundamentally different evaluation model. The AND/OR composition model covers most practical cases. Revisit only if users demand it.

---

## 12. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Tenant filter performance overhead | LOW | MEDIUM | Single column equality check per entity per query (~microseconds). Benchmark before/after. |
| AND/OR composition confuses users | MEDIUM | LOW | Default is OR (existing behavior). AND requires explicit `compose="and"`. Document clearly with examples. |
| Field policy `defer(raiseload=True)` breaks serialization | MEDIUM | MEDIUM | Provide `visible_fields()` helper for serializers. Document the `raiseload` behavior prominently. |
| Audit handler exceptions crash request | LOW | HIGH | Dispatcher catches all handler exceptions. Audit failures never break authorization (defense in depth). |
| Policy cache returns stale expression | LOW | HIGH | Cache is request-scoped via contextvars. No cross-request leakage by design. Cache key includes actor ID. |
| Polar parser incomplete | HIGH | LOW | Parser is best-effort by design. Unsupported constructs are flagged, not silently dropped. Manual conversion always available. |
| Registry inheritance lookup performance | LOW | LOW | Parent lookup is O(1) dict access. Chain depth is typically 1-2 levels. |
| Thread safety with parent registries | LOW | MEDIUM | Parent registries are read-only after startup (append-only during module import). Child registries are request-scoped. Lock from plan #3 protects registration. |

---

## 13. Open Questions

1. **Tenant filtering and write operations**: Should tenant isolation apply to UPDATE/DELETE statements (when write interception is enabled)? Recommendation: Yes, using the same `_apply_tenant_filter` logic. Defer implementation until write interception (from the existing plan draft) is built.

2. **Field policy interaction with `select(Model.specific_column)`**: If a query explicitly selects only certain columns (`select(Post.id, Post.title)`), should field policies still defer columns not in the select? Recommendation: No. Field policies only affect full-model loads (`select(Post)`). Explicit column selection is already a form of field-level control.

3. **Registry inheritance depth limit**: Should there be a maximum depth for parent chains to prevent accidental infinite loops? Recommendation: Yes, cap at 10 levels with a clear error message. In practice, 2-3 levels is the maximum.

4. **Audit event batching**: Should the `DatabaseAuditHandler` batch inserts for performance? Recommendation: Start with per-event inserts. Add optional batching (flush every N events or every M milliseconds) in a follow-up if users report performance issues.

5. **Migration tooling as separate package**: Should `sqla_authz.migration` be a separate package (`sqla-authz-migration`) to keep the core package lean? Recommendation: Keep it in the core package but behind a lazy import guard. The code is small (~600 LOC) and the convenience of `from sqla_authz.migration import migrate_from_oso` outweighs the size concern.
