# Brainstorm: Cross-Cutting `scope()` Primitive

**Date:** 2026-03-07
**Status:** Design complete
**Related:** `.docs/analysis.md` Issue #2, Proposal B

## What We're Building

A composable, cross-cutting filter primitive called `scope()` that is automatically AND'd with all policy results for matching models. Scopes enforce invariants like tenant isolation that must never be accidentally bypassed by adding a new policy or a new model.

**The problem it solves:** In multi-tenant apps, every policy for every model must independently include the tenant filter (e.g., `Model.org_id == actor.org_id`). Forgetting it on one model leaks data across tenants. This is copy-paste security — the #1 authorization bug in real SaaS apps.

**Core semantics:**
- Policies are OR'd (any match grants access)
- Scopes are AND'd with the OR'd policy result (scopes restrict, policies grant)
- Multiple scopes on the same model are AND'd together (more scopes = more restrictive)
- Final SQL shape: `WHERE (policy1 OR policy2) AND scope1 AND scope2`

## Why This Approach

We evaluated four model-targeting strategies (explicit list, field-based auto-detection, mixin/base-class detection, predicate function) and chose **explicit model list** because:

1. **Auditable** — you can read the decorator and know exactly which models are scoped
2. **No magic** — no column-name matching that could accidentally catch unrelated models
3. **Paired with safety net** — `verify_scopes()` startup check catches models that should be scoped but aren't, addressing the "forgot to add new model" risk
4. **Simple** — no new concepts beyond "list your models"

## Key Decisions

### 1. Registration API

**Decision:** Decorator with explicit model list and Model parameter.

```python
@scope(applies_to=[Post, Comment, Document])
def tenant_scope(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id
```

- `applies_to` takes a list of SQLAlchemy model classes
- The scope function receives `(actor, Model)` where `Model` is the class currently being filtered
- One function handles all models in the list — requires models to share the filtered column
- Returns `ColumnElement[bool]`, same as policy functions

### 2. Action Specificity

**Decision:** All actions by default, with optional `actions=` restriction.

```python
# Applies to ALL actions (read, update, delete, etc.)
@scope(applies_to=[Post, Comment])
def tenant_scope(actor, Model):
    return Model.org_id == actor.org_id

# Restricted to specific actions
@scope(applies_to=[Post], actions=["read"])
def soft_delete_scope(actor, Model):
    return Model.deleted_at.is_(None)
```

Rationale: Tenant isolation should never be action-dependent. The `actions=` parameter is for non-universal scopes like soft-delete (which shouldn't restrict deletes).

### 3. Composition

**Decision:** Multiple scopes AND'd together.

```sql
-- Final SQL for a model with tenant + soft-delete scopes:
WHERE (policy1 OR policy2)     -- policies grant access
  AND org_id = :org_id          -- tenant scope restricts
  AND deleted_at IS NULL         -- soft-delete scope restricts
```

### 4. Registry Placement

**Decision:** Inside existing `PolicyRegistry`.

- Add `_scopes: dict[type, list[ScopeRegistration]]` alongside `_policies`
- `registry.clear()` clears both policies and scopes
- No new registry class — `registry=` parameter works for both
- New methods: `register_scope()`, `lookup_scopes()`, `has_scopes()`

### 5. Bypass Semantics

**Decision:** Scope function returns `true()` for admin bypass.

```python
@scope(applies_to=[Post, Comment])
def tenant_scope(actor, Model):
    if actor.is_superadmin:
        return true()  # no restriction
    return Model.org_id == actor.org_id
```

No new bypass mechanism needed. The scope is always evaluated but can be a no-op. This keeps the bypass logic in one place (the scope function) and doesn't introduce new security-sensitive escape hatches.

### 6. Safety Net

**Decision:** Standalone `verify_scopes()` function only. No runtime config flag.

```python
from sqla_authz import verify_scopes

# In app startup or CI:
verify_scopes(Base, field="org_id")
# Scans all Base subclasses, raises if any with org_id lack a scope

# Optional predicate for custom logic:
verify_scopes(Base, when=lambda M: hasattr(M, "org_id"))
```

No `require_scope_for_field` config option — `verify_scopes()` at startup/CI is sufficient. No runtime overhead, no config complexity.

### 7. Integration Point

**Decision:** `evaluate_policies()` in `_expression.py`.

This is the single function where policies get OR'd. By looking up and AND'ing scopes here, all three evaluation paths get scope support automatically:
- `authorize_query()` — SQL WHERE clause injection
- `can()` / `authorize()` — in-memory point checks via `eval_expression()`
- Session interceptor — automatic query filtering

The scope expressions use the same `ColumnElement[bool]` type as policies, so the in-memory evaluator (`_eval.py`) handles them with zero changes.

## Scenarios Validated

### Multi-tenant SaaS
```python
@scope(applies_to=[Project, Task, Comment, Invoice])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id

@policy(Task, "read")
def task_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()  # still scoped to org
    return Task.assignee_id == actor.id
```

### Soft-delete
```python
@scope(applies_to=[Post, Comment, Task], actions=["read"])
def hide_deleted(actor: User, Model: type) -> ColumnElement[bool]:
    if actor.is_admin:
        return true()  # admins see deleted rows
    return Model.deleted_at.is_(None)
```

### Data residency
```python
@scope(applies_to=[UserData, Document, Attachment])
def region_scope(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.region == actor.region
```

## Resolved Questions

1. **`verify_scopes()` API** — Standalone function, accepts `Base` (scans all subclasses), with `field=` for column-based matching and optional `when=` predicate for custom logic. Not a registry method.

2. **`require_scope_for_field` config** — Not needed. `verify_scopes()` at startup/CI is sufficient. No runtime config overhead.

3. **Scope + no policies** — Preserve fail-closed. No policies = `false()`, regardless of scopes. Scopes are restrictions on top of policies, not replacements. A model must have at least one policy to be queryable.

4. **Testing utilities** — Defer to follow-up. Existing `assert_authorized` and `SimulatedQuery` already test the combined result of policies + scopes. Add scope-specific helpers later based on real usage feedback.

## Open Questions

None — all design questions resolved.
