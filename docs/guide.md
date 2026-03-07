# Guide

## Policies

A policy is a Python function decorated with `@policy(Model, "action")` that returns a `ColumnElement[bool]` — a SQLAlchemy filter expression, the same type you'd pass to `.where()`.

### Defining Policies

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True
```

Policies must be **synchronous** and must not perform I/O. The returned expression is built in memory and compiled to SQL by SQLAlchemy.

!!! tip "Action Constants"
    Use `READ`, `UPDATE`, `DELETE`, `CREATE` from `sqla_authz` instead of
    bare strings. They provide IDE autocomplete and prevent typos like
    `"raed"` that silently return zero rows.
    See [Action Safety](#action-safety) below.

### Python Control Flow

Because policies are plain Python functions, you can branch on actor attributes to produce different SQL for different roles:

```python
from sqlalchemy import true, or_

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()  # no WHERE clause — admin sees all rows
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

Role checks (`actor.role == "admin"`) run in Python. Row-level conditions (`Post.is_published == True`) become SQL. This separation is key — you get the flexibility of Python for actor logic and the efficiency of SQL for data filtering.

### Multiple Policies

Multiple `@policy` decorators for the same `(Model, action)` are OR'd together. This lets you compose authorization rules from separate modules:

```python
# In publishing.py
@policy(Post, "read")
def published_posts(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True


# In ownership.py
@policy(Post, "read")
def own_posts(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id

# Effective filter: WHERE is_published = true OR author_id = :id
```

### true() and false()

`sqlalchemy.true()` allows all rows (no WHERE clause restriction). `sqlalchemy.false()` denies all rows (`WHERE FALSE`). Use them as return values for unconditional grant or deny:

```python
@policy(AuditLog, "read")
def audit_log_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "auditor":
        return true()
    return false()
```

### Custom Registries

The global registry works for most applications. For test isolation or multi-tenant scenarios, create a separate `PolicyRegistry`:

```python
from sqla_authz.policy import PolicyRegistry

tenant_registry = PolicyRegistry()

@policy(Post, "read", registry=tenant_registry)
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.org_id == actor.org_id

stmt = authorize_query(
    select(Post), actor=user, action="read", registry=tenant_registry
)
```

---

## Action Safety

Action constants and validation catch typos before they cause silent data loss.

```python
from sqla_authz import READ, UPDATE, DELETE, CREATE

@policy(Post, READ)
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True
```

### Custom Actions

Use `action()` to create validated constants for domain-specific actions:

```python
from sqla_authz import action

PUBLISH = action("publish")
SOFT_DELETE = action("soft_delete")
```

Names must be lowercase alphabetic with optional underscores. Invalid names raise `ValueError` at definition time.

### Unknown Action Detection

Configure `on_unknown_action` to catch misspelled action strings at query time:

| Environment | `on_unknown_action` | Why |
|---|---|---|
| Development | `"warn"` | Catch typos immediately |
| CI / Tests | `"raise"` | Fail fast on misspelled actions |
| Production | `"ignore"` (default) | No runtime overhead; rely on CI |

```python
configure(on_unknown_action="raise")

authorize_query(select(Post), actor=user, action="raed")
# UnknownActionError: Action 'raed' has no registered policies. Did you mean 'read'? Known actions: ['create', 'delete', 'read', 'update']
```

`strict_mode=True` sets `on_unknown_action="warn"` automatically.

---

## Relationship Traversal

Authorization rules often depend on related models — "show me posts by authors in my organization." Use SQLAlchemy's `has()` (many-to-one) and `any()` (one-to-many) to traverse relationships. These compile to SQL EXISTS subqueries:

```python
@policy(Post, "read")
def same_org_posts(actor: User) -> ColumnElement[bool]:
    return Post.author.has(User.org_id == actor.org_id)
```

Generated SQL:

```sql
WHERE EXISTS (
    SELECT 1 FROM users
    WHERE users.id = posts.author_id AND users.org_id = :org_id
)
```

Multi-hop traversal nests naturally — "posts by authors whose organization is in my region":

```python
@policy(Post, "read")
def same_region_posts(actor: User) -> ColumnElement[bool]:
    return Post.author.has(
        User.organization.has(Organization.region == actor.region)
    )
```

For programmatic traversal, use `traverse_relationship_path()`:

```python
from sqla_authz.compiler._relationship import traverse_relationship_path

return traverse_relationship_path(
    Post, path=["author"], leaf_condition=User.org_id == actor.org_id,
)
```

!!! tip "Performance"
    Index foreign key columns and filter columns used in EXISTS subqueries. For deep multi-hop chains on hot paths, consider denormalizing the join key onto the primary table.

---

## Scopes

### The Multi-Tenant Problem

```python
@policy(Post, READ)
def post_read(actor: User) -> ColumnElement[bool]:
    return (Post.org_id == actor.org_id) & (Post.is_published == True)

@policy(Comment, READ)
def comment_read(actor: User) -> ColumnElement[bool]:
    return Comment.org_id == actor.org_id  # easy to forget on new models
```

Every policy repeats `Model.org_id == actor.org_id`. If you add a new model and forget this filter, that model's data is visible across tenants.

### Defining a Scope

```python
from sqla_authz import scope

@scope(applies_to=[Post, Comment, Document])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id
```

Now individual policies only express their own logic -- the tenant filter is automatic.

Register scopes anywhere before query time -- typically in a `scopes.py` module imported at app startup. Scopes and policies can be registered in any order.

### How Scopes Compose

```
final_filter = (policy_1 OR policy_2) AND scope_1 AND scope_2
```

- **Policies grant access** -- if any policy matches, the row is a candidate
- **Scopes restrict access** -- all scopes must match for the row to be returned
- **No policy = no access** -- scopes cannot override the deny-by-default rule. If no policy exists for a `(model, action)` pair, the result is `WHERE FALSE` regardless of scopes.

Tenant + soft-delete scopes compose naturally:

```python
@scope(applies_to=[Post, Comment])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id

@scope(applies_to=[Post, Comment])
def soft_delete(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.deleted_at.is_(None)
```

Generated SQL:

```sql
WHERE (is_published = true OR author_id = :id)
  AND org_id = :org_id
  AND deleted_at IS NULL
```

To bypass a scope for admin users, return `true()`:

```python
from sqlalchemy import true

@scope(applies_to=[Post, Comment])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return Model.org_id == actor.org_id
```

Returning `true()` bypasses the scope, but policies still apply. To grant unrestricted access, the policy must also return `true()` for admins.

Scopes apply to all entry points -- `authorize_query()`, session interception, and `can()`/`authorize()` point checks. Scope expressions used with `can()` must use the supported operator subset. See [Limitations](limitations.md#scope-limitations).

### Action-Specific Scopes

Some scopes should only apply to certain actions. A soft-delete scope should hide deleted rows from reads but not prevent actual deletions:

```python
from sqla_authz import READ

@scope(applies_to=[Post], actions=[READ])
def soft_delete(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.deleted_at.is_(None)
```

Without `actions=[READ]`, this scope would also prevent `DELETE` operations on soft-deleted rows. When `actions` is omitted (or `None`), the scope applies to all actions.

### Catching Missing Scopes

```python
from sqla_authz import verify_scopes

# In your app startup (e.g., create_app(), FastAPI lifespan)
verify_scopes(Base, field="org_id")
```

This checks every subclass of `Base`. If any has an `org_id` column but no registered scope, it raises immediately -- before the application serves requests.

```python
verify_scopes(Base, field="org_id")
# UnscopedModelError: The following models have a 'org_id' column but no registered scope: Invoice, Notification
```

Custom predicate variant:

```python
verify_scopes(Base, when=lambda M: hasattr(M, "org_id"))
```

`field` and `when` are mutually exclusive. All model modules must be imported before calling `verify_scopes()`.

!!! tip "Call at Startup or in CI"
    Call `verify_scopes()` during application startup or in your test
    suite -- never in the request path. It scans all model classes,
    which is a one-time cost at boot.

---

## Point Checks

`authorize_query()` filters collections. For a single already-loaded object — "can this user delete this specific post?" — use `can()` or `authorize()`:

```python
from sqla_authz import can, authorize

# Boolean check
if can(actor, "delete", post):
    session.delete(post)

# Raising check — throws AuthorizationDenied if denied
authorize(actor, "edit", post)
authorize(actor, "edit", post, message="Only the author can edit this post.")
```

Point checks reuse your `@policy` functions. They evaluate the policy expression against the object's attributes in memory — your application database is not touched.

!!! warning "Not for Collections"
    Each `can()` call creates a temporary in-memory evaluation context. Use `authorize_query()` for filtering collections — it generates a single SQL query regardless of how many rows exist.

---

## Session Interception

If calling `authorize_query()` on every statement is too repetitive, you can authorize all SELECTs automatically via SQLAlchemy's `do_orm_execute` event:

```python
from sqla_authz import authorized_sessionmaker

SessionLocal = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_user,
    action="read",
)

with SessionLocal() as session:
    # Every SELECT is authorized — no explicit authorize_query() needed
    posts = session.execute(select(Post)).scalars().all()
```

Skip authorization for specific queries:

```python
session.execute(select(Post).execution_options(skip_authz=True))
```

Override the action per-query:

```python
session.execute(select(Post).execution_options(authz_action="update"))
```

For lower-level control, use `install_interceptor()` on an existing sessionmaker.

The interceptor uses `with_loader_criteria()` to propagate filters to relationship loads (`selectinload`, `joinedload`, lazy loads), so related objects are filtered consistently.

!!! warning "Start Explicit"
    Automatic interception silently filters rows, which can be surprising. Start with `authorize_query()` to understand where authorization boundaries are, then switch to interception once you're confident in your policies.

---

## Configuration

Global configuration via `configure()`:

```python
from sqla_authz import configure

configure(
    on_missing_policy="raise",  # NoPolicyError instead of silent deny
    default_action="read",
    log_policy_decisions=True,
)
```

| Field | Default | Description |
|-------|---------|-------------|
| `on_missing_policy` | `"deny"` | No policy registered: `"deny"` appends `WHERE FALSE`; `"raise"` throws `NoPolicyError` |
| `default_action` | `"read"` | Action used by session interception when none is specified |
| `on_unknown_action` | `"ignore"` | Action not found in registry: `"ignore"` silent (backward compatible); `"warn"` logs with suggestions; `"raise"` throws `UnknownActionError` |
| `log_policy_decisions` | `False` | Emit audit log entries on the `"sqla_authz"` logger |

Use `"raise"` during development to catch models that don't have policies yet. Switch to `"deny"` in production for fail-closed behavior.

Configuration resolves in three layers: **Global** (`configure()`) → **Session** (`authorized_sessionmaker`) → **Query** (`execution_options`). Use `AuthzConfig.merge()` for selective overrides.

---

## Predicates

When the same condition appears across multiple policies — "is the actor the owner?" — extract it into a reusable predicate:

```python
from sqla_authz.policy._predicate import predicate

is_owner = predicate(lambda actor: Document.owner_id == actor.id)
is_team_member = predicate(lambda actor: Document.team_id == actor.team_id)
is_public = predicate(lambda actor: Document.visibility == "public")

@policy(Document, "read", predicate=is_public | is_team_member | is_owner)
def doc_read(actor): ...

@policy(Document, "delete", predicate=is_owner)
def doc_delete(actor): ...
```

Predicates support `&` (AND), `|` (OR), and `~` (NOT) operators. Built-in predicates: `always_allow` (`true()`) and `always_deny` (`false()`).

Use predicates when you share conditions across multiple policies. For one-off rules, inline `@policy` functions are simpler.

---

## Audit Logging

Enable with `configure(log_policy_decisions=True)`. Entries are emitted on the `"sqla_authz"` logger:

| Level | Content |
|-------|---------|
| `INFO` | Policy matched — entity, action, actor, policy count |
| `DEBUG` | Same as INFO + policy names + compiled filter expression |
| `WARNING` | No policy found for `(model, action)` |

Recommended log levels: `WARNING` in production (catch misconfigurations), `INFO` in staging, `DEBUG` in development.
