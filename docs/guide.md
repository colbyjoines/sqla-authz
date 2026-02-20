# Guide

## Policies

A policy is a Python function decorated with `@policy(Model, "action")` that returns a `ColumnElement[bool]` — the same filter expression you'd pass to `.where()`.

### Defining Policies

```python
from sqlalchemy import ColumnElement
from sqla_authz import policy

@policy(Post, "read")
def post_read(actor) -> ColumnElement[bool]:
    return Post.is_published == True
```

Policies must be **synchronous** and must not perform I/O. The expression is built in memory and handed to SQLAlchemy.

### Python Control Flow

Policies are plain functions — any control flow is valid:

```python
from sqlalchemy import true, or_

@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

### Multiple Policies

Multiple `@policy` decorators for the same `(Model, action)` are OR'd together automatically, letting you compose rules from separate modules.

### true() and false()

`sqlalchemy.true()` allows all rows. `sqlalchemy.false()` denies all rows. Useful for admin bypass and temporary lockdowns.

### Custom Registries

For test isolation or multi-tenant apps, create a dedicated `PolicyRegistry`:

```python
from sqla_authz.policy import PolicyRegistry

tenant_registry = PolicyRegistry()

@policy(Post, "read", registry=tenant_registry)
def post_read(actor) -> ColumnElement[bool]:
    return Post.org_id == actor.org_id

stmt = authorize_query(select(Post), actor=user, action="read", registry=tenant_registry)
```

---

## Relationship Traversal

Authorization rules often depend on related models. Use SQLAlchemy's `has()` (many-to-one) and `any()` (one-to-many / many-to-many) for EXISTS subqueries:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.author.has(User.org_id == actor.org_id)
```

Generated SQL:

```sql
WHERE EXISTS (
    SELECT 1 FROM user
    WHERE user.id = post.author_id AND user.org_id = :org_id
)
```

Multi-hop traversal nests naturally:

```python
@policy(Post, "read")
def post_read(actor: User) -> ColumnElement[bool]:
    return Post.author.has(
        User.organization.has(Organization.id == actor.org_id)
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

## Point Checks

`can()` and `authorize()` answer a binary question about a single, already-loaded object:

```python
from sqla_authz import can, authorize

if can(actor, "delete", post):
    session.delete(post)

# Or the raising variant:
authorize(actor, "edit", post)  # raises AuthorizationDenied on failure
authorize(actor, "edit", post, message="Only editors can edit.")
```

Point checks reuse your `@policy` functions. They evaluate against an in-memory SQLite database — your application database is not touched.

!!! warning "Don't Use in Loops"
    Each call creates a temporary SQLite database. Use `authorize_query()` for collections.

---

## Session Interception

Automatically authorize every SELECT via SQLAlchemy's `do_orm_execute` event:

```python
from sqla_authz import authorized_sessionmaker

SessionLocal = authorized_sessionmaker(
    bind=engine,
    actor_provider=get_current_user,
    action="read",
)

with SessionLocal() as session:
    posts = session.execute(select(Post)).scalars().all()  # auto-authorized
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

The interceptor uses `with_loader_criteria()` to propagate filters to relationship loads (`selectinload`, `joinedload`, lazy loads).

!!! warning
    Automatic interception can be surprising — authorization silently filters rows. Start with `authorize_query()` and switch to interception once you understand query boundaries.

---

## Configuration

All configuration is in `AuthzConfig`, set globally with `configure()`:

```python
from sqla_authz import configure

configure(
    on_missing_policy="raise",  # "deny" (default) or "raise"
    default_action="read",
    log_policy_decisions=True,
)
```

| Field | Default | Description |
|-------|---------|-------------|
| `on_missing_policy` | `"deny"` | `"deny"` appends `WHERE FALSE`; `"raise"` throws `NoPolicyError` |
| `default_action` | `"read"` | Default action for session interception |
| `log_policy_decisions` | `False` | Emit audit log entries on the `"sqla_authz"` logger |

Configuration resolves in three layers: **Global** (`configure()`) → **Session** (`authorized_sessionmaker`) → **Query** (`execution_options`). Use `AuthzConfig.merge()` for selective overrides.

---

## Predicates

Reusable authorization building blocks with `&`, `|`, `~` composition:

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

Built-in predicates: `always_allow` (`true()`) and `always_deny` (`false()`).

Use predicates when you have reusable conditions across multiple policies. For one-off policies, inline `@policy` functions are simpler.

---

## Audit Logging

Enable with `configure(log_policy_decisions=True)`. Records are emitted on the `"sqla_authz"` logger:

| Level | When |
|-------|------|
| `INFO` | Policy matched — entity, action, actor, policy count |
| `DEBUG` | Same as INFO + policy names + compiled filter expression |
| `WARNING` | No policy found for `(model, action)` |

Recommended levels: `WARNING` in production, `INFO` in staging, `DEBUG` in development.
