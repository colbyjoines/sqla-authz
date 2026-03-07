# Getting Started

## Installation

Requires Python 3.10+ and SQLAlchemy 2.0+. No external servers or sidecars.

=== "pip"

    ```bash
    pip install sqla-authz
    ```

=== "uv"

    ```bash
    uv add sqla-authz
    ```

Optional extras:

| Extra | Use when |
|---|---|
| `sqla-authz[fastapi]` | Building FastAPI apps with `AuthzDep` |
| `sqla-authz[testing]` | Writing tests with mock actors and assertion helpers |
| `sqla-authz[all]` | All optional dependencies |

---

## Quick Start

### 1. Define your models

Standard SQLAlchemy 2.0 declarative models — sqla-authz doesn't require a base class or mixin.

```python
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(default="member")
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"))


class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    is_published: Mapped[bool] = mapped_column(default=False)
    author: Mapped[User] = relationship()
```

### 2. Write a policy

A policy is a function decorated with `@policy(Model, "action")`. It receives the current actor and returns a SQLAlchemy `ColumnElement[bool]` — the same type you'd pass to `.where()`.

```python
from sqlalchemy import ColumnElement, or_, true
from sqla_authz import policy, READ


@policy(Post, READ)  # or @policy(Post, "read") -- bare strings still work
def post_read_policy(actor: User) -> ColumnElement[bool]:
    # Admins see everything
    if actor.role == "admin":
        return true()
    # Everyone else sees published posts and their own drafts
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

The policy is registered globally at import time. At query time, it's called with the current actor, and the returned expression becomes a WHERE clause.

Because policies are plain Python, you can use any control flow — `if`/`else`, early returns, helper functions. Role checks happen in Python; row-level conditions become SQL.

### 3. Authorize a query

```python
from sqlalchemy import select
from sqla_authz import authorize_query, READ

stmt = select(Post).order_by(Post.id)
stmt = authorize_query(stmt, actor=current_user, action=READ)
posts = session.execute(stmt).scalars().all()
```

The generated SQL:

```sql
SELECT posts.id, posts.title, posts.author_id, posts.is_published
FROM posts
WHERE (posts.is_published = true OR posts.author_id = :author_id_1)
ORDER BY posts.id
```

`authorize_query()` is synchronous — it builds filter expressions in memory with no database I/O. The same call works with both `Session` and `AsyncSession`.

!!! info "Deny by Default"
    No registered policy for a `(model, action)` pair? The query gets `WHERE FALSE` — zero rows returned, not a data leak. Set `on_missing_policy="raise"` to get a `NoPolicyError` instead. See [Configuration](#configuration).

---

## Core Concepts

### The Registry

`PolicyRegistry` maps `(Model, action)` pairs to policy functions. When multiple policies exist for the same key, they're OR'd together — if any policy grants access, the row is returned:

```python
@policy(Post, "read")
def published_posts(actor: User) -> ColumnElement[bool]:
    return Post.is_published == True


@policy(Post, "read")
def own_posts(actor: User) -> ColumnElement[bool]:
    return Post.author_id == actor.id

# Effective filter: WHERE is_published = true OR author_id = :id
```

This lets you compose rules from separate modules without coordination — each module registers its own policies, and they combine automatically.

Action constants like `READ` and `UPDATE` prevent typo bugs that silently return zero rows. See the [API Reference](reference/api.md) for details.

### Three Entry Points

Pick the level of control that fits your application:

1. **Explicit** — `authorize_query(stmt, actor, action)`. You call it before every query. Full visibility and control. **Start here.**
2. **Automatic** — `authorized_sessionmaker()` wraps your session so every SELECT is authorized via SQLAlchemy's `do_orm_execute` event. Less boilerplate, but authorization happens invisibly. See [Session Interception](#session-interception).
3. **Framework** — `AuthzDep` for FastAPI. Authorization is handled in the dependency injection layer. See [FastAPI](#fastapi).

### ActorLike Protocol

Any object with an `.id` attribute satisfies the `ActorLike` protocol — SQLAlchemy models, dataclasses, Pydantic models, or a plain `SimpleNamespace`. No base class required.

```python
from dataclasses import dataclass

@dataclass
class User:
    id: int
    role: str
    team_id: int | None = None
```

Your policies reference `actor.whatever` — add whatever attributes your policies need. The library only requires `.id` for type safety; everything else is up to you.

---

## Scopes

### The Multi-Tenant Problem

In a multi-tenant app, every policy must include a tenant filter. Forgetting it on one model leaks data across tenants.

```python
@policy(Post, READ)
def post_read(actor: User) -> ColumnElement[bool]:
    return (Post.org_id == actor.org_id) & (Post.is_published == True)

@policy(Comment, READ)
def comment_read(actor: User) -> ColumnElement[bool]:
    return Comment.org_id == actor.org_id  # easy to forget on new models
```

### Defining a Scope

Scopes are cross-cutting filters AND'd with all policies for matching models:

```python
from sqla_authz import scope

@scope(applies_to=[Post, Comment, Document])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    return Model.org_id == actor.org_id
```

Now individual policies only express their own logic — the tenant filter is automatic.

### How Scopes Compose

```
final_filter = (policy_1 OR policy_2) AND scope_1 AND scope_2
```

- **Policies grant access** — if any policy matches, the row is a candidate
- **Scopes restrict access** — all scopes must match for the row to be returned
- **No policy = no access** — scopes cannot override the deny-by-default rule

To bypass a scope for admin users, return `true()`:

```python
from sqlalchemy import true

@scope(applies_to=[Post, Comment])
def tenant(actor: User, Model: type) -> ColumnElement[bool]:
    if actor.role == "admin":
        return true()
    return Model.org_id == actor.org_id
```

### Catching Missing Scopes

```python
from sqla_authz import verify_scopes

# In your app startup (e.g., create_app(), FastAPI lifespan)
verify_scopes(Base, field="org_id")
# UnscopedModelError if any model has org_id but no registered scope
```

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
```

Point checks reuse your `@policy` functions. They evaluate the policy expression against the object's attributes in memory — no database round-trip.

!!! warning "Operator Limitations"
    Point checks support common operators (`==`, `!=`, `<`, `>`, `in_`, `has()`, `any()`, etc.) but not SQL functions like `func.lower()` or database-specific operators. Mark such policies with `query_only=True` to get a clear error. See [Limitations](limitations.md) for the full operator list.

---

## Session Interception

If calling `authorize_query()` on every statement is too repetitive, authorize all SELECTs automatically:

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

!!! warning "Start Explicit"
    Automatic interception silently filters rows, which can be surprising. Start with `authorize_query()` to understand where authorization boundaries are, then switch to interception once you're confident in your policies.

---

## Configuration

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
| `on_unknown_action` | `"ignore"` | Action not found in registry: `"ignore"` silent; `"warn"` logs with suggestions; `"raise"` throws `UnknownActionError` |
| `log_policy_decisions` | `False` | Emit audit log entries on the `"sqla_authz"` logger |

---

## FastAPI

```bash
pip install sqla-authz[fastapi]
```

### Direct Pattern

Call `authorize_query()` in each endpoint:

```python
from sqla_authz import authorize_query

@app.get("/posts")
async def list_posts(
    actor: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[PostSchema]:
    stmt = authorize_query(select(Post), actor=actor, action="read")
    result = await session.execute(stmt)
    return result.scalars().all()
```

### AuthzDep

Inject authorized results directly into endpoints:

```python
from sqla_authz.integrations.fastapi import AuthzDep, configure_authz, install_error_handlers

configure_authz(
    app=app,
    get_actor=lambda request: request.state.user,
    get_session=lambda request: request.state.session,
)
install_error_handlers(app)

@app.get("/posts")
async def list_posts(posts: list[Post] = AuthzDep(Post, "read")) -> list[dict]:
    return [{"id": p.id, "title": p.title} for p in posts]

@app.get("/posts/{post_id}")
async def get_post(post: Post = AuthzDep(Post, "read", id_param="post_id")) -> dict:
    return {"id": post.id, "title": post.title}
```

`install_error_handlers()` maps `AuthorizationDenied` to 403 and `NoPolicyError` to 500.

---

## Testing

```bash
pip install sqla-authz[testing]
```

### Mock Actors

Lightweight actors for testing without real user records:

```python
from sqla_authz.testing import MockActor, make_admin, make_user, make_anonymous

admin = make_admin()                                  # id=1, role="admin"
user = make_user(id=7, role="editor", org_id=5)       # custom attributes
anon = make_anonymous()                               # id=0, role="anonymous"
```

### Assertion Helpers

```python
from sqla_authz.testing import assert_authorized, assert_denied, assert_query_contains

# Verify that a query returns rows for this actor
assert_authorized(session, select(Post), actor=make_admin(), action="read",
                  expected_count=3, registry=authz_registry)

# Verify that a query returns zero rows
assert_denied(session, select(Post), actor=make_anonymous(), action="read",
              registry=authz_registry)

# Check the compiled SQL without executing it
assert_query_contains(select(Post), actor=make_user(id=42), action="read",
                      text="author_id = 42", registry=authz_registry)
```

### Pytest Fixtures

Fixtures are auto-discovered via the `pytest11` entry point — no imports needed.

- **`authz_registry`** — Fresh, empty `PolicyRegistry` for each test. Prevents policy leaks between tests.
- **`authz_config`** — Returns the default `AuthzConfig`.
- **`isolated_authz_state`** — Saves and restores the global registry state around a test.

!!! tip "Registry Isolation"
    Always use a per-test `PolicyRegistry` (the `authz_registry` fixture or a local instance). Module-level `@policy` decorators register to the global registry, which persists across tests.
