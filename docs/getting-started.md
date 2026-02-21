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
from sqla_authz import policy


@policy(Post, "read")
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
from sqla_authz import authorize_query

stmt = select(Post).order_by(Post.id)
stmt = authorize_query(stmt, actor=current_user, action="read")
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
    No registered policy for a `(model, action)` pair? The query gets `WHERE FALSE` — zero rows returned, not a data leak. Set `on_missing_policy="raise"` to get a `NoPolicyError` instead. See [Configuration](guide.md#configuration).

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

### Three Entry Points

Pick the level of control that fits your application:

1. **Explicit** — `authorize_query(stmt, actor, action)`. You call it before every query. Full visibility and control. **Start here.**
2. **Automatic** — `authorized_sessionmaker()` wraps your session so every SELECT is authorized via SQLAlchemy's `do_orm_execute` event. Less boilerplate, but authorization happens invisibly. See [Session Interception](guide.md#session-interception).
3. **Framework** — `AuthzDep` for FastAPI. Authorization is handled in the dependency injection layer. See [Integrations](integrations.md).

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
