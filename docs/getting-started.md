# Getting Started

## Installation

Requires Python 3.10+ and SQLAlchemy 2.0+. No external server dependencies.

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
| `sqla-authz[fastapi]` | Building FastAPI apps |
| `sqla-authz[testing]` | Writing tests with built-in fixtures |
| `sqla-authz[all]` | All optional dependencies |

---

## Quick Start

### 1. Define your models

Standard SQLAlchemy 2.0 declarative models. Nothing special required.

```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    author_id: Mapped[int]
    is_published: Mapped[bool] = mapped_column(default=False)
```

### 2. Write a policy

Decorate a function with `@policy(Model, "action")`. It receives the current actor and returns a SQLAlchemy `ColumnElement[bool]`.

```python
from sqlalchemy import ColumnElement, or_
from sqla_authz import policy


@policy(Post, "read")
def post_read_policy(actor) -> ColumnElement[bool]:
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

The policy is registered globally at import time and evaluated lazily per-request.

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

`authorize_query()` is always synchronous — it builds filter expressions with no database I/O. The same call works with both `Session` and `AsyncSession`.

!!! info "Deny by Default"
    No registered policy for a `(model, action)` pair? The query gets `WHERE FALSE` — zero rows returned. Configure `on_missing_policy="raise"` to get `NoPolicyError` instead. See [Configuration](guide.md#configuration).

---

## Core Concepts

### The Registry

`PolicyRegistry` maps `(Model, action)` pairs to policy functions. Multiple policies for the same key are OR'd together:

```python
@policy(Post, "read")
def published_posts(actor) -> ColumnElement[bool]:
    return Post.is_published == True


@policy(Post, "read")
def own_posts(actor) -> ColumnElement[bool]:
    return Post.author_id == actor.id

# Effective filter: is_published OR author_id = :id
```

### Three Entry Points

1. **Explicit** — `authorize_query()` before executing any statement. Full control. Recommended starting point.
2. **Automatic** — `authorized_sessionmaker()` wraps your session factory so every SELECT is authorized via `do_orm_execute`. See [Session Interception](guide.md#session-interception).
3. **Framework** — `AuthzDep` (FastAPI). See [Integrations](integrations.md).

### ActorLike Protocol

Any object with an `.id` attribute works as an actor — dataclass, Pydantic model, ORM model, or `SimpleNamespace`. No base class required.

```python
from dataclasses import dataclass

@dataclass
class User:
    id: int
    role: str
```
