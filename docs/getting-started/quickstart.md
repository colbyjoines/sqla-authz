# Quick Start

**The problem**: You need row-level authorization — users should only see the rows they are allowed to see. Rolling this by hand means scattering `WHERE author_id = :user_id` clauses across your codebase and hoping nothing slips through.

**The solution**: Declare your rules once as Python functions. sqla-authz compiles them into SQL `WHERE` clauses automatically, every time, for every query.

---

## 1. Define Your Models

Use standard SQLAlchemy 2.0 declarative models. Nothing special is required.

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

## 2. Write a Policy

Decorate a function with `@policy(Model, "action")`. The function receives the current actor and returns a SQLAlchemy `ColumnElement[bool]` — the same filter expression you would pass to `.where()` by hand.

```python
from sqlalchemy import ColumnElement, or_
from sqla_authz import policy


@policy(Post, "read")
def post_read_policy(actor) -> ColumnElement[bool]:
    """Anyone can read published posts. Authors can read their own drafts."""
    return or_(
        Post.is_published == True,
        Post.author_id == actor.id,
    )
```

The policy is registered globally at import time. It applies whenever `authorize_query()` is called for `(Post, "read")`.

## 3. Authorize a Query

Call `authorize_query()` before executing any `select()` statement. Pass the current actor and the action being performed.

```python
from sqlalchemy import select
from sqla_authz import authorize_query

stmt = select(Post).order_by(Post.id)
stmt = authorize_query(stmt, actor=current_user, action="read")
```

`authorize_query()` returns a new statement with the policy applied as a `WHERE` clause. The original `stmt` is not mutated.

## 4. See the SQL

The compiled query includes a `WHERE` clause derived from your policy:

```sql
SELECT posts.id, posts.title, posts.author_id, posts.is_published
FROM posts
WHERE (posts.is_published = true OR posts.author_id = :author_id_1)
ORDER BY posts.id
```

No joins, no subselects on the outer query — just a clean `WHERE` predicate.

!!! info "Sync Compilation"
    `authorize_query()` is always synchronous. It builds filter expressions using Python alone, with no database I/O. The same call works identically for `Session` and `AsyncSession`.

---

## 5. Complete Example

=== "Sync"

    ```python
    from sqlalchemy import ColumnElement, create_engine, or_, select
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
    from sqla_authz import policy, authorize_query


    class Base(DeclarativeBase):
        pass


    class Post(Base):
        __tablename__ = "posts"

        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str]
        author_id: Mapped[int]
        is_published: Mapped[bool] = mapped_column(default=False)


    @policy(Post, "read")
    def post_read(actor) -> ColumnElement[bool]:
        """Published posts are visible to all. Drafts only to their author."""
        return or_(Post.is_published == True, Post.author_id == actor.id)


    # Setup
    engine = create_engine("sqlite:///app.db")
    Base.metadata.create_all(engine)


    class User:
        def __init__(self, id: int) -> None:
            self.id = id


    current_user = User(id=42)

    # Seed some data
    with Session(engine) as session:
        session.add_all([
            Post(title="Public post", author_id=1, is_published=True),
            Post(title="My draft", author_id=42, is_published=False),
            Post(title="Someone else's draft", author_id=99, is_published=False),
        ])
        session.commit()

    # Query with authorization — only sees the first two rows
    with Session(engine) as session:
        stmt = select(Post)
        stmt = authorize_query(stmt, actor=current_user, action="read")
        posts = session.execute(stmt).scalars().all()
        # posts == [Post("Public post"), Post("My draft")]
    ```

=== "Async"

    ```python
    import asyncio
    from sqlalchemy import ColumnElement, or_, select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from sqla_authz import policy, authorize_query


    class Base(DeclarativeBase):
        pass


    class Post(Base):
        __tablename__ = "posts"

        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str]
        author_id: Mapped[int]
        is_published: Mapped[bool] = mapped_column(default=False)


    @policy(Post, "read")
    def post_read(actor) -> ColumnElement[bool]:
        """Published posts are visible to all. Drafts only to their author."""
        return or_(Post.is_published == True, Post.author_id == actor.id)


    engine = create_async_engine("sqlite+aiosqlite:///app.db")


    class User:
        def __init__(self, id: int) -> None:
            self.id = id


    async def get_posts(current_user: User) -> list[Post]:
        # authorize_query() is sync — build the statement before awaiting
        stmt = select(Post)
        stmt = authorize_query(stmt, actor=current_user, action="read")

        async with AsyncSession(engine) as session:
            result = await session.execute(stmt)
            return list(result.scalars().all())


    async def main() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        current_user = User(id=42)
        posts = await get_posts(current_user)
        print(posts)


    asyncio.run(main())
    ```

!!! tip "Deny by Default"
    If no policy is registered for a `(model, action)` pair, sqla-authz appends `WHERE FALSE` and returns zero rows. There is no accidental data leak from a missing policy. To raise an error instead, see [Configuration](../guide/configuration.md).

---

## Next Steps

- [Core Concepts](concepts.md) — understand how the pieces fit together
- [Writing Policies](../guide/policies.md) — compound rules, role checks, relationship traversal
- [Point Checks](../guide/point-checks.md) — `can()` and `authorize()` for single resources
- [FastAPI Integration](../integrations/fastapi.md) — `AuthzDep` for dependency injection
