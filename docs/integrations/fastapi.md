# FastAPI

sqla-authz integrates with FastAPI through two complementary patterns: a direct `authorize_query()` call inside each route (simple, explicit), and the `AuthzDep` convenience layer that wires actor resolution and session management once, globally.

---

## Installation

```bash
pip install sqla-authz[fastapi]
```

This adds `fastapi` as a dependency alongside the core library.

---

## Basic Pattern

No special adapter is needed for basic use. Call `authorize_query()` directly inside each endpoint. This is the recommended starting point — it keeps authorization visible at the call site and requires no upfront configuration.

```python title="Direct authorize_query() in endpoints"
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqla_authz import authorize_query

app = FastAPI()


@app.get("/posts")
async def list_posts(
    actor: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> list[PostSchema]:
    stmt = select(Post)
    stmt = authorize_query(stmt, actor=actor, action="read")
    posts = session.execute(stmt).scalars().all()
    return [PostSchema.from_orm(p) for p in posts]
```

For single-item endpoints, return 404 — not 403 — when an item is not found or not authorized. Returning 403 reveals that the resource exists, which is an information leak.

```python title="Single-item endpoint — always 404, never 403"
@app.get("/posts/{post_id}")
async def get_post(
    post_id: int,
    actor: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> PostSchema:
    stmt = select(Post).where(Post.id == post_id)
    stmt = authorize_query(stmt, actor=actor, action="read")
    post = session.execute(stmt).scalars().first()
    if post is None:
        raise HTTPException(status_code=404, detail="Not found")
    return PostSchema.from_orm(post)
```

!!! warning "Single Item Security"
    Always return `404` (not `403`) for single-item lookups. Returning `403` tells an attacker that the resource exists but is forbidden — leaking information about other users' data. A `404` response is indistinguishable from a missing resource.

---

## AuthzDep Convenience Layer

Once you have several endpoints following the same pattern, `AuthzDep` removes the boilerplate. Register your actor and session providers once at startup, then use `AuthzDep(Model, "action")` as a dependency in any route.

### Setup

Call `configure_authz()` once when the application starts:

```python title="Application startup"
from fastapi import FastAPI, Request
from sqla_authz.integrations.fastapi import configure_authz, install_error_handlers

app = FastAPI()

configure_authz(
    app=app,
    get_actor=lambda request: get_current_user(request),
    get_session=lambda request: get_db(request),
)
```

`get_actor` and `get_session` are plain callables that receive the `Request` object and return the actor and session respectively. They run synchronously inside the dependency resolver.

### Collection Endpoints

`AuthzDep(Model, action)` without `id_param` returns a list of all authorized instances:

```python title="Collection endpoint"
from sqla_authz.integrations.fastapi import AuthzDep


@app.get("/posts")
async def list_posts(
    posts: list[Post] = AuthzDep(Post, "read"),
) -> list[PostSchema]:
    return [PostSchema.from_orm(p) for p in posts]
```

The dependency resolves the actor and session from `app.state`, builds the authorized query, executes it, and injects the result list directly into the route function.

### Single Item Endpoints

Set `id_param` to the name of the path parameter that holds the primary key. The dependency fetches a single row and raises `404` if it does not exist or is not authorized:

```python title="Single-item endpoint"
@app.get("/posts/{post_id}")
async def get_post(
    post: Post = AuthzDep(Post, "read", id_param="post_id"),
) -> PostSchema:
    return PostSchema.from_orm(post)
```

The path parameter name passed to `id_param` must match the `{…}` placeholder in the route path exactly.

---

## Error Handlers

`install_error_handlers()` registers exception handlers that convert sqla-authz exceptions into appropriate HTTP responses:

```python title="Registering error handlers"
from sqla_authz.integrations.fastapi import install_error_handlers

install_error_handlers(app)
```

| Exception | HTTP Status | When it occurs |
|-----------|-------------|----------------|
| `AuthorizationDenied` | `403 Forbidden` | Raised explicitly by a policy via `authorize()` or `can()` |
| `NoPolicyError` | `500 Internal Server Error` | No policy registered for `(model, action)` and `on_missing="raise"` is configured |

!!! info "Default Behaviour Without Error Handlers"
    Without `install_error_handlers()`, unhandled `AuthorizationDenied` or `NoPolicyError` exceptions propagate as `500` responses. Install the handlers in production to get correctly typed error responses.

---

## Complete Example

A self-contained FastAPI application demonstrating both patterns:

```python title="Complete FastAPI application"
from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy import ColumnElement, create_engine, or_, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqla_authz import authorize_query, policy
from sqla_authz.integrations.fastapi import AuthzDep, configure_authz, install_error_handlers


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
    return or_(Post.is_published == True, Post.author_id == actor.id)


engine = create_engine("sqlite:///app.db")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

app = FastAPI()
install_error_handlers(app)

configure_authz(
    app=app,
    get_actor=lambda request: request.state.user,
    get_session=lambda request: request.state.session,
)


# --- Direct pattern ---

@app.get("/posts/mine")
async def my_posts(
    actor=Depends(lambda r: r.state.user),
    session: Session = Depends(lambda r: r.state.session),
) -> list[dict]:
    stmt = authorize_query(select(Post), actor=actor, action="read")
    posts = session.execute(stmt).scalars().all()
    return [{"id": p.id, "title": p.title} for p in posts]


# --- AuthzDep pattern ---

@app.get("/posts")
async def list_posts(posts: list[Post] = AuthzDep(Post, "read")) -> list[dict]:
    return [{"id": p.id, "title": p.title} for p in posts]


@app.get("/posts/{post_id}")
async def get_post(post: Post = AuthzDep(Post, "read", id_param="post_id")) -> dict:
    return {"id": post.id, "title": post.title}
```

---

## Why Not Middleware?

Authorization cannot be applied in middleware because middleware runs before routing — at that point there is no model class or action name to look up a policy. sqla-authz policies are bound to `(Model, action)` pairs, which are only known inside individual route handlers.

Middleware-level authorization is limited to coarse checks (e.g., "is the user authenticated?"). Row-level authorization — "which rows is this user allowed to see?" — requires route context and belongs in the dependency layer.

!!! tip "Start Simple"
    Use `authorize_query()` directly in each route first. Move to `AuthzDep` once you notice the same actor-resolution and session-wiring boilerplate appearing in multiple routes.
