# Flask

## Installation

```bash
pip install sqla-authz[flask]
```

## Basic Setup

`AuthzExtension` integrates sqla-authz with Flask by providing `authorize_query()` within request context and registering error handlers.

```python
from flask import Flask
from sqla_authz.integrations.flask import AuthzExtension

app = Flask(__name__)
authz = AuthzExtension(
    app,
    actor_provider=lambda: get_current_user(),
)
```

## App Factory Pattern

```python
authz = AuthzExtension(actor_provider=lambda: get_current_user())

def create_app():
    app = Flask(__name__)
    authz.init_app(app)
    return app
```

## Authorizing Queries

Use `authz.authorize_query()` in your view functions:

```python
from sqlalchemy import select

@app.get("/posts")
def list_posts():
    stmt = select(Post)
    stmt = authz.authorize_query(stmt)
    posts = db.session.execute(stmt).scalars().all()
    return jsonify([{"id": p.id, "title": p.title} for p in posts])

@app.get("/posts/<int:post_id>")
def get_post(post_id):
    stmt = select(Post).where(Post.id == post_id)
    stmt = authz.authorize_query(stmt, action="read")
    post = db.session.execute(stmt).scalar_one_or_none()
    if post is None:
        abort(404)
    return jsonify({"id": post.id, "title": post.title})
```

## Error Handling

`AuthzExtension` automatically registers error handlers when initialized:

| Exception | HTTP Status | Response |
|-----------|-------------|----------|
| `AuthorizationDenied` | 403 Forbidden | `{"detail": "Actor ... is not authorized to ..."}` |
| `NoPolicyError` | 500 Internal Server Error | `{"detail": "No policy registered for (...)"}` |

## Custom Action Per Route

Override the default action for specific queries:

```python
@app.post("/posts/<int:post_id>")
def update_post(post_id):
    stmt = select(Post).where(Post.id == post_id)
    stmt = authz.authorize_query(stmt, action="update")
    post = db.session.execute(stmt).scalar_one_or_none()
    if post is None:
        abort(404)
    # ... update logic
```

## Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `Flask \| None` | `None` | Flask app. If provided, calls `init_app()`. |
| `actor_provider` | `Callable[[], ActorLike]` | required | Returns current actor in request context. |
| `default_action` | `str` | `"read"` | Default action when none specified. |
| `registry` | `PolicyRegistry \| None` | `None` | Custom registry. Defaults to global. |
| `config` | `AuthzConfig \| None` | `None` | Custom config. Defaults to global. |

## Complete Example

```python
from flask import Flask, jsonify, abort, request
from sqlalchemy import ColumnElement, create_engine, or_, select, true, false
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqla_authz import policy
from sqla_authz.integrations.flask import AuthzExtension


# --- Models ---
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    role: Mapped[str] = mapped_column(default="viewer")

class Post(Base):
    __tablename__ = "posts"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    author_id: Mapped[int]
    is_published: Mapped[bool] = mapped_column(default=False)


# --- Policies ---
@policy(Post, "read")
def post_read(actor) -> ColumnElement[bool]:
    return or_(Post.is_published == True, Post.author_id == actor.id)


# --- App ---
engine = create_engine("sqlite:///app.db")
SessionLocal = sessionmaker(bind=engine)

def get_current_user():
    # Replace with your authentication logic
    user_id = request.headers.get("X-User-Id", "1")
    with SessionLocal() as session:
        return session.get(User, int(user_id))

app = Flask(__name__)
authz = AuthzExtension(app, actor_provider=get_current_user)

@app.get("/posts")
def list_posts():
    with SessionLocal() as session:
        stmt = select(Post)
        stmt = authz.authorize_query(stmt)
        posts = session.execute(stmt).scalars().all()
        return jsonify([{"id": p.id, "title": p.title} for p in posts])
```

!!! tip "Use authorize_query() Directly"
    You can also use the core `authorize_query()` function directly in Flask views without the extension. The extension simply provides request-context integration and error handlers.
