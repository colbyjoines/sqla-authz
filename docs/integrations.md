# Integrations

## FastAPI

```bash
pip install sqla-authz[fastapi]
```

### Direct Pattern

Call `authorize_query()` in each endpoint — simple, explicit, no setup:

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

For single-item endpoints, return **404** (not 403) to avoid revealing resource existence.

### AuthzDep

Register providers once at startup, then use `AuthzDep` as a dependency:

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

## Flask

```bash
pip install sqla-authz[flask]
```

### Setup

```python
from sqla_authz.integrations.flask import AuthzExtension

authz = AuthzExtension(app, actor_provider=lambda: get_current_user())

# Or with the app factory pattern:
authz = AuthzExtension(actor_provider=lambda: get_current_user())
authz.init_app(app)
```

### Usage

```python
@app.get("/posts")
def list_posts():
    stmt = authz.authorize_query(select(Post))
    posts = db.session.execute(stmt).scalars().all()
    return jsonify([{"id": p.id, "title": p.title} for p in posts])
```

Override the action per-route with `authz.authorize_query(stmt, action="update")`.

`AuthzExtension` automatically registers error handlers mapping `AuthorizationDenied` to 403 and `NoPolicyError` to 500.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `actor_provider` | `Callable[[], ActorLike]` | required | Returns current actor in request context |
| `default_action` | `str` | `"read"` | Default action when none specified |
| `registry` | `PolicyRegistry \| None` | `None` | Custom registry (defaults to global) |
| `config` | `AuthzConfig \| None` | `None` | Custom config (defaults to global) |
