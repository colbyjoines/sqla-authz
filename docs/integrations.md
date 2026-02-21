# Integrations

## FastAPI

```bash
pip install sqla-authz[fastapi]
```

Two patterns are available. Choose based on how much control you need over queries.

### Direct Pattern

Call `authorize_query()` in each endpoint. Use this when you need custom query logic (joins, filters, ordering) alongside authorization:

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

For single-item endpoints, return **404** (not 403) when the authorized query returns nothing — this avoids revealing whether the resource exists.

### AuthzDep

Register providers once at startup, then inject authorized results directly into endpoints. Use this for straightforward CRUD where you don't need custom query logic:

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
