# Plan 05: FastAPI Integration Rewrite

## Problem Statement

The FastAPI integration is a "checkbox feature" that doesn't expose the library's
core value proposition (the `do_orm_execute` interceptor with `with_loader_criteria`).
It has correctness bugs and design issues that make it unsuitable for production use.

> **Note:** The Flask integration has been removed from scope. Focus is exclusively on FastAPI.

### FastAPI Issues

1. **Sync `session.execute()` in async context** (`_dependencies.py:86`). `_resolve()` is
   `async def` but calls `session.execute()` synchronously. With `AsyncSession` this blocks
   the event loop; with sync `Session` under `anyio` it still blocks the worker thread.
2. **Hardcoded PK column to `model.id`** (`_dependencies.py:81`). `getattr(model, "id")`
   fails for models with composite PKs, non-`id` PK names (e.g. `uuid`, `slug`), or
   column-property mismatches.
3. **`configure_authz()` stores state on `app.state`** -- rigid, doesn't compose with
   FastAPI's dependency injection. Users can't override actor/session per-route via
   `Depends()`.
4. **No interceptor integration** -- the library's best feature (`install_interceptor` /
   `authorized_sessionmaker`) is not exposed at all. Users must manually call
   `authorize_query()` for every statement.

---

## Design: FastAPI Rewrite

### New Module Layout

```
src/sqla_authz/integrations/fastapi/
    __init__.py          # re-exports, import guard
    _dependencies.py     # AuthzDep (rewritten), new helpers
    _errors.py           # install_error_handlers (unchanged)
    _middleware.py        # NEW: AuthzMiddleware for interceptor integration
```

### 1. Async-Native `AuthzDep`

**Current signature:**
```python
def AuthzDep(model, action, *, id_param=None, registry=None) -> Depends
```

**New signature:**
```python
def AuthzDep(
    model: type[T],
    action: str,
    *,
    id_param: str | None = None,
    pk_column: str = "id",          # NEW: configurable PK column
    registry: PolicyRegistry | None = None,
) -> Any  # Returns Depends()
```

Changes to `_make_dependency` / `_resolve`:

```python
async def _resolve(request: Request) -> T | list[T]:
    # 1. Resolve actor + session via DI (see below)
    actor = _get_actor(request)
    session = _get_session(request)

    # 2. Use configurable PK column
    if id_param is not None:
        pk_value = request.path_params[id_param]
        pk_col = getattr(model, pk_column)  # was hardcoded to "id"
        stmt = stmt.where(pk_col == pk_value)

    stmt = authorize_query(stmt, actor=actor, action=action, registry=effective_registry)

    # 3. Async-native execution
    if isinstance(session, AsyncSession):
        result = await session.execute(stmt)
    else:
        result = session.execute(stmt)

    return result.scalars().all()  # rest unchanged
```

**Key decision: runtime isinstance check vs. separate `AsyncAuthzDep`.**

Option A: Single `AuthzDep` with runtime `isinstance(session, AsyncSession)` check.
- Pro: One API surface, users don't pick wrong one.
- Con: Import of `AsyncSession` at module level requires `sqlalchemy[asyncio]` extra.

Option B: Separate `AsyncAuthzDep` class.
- Pro: Clean separation, no conditional imports.
- Con: Users must choose correctly, duplication.

**Recommendation: Option A** with a lazy import of `AsyncSession` inside the function body.
This avoids the import cost for sync-only users while keeping one unified API:

```python
async def _resolve(request: Request) -> Any:
    ...
    try:
        from sqlalchemy.ext.asyncio import AsyncSession
        is_async = isinstance(session, AsyncSession)
    except ImportError:
        is_async = False

    if is_async:
        result = await session.execute(stmt)
    else:
        result = session.execute(stmt)
    ...
```

### 2. Replace `configure_authz()` with Dependency Injection

**Current pattern (app.state):**
```python
configure_authz(app=app, get_actor=..., get_session=...)
```

**New pattern (FastAPI Depends):**
```python
from sqla_authz.integrations.fastapi import AuthzDep, get_actor, get_session

# Users override these via app.dependency_overrides or Depends()
def get_actor(request: Request) -> ActorLike:
    raise NotImplementedError("Override get_actor via app.dependency_overrides")

def get_session(request: Request) -> Session:
    raise NotImplementedError("Override get_session via app.dependency_overrides")
```

Usage:
```python
app = FastAPI()

async def my_get_actor(request: Request) -> User:
    return request.state.user

async def my_get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session

app.dependency_overrides[get_actor] = my_get_actor
app.dependency_overrides[get_session] = my_get_session
```

**Backward compatibility:** Keep `configure_authz()` working but mark it as deprecated.
Internally, `configure_authz()` will set `app.dependency_overrides` for the sentinel
dependencies:

```python
def configure_authz(*, app, get_actor, get_session, registry=None):
    """Deprecated: use app.dependency_overrides instead."""
    import warnings
    warnings.warn(
        "configure_authz() is deprecated. Use app.dependency_overrides instead.",
        DeprecationWarning, stacklevel=2,
    )
    app.dependency_overrides[_get_actor_dep] = get_actor
    app.dependency_overrides[_get_session_dep] = get_session
    if registry is not None:
        app.state.sqla_authz_registry = registry
```

### 3. Interceptor Middleware (`_middleware.py`)

This is the highest-value addition. A new `AuthzMiddleware` class that installs the
`do_orm_execute` interceptor on the session factory used by FastAPI routes, making ALL
queries automatically authorized without any per-route `authorize_query()` calls.

```python
# New file: _middleware.py

from sqla_authz.session._interceptor import install_interceptor

def install_authz_interceptor(
    session_factory: sessionmaker[Session] | async_sessionmaker[AsyncSession],
    *,
    actor_provider: Callable[[], ActorLike],
    action: str = "read",
    registry: PolicyRegistry | None = None,
    config: AuthzConfig | None = None,
) -> None:
    """Install do_orm_execute authorization on a session factory.

    After calling this, ALL SELECT queries through sessions created by
    this factory are automatically filtered by authorization policies.

    Works with both sync sessionmaker and async_sessionmaker.

    Args:
        session_factory: The sessionmaker or async_sessionmaker to intercept.
        actor_provider: Callable returning the current actor. For FastAPI,
            this typically reads from a context variable set by middleware.
        action: Default action. Override per-query via
            session.execute(stmt, execution_options={"authz_action": "edit"}).
        registry: Policy registry. Defaults to global.
        config: AuthzConfig. Defaults to global.

    Example::

        from sqla_authz.integrations.fastapi import install_authz_interceptor

        async_factory = async_sessionmaker(bind=async_engine)
        install_authz_interceptor(
            async_factory,
            actor_provider=lambda: current_user_ctx.get(),
            action="read",
        )

        # Now in any route:
        @app.get("/posts")
        async def list_posts(session: AsyncSession = Depends(get_session)):
            result = await session.execute(select(Post))
            return result.scalars().all()  # automatically filtered!
    """
    install_interceptor(
        session_factory,
        actor_provider=actor_provider,
        action=action,
        registry=registry,
        config=config,
    )
```

**Context variable pattern for actor resolution in interceptor:**

The interceptor's `actor_provider` needs access to the current request's actor, but it
runs inside SQLAlchemy's event system (no `Request` object available). Solution: use a
`contextvars.ContextVar`:

```python
# Recommended pattern (documented in examples):
import contextvars
from sqla_authz.integrations.fastapi import install_authz_interceptor

current_user_var: contextvars.ContextVar[User] = contextvars.ContextVar("current_user")

# Middleware to set the context var
@app.middleware("http")
async def set_current_user(request: Request, call_next):
    user = await resolve_user(request)
    token = current_user_var.set(user)
    try:
        response = await call_next(request)
    finally:
        current_user_var.reset(token)
    return response

# Install interceptor with context var
install_authz_interceptor(
    async_session_factory,
    actor_provider=lambda: current_user_var.get(),
)
```

### 4. Updated `__init__.py` Exports

```python
# fastapi/__init__.py
from sqla_authz.integrations.fastapi._dependencies import (
    AuthzDep,
    configure_authz,     # deprecated but still exported
    get_actor,           # sentinel dependency
    get_session,         # sentinel dependency
)
from sqla_authz.integrations.fastapi._errors import install_error_handlers
from sqla_authz.integrations.fastapi._middleware import install_authz_interceptor

__all__ = [
    "AuthzDep",
    "configure_authz",
    "get_actor",
    "get_session",
    "install_authz_interceptor",
    "install_error_handlers",
]
```

---

## File-by-File Change Summary

### FastAPI

| File | Action | Changes |
|------|--------|---------|
| `fastapi/_dependencies.py` | **Rewrite** | Add `pk_column` param; async/sync session detection; DI-based actor/session resolution; deprecate `configure_authz()` |
| `fastapi/_errors.py` | **No change** | Already clean |
| `fastapi/_middleware.py` | **New file** | `install_authz_interceptor()` wrapper around core `install_interceptor` |
| `fastapi/__init__.py` | **Update** | Add new exports: `install_authz_interceptor`, `get_actor`, `get_session` |

### Tests

| File | Action | Changes |
|------|--------|---------|
| `test_fastapi/test_dependencies.py` | **Extend** | Add async session tests; `pk_column` tests; DI override tests |
| `test_fastapi/test_middleware.py` | **New file** | Test interceptor integration with async test client |

---

## New Test Cases

### FastAPI Tests

```python
# test_dependencies.py additions:

class TestAsyncSession:
    """AuthzDep works with AsyncSession."""

    async def test_async_session_execution(self, async_client):
        """AuthzDep awaits session.execute() for AsyncSession."""
        response = await async_client.get("/articles")
        assert response.status_code == 200

    async def test_sync_session_still_works(self, sync_client):
        """AuthzDep falls back to sync execution for Session."""
        response = sync_client.get("/articles")
        assert response.status_code == 200


class TestPkColumn:
    """AuthzDep supports configurable PK column."""

    def test_custom_pk_column(self, client_with_uuid_model):
        """Models with non-id PK work when pk_column is specified."""
        response = client_with_uuid_model.get("/items/abc-123")
        assert response.status_code == 200

    def test_default_pk_column_is_id(self, client):
        """Default pk_column='id' maintains backward compat."""
        response = client.get("/articles/1")
        assert response.status_code == 200


class TestDependencyInjection:
    """Actor and session resolution via Depends()."""

    def test_dependency_overrides(self):
        """app.dependency_overrides works for actor/session."""
        ...

    def test_configure_authz_deprecated(self):
        """configure_authz() emits DeprecationWarning."""
        with pytest.warns(DeprecationWarning, match="deprecated"):
            configure_authz(app=app, get_actor=..., get_session=...)
```

```python
# test_middleware.py (new file):

class TestInterceptorMiddleware:
    """install_authz_interceptor integrates with FastAPI."""

    async def test_queries_auto_filtered(self, async_client):
        """All SELECT queries are automatically authorized."""
        response = await async_client.get("/posts")
        # Only authorized posts returned, no explicit authorize_query() in route
        assert len(response.json()) == 2

    async def test_skip_authz_option(self, async_client):
        """execution_options(skip_authz=True) bypasses interceptor."""
        ...

    async def test_action_override_via_execution_options(self, async_client):
        """execution_options(authz_action='edit') overrides default."""
        ...

    async def test_context_var_actor_resolution(self):
        """Actor resolved from contextvars in interceptor."""
        ...
```

---

## Migration Guide

### FastAPI: Migrating from `configure_authz()`

**Before (v0.x):**
```python
from sqla_authz.integrations.fastapi import configure_authz, AuthzDep

app = FastAPI()
configure_authz(
    app=app,
    get_actor=lambda request: get_current_user(request),
    get_session=lambda request: get_db(request),
)

@app.get("/posts")
async def list_posts(posts: list[Post] = AuthzDep(Post, "read")):
    return posts
```

**After (v1.x) -- Option A: Dependency overrides (recommended):**
```python
from sqla_authz.integrations.fastapi import AuthzDep, get_actor, get_session

app = FastAPI()

# Wire up via standard FastAPI DI
app.dependency_overrides[get_actor] = lambda request: get_current_user(request)
app.dependency_overrides[get_session] = get_db

@app.get("/posts")
async def list_posts(posts: list[Post] = AuthzDep(Post, "read")):
    return posts  # works identically
```

**After (v1.x) -- Option B: Interceptor (zero per-route code):**
```python
from sqla_authz.integrations.fastapi import install_authz_interceptor

current_user_var: ContextVar[User] = ContextVar("current_user")

install_authz_interceptor(
    async_session_factory,
    actor_provider=lambda: current_user_var.get(),
)

@app.get("/posts")
async def list_posts(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Post))
    return result.scalars().all()  # automatically filtered!
```

### PK Column Migration

**Before:** Only models with `id` column worked for single-item lookup.

**After:**
```python
# Model with UUID PK
@app.get("/items/{item_uuid}")
async def get_item(
    item: Item = AuthzDep(Item, "read", id_param="item_uuid", pk_column="uuid"),
):
    return item
```

---

## Example Usage

### FastAPI: Complete Async Example

```python
"""Full FastAPI example with async session and interceptor."""
import contextvars
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sqla_authz import policy
from sqla_authz.integrations.fastapi import (
    install_authz_interceptor,
    install_error_handlers,
)

# --- Setup ---
engine = create_async_engine("sqlite+aiosqlite:///app.db")
async_factory = async_sessionmaker(engine, expire_on_commit=False)

app = FastAPI()
install_error_handlers(app)

# --- Actor context ---
current_user_var: contextvars.ContextVar[User] = contextvars.ContextVar("current_user")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    user = await authenticate(request)
    token = current_user_var.set(user)
    try:
        return await call_next(request)
    finally:
        current_user_var.reset(token)

# --- Install interceptor (one line!) ---
install_authz_interceptor(
    async_factory,
    actor_provider=lambda: current_user_var.get(),
)

# --- Policies ---
@policy(Post, "read")
def post_read(actor: User):
    return (Post.is_published == True) | (Post.author_id == actor.id)

# --- Routes (no authorization code needed!) ---
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_factory() as session:
        yield session

@app.get("/posts")
async def list_posts(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Post))
    return result.scalars().all()

@app.get("/posts/{post_id}")
async def get_post(post_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Post).where(Post.id == post_id))
    post = result.scalar_one_or_none()
    if not post:
        raise HTTPException(404)
    return post
```

---

## Implementation Order

1. **FastAPI `pk_column` param** -- small, backward-compatible addition.
2. **FastAPI async session support** -- runtime `isinstance` check in `_resolve()`.
3. **FastAPI `_middleware.py`** -- new file, `install_authz_interceptor()` wrapper.
4. **FastAPI DI refactor** -- `get_actor`/`get_session` sentinel deps, deprecate `configure_authz()`.
5. **Tests for all new features** -- extend existing test files, add `test_middleware.py`.
6. **Update `__init__.py` exports**.
7. **Documentation examples** in docstrings.

Steps 1-2 can be done independently. Step 3 depends on understanding the interceptor
(already read). Step 4 is the most invasive change and should be done last.

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `configure_authz()` deprecation breaks users | Medium | Keep it working, just emit warning. Remove in v2.0 |
| `isinstance(session, AsyncSession)` import failure | Low | Lazy import with try/except, fallback to sync |
| Interceptor `actor_provider` called outside request context | High | Document the `contextvars` pattern clearly; raise helpful error if context var is unset |
| `with_loader_criteria` doesn't work with `async_sessionmaker` | Low | SQLAlchemy 2.0 async supports `do_orm_execute` events; verify in tests |

---

## Open Questions

1. **Should `install_authz_interceptor` accept `async_sessionmaker` directly?**
   The core `install_interceptor` types its param as `sessionmaker[Session]`. We need to
   verify that `event.listen(async_sessionmaker_instance, "do_orm_execute", handler)` works
   in SQLAlchemy 2.0. If not, we need to type-widen the core function or add an async
   variant.

2. **Should `AuthzDep` support composite primary keys?**
   Current plan only handles single-column PKs via `pk_column`. Composite PKs would need
   `pk_columns: list[str]` and multiple `request.path_params` lookups. Defer to v2.0
   unless users request it.
