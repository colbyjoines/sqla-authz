# Plan 05: Framework Integrations Rewrite (FastAPI + Flask)

## Problem Statement

The FastAPI and Flask integrations are "checkbox features" that don't expose the library's
core value proposition (the `do_orm_execute` interceptor with `with_loader_criteria`). Both
integrations have correctness bugs and design issues that make them unsuitable for
production use.

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

### Flask Issues

1. **28 pyright errors** from Flask's poor typing (`app.extensions` is `dict[str, Any]`).
   Every access to `ext_state["actor_provider"]` etc. is untyped.
2. **No Flask-SQLAlchemy integration** -- requires users to manage their own `sessionmaker`,
   which is unusual in Flask apps that use `flask-sqlalchemy`.
3. **No interceptor integration** -- same as FastAPI. The `authorize_query()` wrapper saves
   one argument (actor) but users still call it manually per-query.
4. **`authorize_query()` wrapper is thin** -- saves only the actor resolution. Users still
   pass `stmt` and optionally `action`. Minimal value over calling the core API directly.

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

## Design: Flask Rewrite

### New Module Layout

```
src/sqla_authz/integrations/flask/
    __init__.py          # re-exports, import guard
    _extension.py        # AuthzExtension (rewritten with type safety)
```

### 1. Fix Pyright Errors with Typed Extension State

Replace the untyped `app.extensions["sqla_authz"]` dict with a proper typed dataclass:

```python
from dataclasses import dataclass

@dataclass
class _AuthzExtensionState:
    """Typed internal state stored on app.extensions."""
    actor_provider: Callable[[], ActorLike]
    default_action: str
    registry: PolicyRegistry | None
    config: AuthzConfig | None
    db: Any | None  # Flask-SQLAlchemy instance (optional)
```

Access pattern with cast:
```python
def _get_state(self) -> _AuthzExtensionState:
    ext_data: Any = current_app.extensions["sqla_authz"]
    return cast("_AuthzExtensionState", ext_data)
```

This eliminates all 28 pyright errors from accessing untyped dict values.

### 2. Flask-SQLAlchemy Integration

Add optional `db` parameter to accept a Flask-SQLAlchemy instance:

```python
class AuthzExtension:
    def __init__(
        self,
        app: Flask | None = None,
        *,
        actor_provider: Callable[[], ActorLike],
        default_action: str = "read",
        registry: PolicyRegistry | None = None,
        config: AuthzConfig | None = None,
        db: Any | None = None,  # NEW: Flask-SQLAlchemy SQLAlchemy instance
    ) -> None:
        self._actor_provider = actor_provider
        self._default_action = default_action
        self._registry = registry
        self._config = config
        self._db = db
        if app is not None:
            self.init_app(app)
```

When `db` is provided, the extension can:
1. Auto-install the interceptor on `db.session` (the scoped session factory).
2. Provide a `get_session()` helper that returns `db.session`.

```python
def init_app(self, app: Flask) -> None:
    state = _AuthzExtensionState(
        actor_provider=self._actor_provider,
        default_action=self._default_action,
        registry=self._registry,
        config=self._config,
        db=self._db,
    )
    app.extensions["sqla_authz"] = state
    self._register_error_handlers(app)
```

### 3. Interceptor Support via `install_interceptor()`

Add a method on `AuthzExtension` that installs the `do_orm_execute` hook:

```python
def install_interceptor(
    self,
    session_factory: sessionmaker[Session] | None = None,
    *,
    action: str | None = None,
) -> None:
    """Install automatic authorization on a session factory.

    If no session_factory is provided and a Flask-SQLAlchemy `db` was
    passed to the constructor, uses `db.session` automatically.

    Args:
        session_factory: Optional explicit sessionmaker. Defaults to
            the Flask-SQLAlchemy session if `db` was provided.
        action: Override default action. Defaults to extension's
            default_action.

    Raises:
        ValueError: If no session_factory provided and no db configured.

    Example::

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(app)
        authz = AuthzExtension(app, actor_provider=get_user, db=db)
        authz.install_interceptor()
        # Now ALL queries through db.session are automatically authorized
    """
    if session_factory is None:
        if self._db is None:
            raise ValueError(
                "No session_factory provided and no Flask-SQLAlchemy db configured. "
                "Pass either session_factory= or db= to AuthzExtension."
            )
        # Flask-SQLAlchemy's db.session is a scoped_session wrapping a sessionmaker
        session_factory = self._db.session

    effective_action = action if action is not None else self._default_action

    from sqla_authz.session._interceptor import install_interceptor as _install

    _install(
        session_factory,
        actor_provider=self._actor_provider,
        action=effective_action,
        registry=self._registry,
        config=self._config,
    )
```

### 4. Better Error Handler Typing

Fix the error handler return type annotations to satisfy pyright:

```python
def _register_error_handlers(self, app: Flask) -> None:
    @app.errorhandler(AuthorizationDenied)
    def handle_authz_denied(
        exc: AuthorizationDenied,
    ) -> tuple[Response, int]:
        return jsonify({"detail": str(exc)}), 403

    @app.errorhandler(NoPolicyError)
    def handle_no_policy(
        exc: NoPolicyError,
    ) -> tuple[Response, int]:
        return jsonify({"detail": str(exc)}), 500
```

### 5. Updated `__init__.py` Exports

```python
# flask/__init__.py (unchanged exports, but AuthzExtension gains new methods)
from sqla_authz.integrations.flask._extension import AuthzExtension

__all__ = ["AuthzExtension"]
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

### Flask

| File | Action | Changes |
|------|--------|---------|
| `flask/_extension.py` | **Rewrite** | `_AuthzExtensionState` dataclass; `db` param; `install_interceptor()` method; typed error handlers |
| `flask/__init__.py` | **No change** | Exports remain the same |

### Tests

| File | Action | Changes |
|------|--------|---------|
| `test_fastapi/test_dependencies.py` | **Extend** | Add async session tests; `pk_column` tests; DI override tests |
| `test_fastapi/test_middleware.py` | **New file** | Test interceptor integration with async test client |
| `test_flask/test_extension.py` | **Extend** | Add `install_interceptor()` tests; Flask-SQLAlchemy integration tests |

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

### Flask Tests

```python
# test_extension.py additions:

class TestInterceptorInstall:
    """AuthzExtension.install_interceptor() works."""

    def test_interceptor_auto_filters_queries(self, app, db_session):
        """After install_interceptor(), queries are auto-filtered."""
        ...

    def test_interceptor_with_flask_sqlalchemy_db(self, app, db):
        """install_interceptor() uses db.session when db= is provided."""
        ...

    def test_interceptor_raises_without_factory_or_db(self):
        """ValueError when no session_factory and no db."""
        ext = AuthzExtension(actor_provider=lambda: Actor(id=1))
        with pytest.raises(ValueError, match="No session_factory"):
            ext.install_interceptor()


class TestTypedState:
    """Extension state is properly typed."""

    def test_state_is_dataclass(self, app_with_policies):
        """Extension state is _AuthzExtensionState, not raw dict."""
        with app_with_policies.app_context():
            state = current_app.extensions["sqla_authz"]
            assert hasattr(state, "actor_provider")
            assert hasattr(state, "default_action")
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

### Flask: Adding Interceptor Support

**Before (v0.x):**
```python
authz = AuthzExtension(app, actor_provider=get_current_user)

@app.get("/posts")
def list_posts():
    stmt = select(Post)
    stmt = authz.authorize_query(stmt)  # manual per-route
    return session.execute(stmt).scalars().all()
```

**After (v1.x) -- with Flask-SQLAlchemy:**
```python
db = SQLAlchemy(app)
authz = AuthzExtension(app, actor_provider=get_current_user, db=db)
authz.install_interceptor()

@app.get("/posts")
def list_posts():
    # No authorize_query() needed -- interceptor handles it
    return db.session.execute(select(Post)).scalars().all()
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

### Flask: Complete Flask-SQLAlchemy Example

```python
"""Full Flask example with Flask-SQLAlchemy and interceptor."""
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy

from sqla_authz import policy
from sqla_authz.integrations.flask import AuthzExtension

# --- Setup ---
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
db = SQLAlchemy(app)

# --- Extension with interceptor ---
authz = AuthzExtension(
    app,
    actor_provider=lambda: g.current_user,
    db=db,
)
authz.install_interceptor()

# --- Policies ---
@policy(Post, "read")
def post_read(actor):
    return (Post.is_published == True) | (Post.author_id == actor.id)

# --- Routes (no authorization code needed!) ---
@app.get("/posts")
def list_posts():
    posts = db.session.execute(select(Post)).scalars().all()
    return [p.to_dict() for p in posts]

# authorize_query() still works for fine-grained control:
@app.get("/admin/posts")
def admin_posts():
    stmt = select(Post)
    stmt = authz.authorize_query(stmt, action="admin_read")
    return db.session.execute(stmt).scalars().all()
```

---

## Implementation Order

1. **Flask type fixes** -- lowest risk, fixes pyright errors, no API changes.
2. **FastAPI `pk_column` param** -- small, backward-compatible addition.
3. **FastAPI async session support** -- runtime `isinstance` check in `_resolve()`.
4. **Flask `_AuthzExtensionState` dataclass** -- internal refactor, no API change.
5. **Flask `db` param + `install_interceptor()` method** -- new feature, additive.
6. **FastAPI `_middleware.py`** -- new file, `install_authz_interceptor()` wrapper.
7. **FastAPI DI refactor** -- `get_actor`/`get_session` sentinel deps, deprecate `configure_authz()`.
8. **Tests for all new features** -- extend existing test files, add `test_middleware.py`.
9. **Update `__init__.py` exports** for both frameworks.
10. **Documentation examples** in docstrings.

Steps 1-4 can be done independently. Steps 5-6 depend on understanding the interceptor
(already read). Step 7 is the most invasive change and should be done last.

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `configure_authz()` deprecation breaks users | Medium | Keep it working, just emit warning. Remove in v2.0 |
| `isinstance(session, AsyncSession)` import failure | Low | Lazy import with try/except, fallback to sync |
| Flask-SQLAlchemy `db.session` is `scoped_session`, not `sessionmaker` | Medium | `install_interceptor` already accepts sessionmaker; need to verify it works with `scoped_session` or extract the underlying factory |
| Interceptor `actor_provider` called outside request context | High | Document the `contextvars` pattern clearly; raise helpful error if context var is unset |
| `with_loader_criteria` doesn't work with `async_sessionmaker` | Low | SQLAlchemy 2.0 async supports `do_orm_execute` events; verify in tests |

---

## Open Questions

1. **Should `install_authz_interceptor` accept `async_sessionmaker` directly?**
   The core `install_interceptor` types its param as `sessionmaker[Session]`. We need to
   verify that `event.listen(async_sessionmaker_instance, "do_orm_execute", handler)` works
   in SQLAlchemy 2.0. If not, we need to type-widen the core function or add an async
   variant.

2. **Should Flask-SQLAlchemy be an optional dependency?**
   Current approach: `db` parameter is `Any | None`, no import of `flask_sqlalchemy` at
   module level. This means zero extra dependencies. The typing is loose but pragmatic.

3. **Should `AuthzDep` support composite primary keys?**
   Current plan only handles single-column PKs via `pk_column`. Composite PKs would need
   `pk_columns: list[str]` and multiple `request.path_params` lookups. Defer to v2.0
   unless users request it.
