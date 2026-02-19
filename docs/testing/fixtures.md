# Pytest Fixtures

`sqla-authz` ships pytest fixtures that are auto-discovered when the package is installed. You do not need to import them or add them to `conftest.py` — they are available in every test file automatically.

## Auto-Discovery

Fixtures are registered via a `pytest11` entry point in `pyproject.toml`:

```toml
[project.entry-points."pytest11"]
sqla_authz = "sqla_authz.testing._plugin"
```

When `sqla-authz[testing]` is installed, pytest loads the plugin at startup and makes all fixtures available globally. Confirm discovery with:

```bash
pytest --fixtures | grep authz
```

## `authz_registry`

Yields a fresh, empty `PolicyRegistry` for each test. The registry is completely isolated from the global default registry — policies registered in one test cannot leak into another.

```python
from sqla_authz import policy
from sqla_authz.testing import assert_authorized, make_admin
from sqlalchemy import select
from sqlalchemy.orm import ColumnElement


def test_custom_policy(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def allow_admin(actor) -> ColumnElement[bool]:
        from sqlalchemy import true
        return true()

    assert_authorized(
        session,
        select(Post),
        actor=make_admin(),
        action="read",
        registry=authz_registry,
    )
```

Each invocation of `authz_registry` creates a new `PolicyRegistry()`. Tests that register policies in this fixture cannot interfere with each other or with module-level `@policy` registrations in the global registry.

**Scope:** function (a new instance per test).

## `authz_config`

Returns the default `AuthzConfig` instance. When the `sqla_authz.config` module is available it returns a real `AuthzConfig`; during early development it returns a plain dict with the same keys.

```python
def test_default_config_denies(authz_config):
    assert authz_config["on_missing_policy"] == "deny"
```

Once the config module is complete, `authz_config` will return a typed `AuthzConfig` object and this fixture will be updated accordingly. The `on_missing_policy` key will remain stable.

**Scope:** function.

## `authz_context`

Placeholder for the `AuthorizationContext` fixture. Returns `None` until the session interception module is implemented.

```python
def test_placeholder(authz_context):
    # authz_context is None until session module ships
    assert authz_context is None
```

This fixture will be updated to return an `AuthorizationContext` dataclass when `sqla_authz.session` is complete. Tests that use it today will automatically receive the real context after that release with no code changes required.

**Scope:** function.

## Using Fixtures

The most common pattern is combining `authz_registry` with a local policy registration so that test policies are isolated from the global registry:

```python title="tests/test_post_read_policy.py"
import pytest
from sqlalchemy import Column, Integer, String, Boolean, select
from sqlalchemy.orm import DeclarativeBase, Session, ColumnElement
from sqlalchemy import create_engine

from sqla_authz import policy
from sqla_authz.testing import (
    make_admin,
    make_user,
    assert_authorized,
    assert_denied,
)


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "posts_fixture_example"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    is_published = Column(Boolean, default=False)
    author_id = Column(Integer)


@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        s.add_all([
            Post(id=1, title="Published", is_published=True, author_id=1),
            Post(id=2, title="Draft",     is_published=False, author_id=1),
        ])
        s.flush()
        yield s
        s.rollback()


def test_admin_reads_all(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def admin_read(actor) -> ColumnElement[bool]:
        from sqlalchemy import true
        return true()

    assert_authorized(
        session,
        select(Post),
        actor=make_admin(),
        action="read",
        expected_count=2,
        registry=authz_registry,
    )


def test_viewer_reads_published_only(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def viewer_read(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    assert_authorized(
        session,
        select(Post),
        actor=make_user(),
        action="read",
        expected_count=1,
        registry=authz_registry,
    )


def test_no_policy_denies(session, authz_registry):
    # authz_registry is empty — no policies registered
    assert_denied(
        session,
        select(Post),
        actor=make_user(),
        action="read",
        registry=authz_registry,
    )
```

Each test receives its own `authz_registry` instance, so policy registrations in `test_admin_reads_all` do not affect `test_viewer_reads_published_only`.

## Combining with conftest.py

For shared models, engines, and seeded sessions, define those in `conftest.py` and let `authz_registry` remain function-scoped:

```python title="tests/conftest.py"
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from myapp.models import Base, Post, Comment


@pytest.fixture(scope="session")
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


@pytest.fixture()
def seeded_posts(session):
    session.add_all([
        Post(id=1, title="Alpha", is_published=True, author_id=10),
        Post(id=2, title="Beta",  is_published=False, author_id=10),
        Post(id=3, title="Gamma", is_published=True, author_id=20),
    ])
    session.flush()
    return session
```

Tests then mix conftest fixtures with `authz_registry`:

```python title="tests/test_post_policies.py"
from sqlalchemy import select
from sqla_authz import policy
from sqla_authz.testing import make_user, assert_authorized


def test_author_sees_own_posts(seeded_posts, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def author_read(actor):
        return Post.author_id == actor.id

    assert_authorized(
        seeded_posts,
        select(Post),
        actor=make_user(id=10),
        action="read",
        expected_count=2,
        registry=authz_registry,
    )
```

Keep the engine and model fixtures at a broader scope (`session` or `module`) while `authz_registry` stays at function scope. This avoids policy leakage between tests while keeping database setup fast.
