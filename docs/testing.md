# Testing

`sqla-authz` ships test utilities for verifying policies. Install the testing extras:

```bash
pip install sqla-authz[testing]
```

## Mock Actors

`MockActor` satisfies the `ActorLike` protocol. Three factories cover common shapes:

```python
from sqla_authz.testing import MockActor, make_admin, make_user, make_anonymous

admin = make_admin()          # id=1, role="admin"
user  = make_user(id=7, role="editor", org_id=5)
anon  = make_anonymous()      # id=0, role="anonymous"

# Or build directly
actor = MockActor(id=42, role="viewer", org_id=10)
```

## Assertion Helpers

### `assert_authorized()`

Applies `authorize_query`, executes, and asserts at least one row is returned:

```python
from sqla_authz.testing import assert_authorized

assert_authorized(
    session,
    select(Post),
    actor=make_admin(),
    action="read",
    expected_count=3,       # optional exact count
    registry=authz_registry,
)
```

### `assert_denied()`

Asserts that zero rows are returned after authorization:

```python
from sqla_authz.testing import assert_denied

assert_denied(
    session,
    select(Post),
    actor=make_anonymous(),
    action="read",
    registry=authz_registry,
)
```

### `assert_query_contains()`

Checks that compiled SQL contains a substring. No database required:

```python
from sqla_authz.testing import assert_query_contains

assert_query_contains(
    select(Post),
    actor=make_user(id=42),
    action="read",
    text="author_id = 42",
    registry=authz_registry,
)
```

## Pytest Fixtures

Fixtures are auto-discovered via the `pytest11` entry point — no imports needed.

### `authz_registry`

Yields a fresh, empty `PolicyRegistry` per test. Policies registered here are isolated from the global registry and from other tests:

```python
def test_custom_policy(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def allow_published(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    assert_authorized(
        session, select(Post),
        actor=make_user(), action="read",
        registry=authz_registry,
    )
```

### `authz_config`

Returns the default `AuthzConfig`. Useful for asserting default values in tests.

## Example

A complete test file using all utilities together:

```python title="tests/test_post_policies.py"
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from sqla_authz import policy
from sqla_authz.testing import (
    make_admin, make_user,
    assert_authorized, assert_denied, assert_query_contains,
)


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "test_posts"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    is_published: Mapped[bool] = mapped_column(default=False)
    author_id: Mapped[int]


@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        s.add_all([
            Post(id=1, title="Published", is_published=True, author_id=10),
            Post(id=2, title="Draft", is_published=False, author_id=10),
            Post(id=3, title="Other", is_published=True, author_id=99),
        ])
        s.flush()
        yield s
        s.rollback()


def test_admin_sees_all(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_all(actor):
        from sqlalchemy import true
        return true()

    assert_authorized(session, select(Post), actor=make_admin(), action="read",
                      expected_count=3, registry=authz_registry)


def test_viewer_sees_published(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_published(actor):
        return Post.is_published == True

    assert_authorized(session, select(Post), actor=make_user(), action="read",
                      expected_count=2, registry=authz_registry)


def test_no_policy_denies(session, authz_registry):
    assert_denied(session, select(Post), actor=make_user(), action="read",
                  registry=authz_registry)


def test_sql_structure(authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def owner_read(actor):
        return Post.author_id == actor.id

    assert_query_contains(select(Post), actor=make_user(id=42), action="read",
                          text="author_id = 42", registry=authz_registry)
```

!!! tip "Registry Isolation"
    Always pass a local `PolicyRegistry` (or use the `authz_registry` fixture) to prevent test pollution from module-level `@policy` decorators in application code.
