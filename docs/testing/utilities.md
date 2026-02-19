# Test Utilities

`sqla-authz` ships a dedicated testing package with mock actors, assertion helpers, and pytest fixtures. These tools cover the full testing surface: SQL structure verification, row-level filtering, and integration against a real database.

## Installation

The testing extras install `pytest` and `hypothesis` alongside the core library:

```bash
pip install sqla-authz[testing]
```

Or with uv:

```bash
uv add sqla-authz[testing]
```

## MockActor

`MockActor` is a lightweight, immutable dataclass that satisfies the `ActorLike` protocol. Use it anywhere a policy function receives an actor.

```python
from sqla_authz.testing import MockActor

actor = MockActor(id=1, role="editor", org_id=42)

assert actor.id == 1
assert actor.role == "editor"
assert actor.org_id == 42
```

`MockActor` is defined as `@dataclass(frozen=True, slots=True)`, so instances are hashable and immutable. The `id` field is required; `role` and `org_id` are optional.

```python
@dataclass(frozen=True, slots=True)
class MockActor:
    id: int | str
    role: str = "viewer"       # default: "viewer"
    org_id: int | None = None  # default: None
```

## Factory Functions

Three convenience factories cover the most common actor shapes:

### `make_admin()`

Returns a `MockActor` with `role="admin"`:

```python
from sqla_authz.testing import make_admin

admin = make_admin()
assert admin.id == 1
assert admin.role == "admin"

# Custom ID
admin = make_admin(id=99)
assert admin.id == 99
```

### `make_user()`

Returns a regular `MockActor`. All fields are configurable:

```python
from sqla_authz.testing import make_user

user = make_user()
assert user.role == "viewer"

# Editor in org 5
editor = make_user(id=7, role="editor", org_id=5)
assert editor.org_id == 5
```

### `make_anonymous()`

Returns a `MockActor` with `id=0` and `role="anonymous"`. Useful for testing deny-by-default behaviour:

```python
from sqla_authz.testing import make_anonymous

anon = make_anonymous()
assert anon.id == 0
assert anon.role == "anonymous"
```

## `assert_authorized()`

Applies `authorize_query` to a `Select` statement, executes it, and asserts that at least one row is returned. Fails with `AssertionError` if zero rows come back.

```python
from sqlalchemy import select
from sqla_authz.testing import assert_authorized, make_admin

def test_admin_can_read_posts(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def admin_read(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    # Seed data
    session.add(Post(title="Hello", is_published=True))
    session.commit()

    assert_authorized(
        session,
        select(Post),
        actor=make_admin(),
        action="read",
        registry=authz_registry,
    )
```

Pass `expected_count` to assert an exact row count:

```python
assert_authorized(
    session,
    select(Post),
    actor=make_admin(),
    action="read",
    expected_count=3,
    registry=authz_registry,
)
```

**Signature:**

```python
def assert_authorized(
    session: Session,
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    expected_count: int | None = None,
    registry: PolicyRegistry | None = None,
) -> None: ...
```

When `registry` is omitted, the global default registry is used.

## `assert_denied()`

The inverse of `assert_authorized`. Applies `authorize_query`, executes the statement, and asserts that zero rows are returned.

```python
from sqlalchemy import select
from sqla_authz.testing import assert_denied, make_anonymous

def test_anonymous_cannot_read_posts(session, authz_registry):
    # No policy registered for ("Post", "read") in this registry
    # → deny-by-default applies

    assert_denied(
        session,
        select(Post),
        actor=make_anonymous(),
        action="read",
        registry=authz_registry,
    )
```

**Signature:**

```python
def assert_denied(
    session: Session,
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    registry: PolicyRegistry | None = None,
) -> None: ...
```

## `assert_query_contains()`

Verifies that the compiled SQL of an authorized statement contains a given substring. No database connection is required — this compiles the statement to a string and inspects it.

```python
from sqlalchemy import select
from sqla_authz.testing import assert_query_contains, make_admin

def test_owner_filter_in_sql(authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def owner_read(actor) -> ColumnElement[bool]:
        return Post.author_id == actor.id

    assert_query_contains(
        select(Post),
        actor=make_admin(id=7),
        action="read",
        text="author_id = 7",
        registry=authz_registry,
    )
```

The `text` check is a plain substring match on the output of `stmt.compile(compile_kwargs={"literal_binds": True})`. This lets you verify that the filter expression is structurally correct without seeding or querying a database.

**Signature:**

```python
def assert_query_contains(
    stmt: Select[Any],
    actor: ActorLike,
    action: str,
    *,
    text: str,
    registry: PolicyRegistry | None = None,
) -> None: ...
```

## Complete Test Example

The example below shows all utilities working together in a single test file:

```python title="tests/test_post_policies.py"
import pytest
from sqlalchemy import Column, Integer, String, Boolean, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session

from sqla_authz import policy, authorize_query
from sqla_authz.testing import (
    MockActor,
    make_admin,
    make_user,
    make_anonymous,
    assert_authorized,
    assert_denied,
    assert_query_contains,
)
from sqla_authz.policy._registry import PolicyRegistry


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "post"
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    is_published = Column(Boolean, default=False)
    author_id = Column(Integer, nullable=False)


@pytest.fixture(scope="module")
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
def seeded_session(session):
    session.add_all([
        Post(id=1, title="Public post", is_published=True, author_id=10),
        Post(id=2, title="Draft post", is_published=False, author_id=10),
        Post(id=3, title="Other author", is_published=True, author_id=99),
    ])
    session.flush()
    return session


# ── Policy definitions ───────────────────────────────────────────────────────

@pytest.fixture()
def registry_with_policies():
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def read_published(actor) -> bool:
        # Admins see everything; others only see published posts
        if actor.role == "admin":
            from sqlalchemy import true
            return true()
        return Post.is_published == True

    @policy(Post, "delete", registry=registry)
    def delete_own(actor):
        return Post.author_id == actor.id

    return registry


# ── SQL structure tests (no DB required) ─────────────────────────────────────

def test_admin_read_has_no_filter(registry_with_policies):
    """Admin policy compiles to WHERE true."""
    assert_query_contains(
        select(Post),
        actor=make_admin(),
        action="read",
        text="1",  # literal true compiles to 1 in SQLite
        registry=registry_with_policies,
    )


def test_viewer_read_filters_published(registry_with_policies):
    """Viewer policy appends is_published = 1 to the query."""
    assert_query_contains(
        select(Post),
        actor=make_user(),
        action="read",
        text="is_published",
        registry=registry_with_policies,
    )


def test_delete_filter_uses_actor_id(registry_with_policies):
    """Delete policy compiles actor ID into WHERE clause."""
    assert_query_contains(
        select(Post),
        actor=make_user(id=42),
        action="delete",
        text="author_id = 42",
        registry=registry_with_policies,
    )


# ── Row-level tests (SQLite in-memory) ───────────────────────────────────────

def test_admin_sees_all_posts(seeded_session, registry_with_policies):
    assert_authorized(
        seeded_session,
        select(Post),
        actor=make_admin(),
        action="read",
        expected_count=3,
        registry=registry_with_policies,
    )


def test_viewer_sees_only_published(seeded_session, registry_with_policies):
    assert_authorized(
        seeded_session,
        select(Post),
        actor=make_user(),
        action="read",
        expected_count=2,
        registry=registry_with_policies,
    )


def test_anonymous_denied_with_no_policy(seeded_session):
    """No policy registered → deny-by-default → zero rows."""
    empty_registry = PolicyRegistry()
    assert_denied(
        seeded_session,
        select(Post),
        actor=make_anonymous(),
        action="read",
        registry=empty_registry,
    )


def test_user_can_delete_own_posts(seeded_session, registry_with_policies):
    author = make_user(id=10)
    assert_authorized(
        seeded_session,
        select(Post),
        actor=author,
        action="delete",
        expected_count=2,
        registry=registry_with_policies,
    )


def test_user_cannot_delete_others_posts(seeded_session, registry_with_policies):
    other = make_user(id=99)
    assert_denied(
        seeded_session,
        select(Post).where(Post.id == 1),  # belongs to author_id=10
        actor=other,
        action="delete",
        registry=registry_with_policies,
    )
```
