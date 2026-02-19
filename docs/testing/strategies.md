# Testing Strategies

Well-tested authorization code needs three layers of coverage: structural SQL verification, row-level filtering against a real database, and full integration against the production database engine. This page describes each layer and how to apply property-based testing and isolation patterns on top of them.

## Three Levels of Testing

### Level 1: SQL Structure Tests

Use `assert_query_contains()` to verify that a policy produces the correct filter expression in compiled SQL. No database connection is required — the assertion compiles the statement to a string and checks for a substring.

These tests are fast, deterministic, and the right place to catch logic errors in filter construction before touching a database.

```python title="tests/test_compiler/test_post_sql_structure.py"
from sqlalchemy import select
from sqla_authz import policy
from sqla_authz.testing import assert_query_contains, make_user, make_admin
from sqla_authz.policy._registry import PolicyRegistry
from sqlalchemy.orm import ColumnElement


def test_owner_filter_embeds_actor_id():
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def owner_read(actor) -> ColumnElement[bool]:
        return Post.author_id == actor.id

    assert_query_contains(
        select(Post),
        actor=make_user(id=42),
        action="read",
        text="author_id = 42",
        registry=registry,
    )


def test_published_filter_is_present():
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def published_read(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    assert_query_contains(
        select(Post),
        actor=make_user(),
        action="read",
        text="is_published",
        registry=registry,
    )


def test_admin_policy_produces_true():
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def admin_read(actor) -> ColumnElement[bool]:
        from sqlalchemy import true
        return true()

    # sqlalchemy.true() compiles to 1 in SQLite dialect
    assert_query_contains(
        select(Post),
        actor=make_admin(),
        action="read",
        text="1",
        registry=registry,
    )
```

**When to use:** Always. Every policy should have at least one SQL structure test. These run in milliseconds and require no fixtures beyond the policy itself.

### Level 2: Unit Tests

Use an in-memory SQLite database to verify that the compiled WHERE clause actually filters rows correctly. These tests seed known data and assert exact row counts using `assert_authorized` and `assert_denied`.

```python title="tests/test_policy/test_post_unit.py"
import pytest
from sqlalchemy import Column, Integer, String, Boolean, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, ColumnElement

from sqla_authz import policy
from sqla_authz.testing import (
    make_admin,
    make_user,
    make_anonymous,
    assert_authorized,
    assert_denied,
)
from sqla_authz.policy._registry import PolicyRegistry


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "post_unit"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    is_published = Column(Boolean, default=False)
    author_id = Column(Integer)
    org_id = Column(Integer, nullable=True)


@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        s.add_all([
            Post(id=1, title="Pub-A",  is_published=True,  author_id=1, org_id=10),
            Post(id=2, title="Draft-A",is_published=False, author_id=1, org_id=10),
            Post(id=3, title="Pub-B",  is_published=True,  author_id=2, org_id=10),
            Post(id=4, title="Pub-C",  is_published=True,  author_id=3, org_id=20),
        ])
        s.flush()
        yield s
        s.rollback()


def test_viewer_only_sees_published(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_published(actor) -> ColumnElement[bool]:
        return Post.is_published == True

    assert_authorized(
        session, select(Post),
        actor=make_user(), action="read",
        expected_count=3,
        registry=authz_registry,
    )


def test_admin_sees_all_rows(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_all(actor) -> ColumnElement[bool]:
        from sqlalchemy import true
        return true()

    assert_authorized(
        session, select(Post),
        actor=make_admin(), action="read",
        expected_count=4,
        registry=authz_registry,
    )


def test_author_sees_own_only(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_own(actor) -> ColumnElement[bool]:
        return Post.author_id == actor.id

    assert_authorized(
        session, select(Post),
        actor=make_user(id=1), action="read",
        expected_count=2,
        registry=authz_registry,
    )

    assert_denied(
        session, select(Post).where(Post.author_id == 2),
        actor=make_user(id=1), action="read",
        registry=authz_registry,
    )
```

**When to use:** For every policy that filters rows based on data. SQLite covers all basic SQL expressions. Use PostgreSQL (Level 3) only when the policy uses dialect-specific features.

### Level 3: Integration Tests

Use a real PostgreSQL database to verify behaviour that SQLite cannot reproduce faithfully: JSONB operators, full-text search filters, array containment, or window function expressions used in subqueries.

Mark these tests with `@pytest.mark.integration` and keep them in `tests/integration/`:

```python title="tests/integration/test_post_integration.py"
import pytest
from sqlalchemy import select, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqla_authz import policy
from sqla_authz.testing import make_user, assert_authorized, assert_denied
from sqlalchemy.orm import ColumnElement


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def pg_engine(postgresql):
    # postgresql fixture from pytest-postgresql or a docker-based fixture
    from sqlalchemy import create_engine
    engine = create_engine(postgresql.url)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def pg_session(pg_engine):
    from sqlalchemy.orm import Session
    with Session(pg_engine) as s:
        s.add_all([
            Post(id=1, title="A", metadata={"visibility": "public"},  author_id=1),
            Post(id=2, title="B", metadata={"visibility": "private"}, author_id=1),
        ])
        s.flush()
        yield s
        s.rollback()


def test_jsonb_visibility_filter(pg_session, authz_registry):
    """Policy using PostgreSQL JSONB operator."""
    @policy(Post, "read", registry=authz_registry)
    def jsonb_read(actor) -> ColumnElement[bool]:
        return Post.metadata["visibility"].astext == "public"

    assert_authorized(
        pg_session, select(Post),
        actor=make_user(), action="read",
        expected_count=1,
        registry=authz_registry,
    )
```

Run integration tests explicitly:

```bash
pytest -m integration
```

Exclude them from the fast unit suite:

```bash
pytest -m "not integration"
```

## Property-Based Testing with Hypothesis

Use `hypothesis` to generate random actors and resources, then verify that authorization invariants hold across all inputs. This catches edge cases that hand-written examples miss.

```python title="tests/test_policy/test_post_hypothesis.py"
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from sqlalchemy import select
from sqla_authz import policy
from sqla_authz.testing import MockActor, assert_query_contains
from sqla_authz.policy._registry import PolicyRegistry
from sqlalchemy.orm import ColumnElement


actor_ids   = st.integers(min_value=1, max_value=10_000)
actor_roles = st.sampled_from(["viewer", "editor", "admin"])
org_ids     = st.one_of(st.none(), st.integers(min_value=1, max_value=100))

actors = st.builds(MockActor, id=actor_ids, role=actor_roles, org_id=org_ids)


@given(actor=actors)
@settings(max_examples=200)
def test_owner_filter_always_embeds_actor_id(actor):
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def owner_read(a) -> ColumnElement[bool]:
        return Post.author_id == a.id

    assert_query_contains(
        select(Post),
        actor=actor,
        action="read",
        text=str(actor.id),
        registry=registry,
    )


@given(actor=actors)
@settings(max_examples=200)
def test_org_filter_always_embeds_org_id(actor):
    assume(actor.org_id is not None)

    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def org_read(a) -> ColumnElement[bool]:
        return Post.org_id == a.org_id

    assert_query_contains(
        select(Post),
        actor=actor,
        action="read",
        text=str(actor.org_id),
        registry=registry,
    )
```

**Invariants worth testing with Hypothesis:**

- The actor's `id` always appears in the compiled SQL when a policy uses it.
- Admin actors always receive an unrestricted filter (`WHERE 1`).
- Anonymous actors (`id=0`) are always denied when no policy exists.
- Two policies OR'd together always produce a superset of either alone.

## Testing Deny-by-Default

When no policy is registered for a `(Model, action)` pair, `authorize_query` appends `WHERE false`, returning zero rows. Test this explicitly to document the contract and catch regressions if the default changes.

```python
def test_no_policy_returns_zero_rows(session):
    empty_registry = PolicyRegistry()

    # No policies registered at all
    assert_denied(
        session,
        select(Post),
        actor=make_user(id=1),
        action="read",
        registry=empty_registry,
    )


def test_wrong_action_returns_zero_rows(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_all(actor):
        from sqlalchemy import true
        return true()

    # Policy is for "read", not "write" — deny-by-default for "write"
    assert_denied(
        session,
        select(Post),
        actor=make_user(),
        action="write",
        registry=authz_registry,
    )


def test_wrong_model_returns_zero_rows(session, authz_registry):
    @policy(Post, "read", registry=authz_registry)
    def read_posts(actor):
        from sqlalchemy import true
        return true()

    # Comment has no policy in this registry
    assert_denied(
        session,
        select(Comment),
        actor=make_user(),
        action="read",
        registry=authz_registry,
    )
```

## Testing Multiple Policies

When two or more policies are registered for the same `(Model, action)` pair, they are OR'd together. A row visible under either policy is included in the result. Test this behaviour explicitly:

```python
def test_two_policies_are_ored(session, authz_registry):
    """Author OR admin can read — union of both sets."""

    @policy(Post, "read", registry=authz_registry)
    def own_posts(actor):
        return Post.author_id == actor.id

    @policy(Post, "read", registry=authz_registry)
    def published_posts(actor):
        return Post.is_published == True

    # actor.id=99 owns no posts, but can see published ones
    assert_authorized(
        session,
        select(Post),
        actor=make_user(id=99),
        action="read",
        registry=authz_registry,
    )


def test_policy_or_is_additive_not_restrictive(session, authz_registry):
    """OR composition never reduces the visible set."""
    registry_one = PolicyRegistry()
    registry_two = PolicyRegistry()

    @policy(Post, "read", registry=registry_one)
    def p1(actor):
        return Post.author_id == actor.id

    @policy(Post, "read", registry=registry_two)
    def p2_a(actor):
        return Post.author_id == actor.id

    @policy(Post, "read", registry=registry_two)
    def p2_b(actor):
        return Post.is_published == True

    from sqlalchemy import func
    actor = make_user(id=1)

    count_one = session.execute(
        authorize_query(select(func.count()).select_from(Post), actor=actor, action="read", registry=registry_one)
    ).scalar()

    count_two = session.execute(
        authorize_query(select(func.count()).select_from(Post), actor=actor, action="read", registry=registry_two)
    ).scalar()

    assert count_two >= count_one
```

## Testing with Custom Registries

Always pass a local `PolicyRegistry` to isolate tests from the global registry. This prevents module-level `@policy` decorators in application code from contaminating unit tests.

```python
def test_isolation_from_global_registry(session):
    """Policies in global registry do not affect tests using a local registry."""
    local_registry = PolicyRegistry()

    # Do not register any policy in local_registry
    # Even if the global registry has policies for Post, this test
    # is only looking at local_registry → deny-by-default applies.
    assert_denied(
        session,
        select(Post),
        actor=make_admin(),
        action="read",
        registry=local_registry,
    )
```

Use the `authz_registry` fixture (function-scoped) for the same effect without manual instantiation:

```python
def test_isolation_via_fixture(session, authz_registry):
    # authz_registry is always a fresh, empty PolicyRegistry
    assert_denied(
        session,
        select(Post),
        actor=make_admin(),
        action="read",
        registry=authz_registry,
    )
```

For parametrized tests across multiple registry configurations, build each registry inside the parametrize body:

```python
@pytest.mark.parametrize("role,expected", [
    ("admin",  3),
    ("editor", 2),
    ("viewer", 1),
])
def test_role_based_visibility(session, role, expected):
    registry = PolicyRegistry()

    @policy(Post, "read", registry=registry)
    def role_read(actor):
        from sqlalchemy import case, true
        return case(
            (actor.role == "admin",  true()),
            (actor.role == "editor", Post.is_published == True),
            else_=Post.author_id == actor.id,
        )

    assert_authorized(
        session,
        select(Post),
        actor=make_user(role=role),
        action="read",
        expected_count=expected,
        registry=registry,
    )
```

Each parametrized case gets its own `PolicyRegistry`, so there is no shared state between runs.
