"""Async integration tests — prove sqla-authz works with AsyncSession."""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sqla_authz._checks import authorize, can
from sqla_authz.compiler._query import authorize_query
from sqla_authz.exceptions import AuthorizationDenied
from sqla_authz.policy._registry import PolicyRegistry
from tests.conftest import Base, MockActor, Organization, Post, Tag, User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> PolicyRegistry:
    """Fresh registry per test to avoid cross-test pollution."""
    return PolicyRegistry()


@pytest_asyncio.fixture()
async def async_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def async_session(async_engine):
    factory = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture()
async def async_sample_data(async_session: AsyncSession):
    """Seed the database with sample data through the async session."""
    org = Organization(id=1, name="Acme Corp")
    async_session.add(org)

    alice = User(id=1, name="Alice", role="admin", org_id=1)
    bob = User(id=2, name="Bob", role="editor", org_id=1)
    charlie = User(id=3, name="Charlie", role="viewer", org_id=None)
    async_session.add_all([alice, bob, charlie])

    tag_public = Tag(id=1, name="python", visibility="public")
    tag_private = Tag(id=2, name="internal", visibility="private")
    async_session.add_all([tag_public, tag_private])

    post1 = Post(id=1, title="Public Post", is_published=True, author_id=1)
    post2 = Post(id=2, title="Draft Post", is_published=False, author_id=1)
    post3 = Post(id=3, title="Bob's Post", is_published=True, author_id=2)
    post1.tags.append(tag_public)
    post2.tags.append(tag_private)
    async_session.add_all([post1, post2, post3])

    await async_session.flush()
    return {
        "users": [alice, bob, charlie],
        "posts": [post1, post2, post3],
        "tags": [tag_public, tag_private],
        "organizations": [org],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAuthorizeQueryAsync:
    """authorize_query() produces correct filters executed via AsyncSession."""

    @pytest.mark.asyncio
    async def test_authorize_query_filters_with_async_session(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """Basic filtering: only published posts are returned."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Only published posts",
        )

        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=99),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 2
        assert all(p.is_published for p in posts)
        titles = {p.title for p in posts}
        assert titles == {"Public Post", "Bob's Post"}

    @pytest.mark.asyncio
    async def test_authorize_query_actor_based_filtering_async(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """Actor-based filtering: only posts by the actor are returned."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Only own posts",
        )

        # Alice (id=1) should see her 2 posts
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=1),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 2
        assert all(p.author_id == 1 for p in posts)

        # Bob (id=2) should see his 1 post
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=2),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 1
        assert posts[0].author_id == 2

    @pytest.mark.asyncio
    async def test_multiple_policies_ored_async(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """Two policies for the same (model, action) are OR'd together."""
        # Policy 1: published posts
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published",
            description="Published posts",
        )
        # Policy 2: own posts (regardless of published status)
        registry.register(
            Post,
            "read",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="Own posts",
        )

        # Alice (id=1) should see all 3 posts:
        # - post1 (published, hers), post2 (draft, hers), post3 (published, Bob's)
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=1),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 3

        # Charlie (id=3) has no posts, so only sees published ones
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=3),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 2
        assert all(p.is_published for p in posts)


class TestRelationshipTraversalAsync:
    """Relationship traversal (has/any) works correctly via AsyncSession."""

    @pytest.mark.asyncio
    async def test_relationship_has_traversal_async(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """MANYTOONE: Post.author.has(User.org_id == actor.org_id)."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.author.has(User.org_id == actor.org_id),
            name="same_org",
            description="Posts by authors in the same org",
        )

        # Actor in org 1 should see posts by Alice (org 1) and Bob (org 1)
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=99, org_id=1),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 3
        assert {p.title for p in posts} == {"Public Post", "Draft Post", "Bob's Post"}

        # Actor in org 999 should see no posts (no authors in that org)
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=99, org_id=999),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 0

    @pytest.mark.asyncio
    async def test_relationship_any_traversal_async(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """MANYTOMANY: Post.tags.any(Tag.visibility == 'public')."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.tags.any(Tag.visibility == "public"),
            name="public_tags",
            description="Posts with at least one public tag",
        )

        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=99),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        # Only post1 has a public tag
        assert len(posts) == 1
        assert posts[0].title == "Public Post"


class TestDenyByDefaultAsync:
    """Empty registry denies all access via AsyncSession."""

    @pytest.mark.asyncio
    async def test_deny_by_default_no_policy_async(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """No policies registered -> zero rows returned."""
        stmt = authorize_query(
            select(Post),
            actor=MockActor(id=1),
            action="read",
            registry=registry,
        )
        result = await async_session.execute(stmt)
        posts = result.scalars().all()

        assert len(posts) == 0


class TestPointChecksAsync:
    """can() and authorize() point checks work with async-fetched instances."""

    @pytest.mark.asyncio
    async def test_can_point_check_works(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """can() evaluates correctly on a Post instance fetched via AsyncSession."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Only published posts",
        )

        # Fetch a published post via async session
        result = await async_session.execute(select(Post).where(Post.id == 1))
        published_post = result.scalars().one()

        # Fetch a draft post via async session
        result = await async_session.execute(select(Post).where(Post.id == 2))
        draft_post = result.scalars().one()

        # can() uses sync SQLite internally — works fine with detached instances
        assert can(MockActor(id=99), "read", published_post, registry=registry) is True
        assert can(MockActor(id=99), "read", draft_post, registry=registry) is False

    @pytest.mark.asyncio
    async def test_authorize_raises_when_denied(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """authorize() raises AuthorizationDenied for a draft post."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Only published posts",
        )

        result = await async_session.execute(select(Post).where(Post.id == 2))
        draft_post = result.scalars().one()

        with pytest.raises(AuthorizationDenied) as exc_info:
            authorize(MockActor(id=99), "read", draft_post, registry=registry)

        assert exc_info.value.action == "read"
        assert exc_info.value.resource_type == "Post"

    @pytest.mark.asyncio
    async def test_authorize_passes_when_allowed(
        self,
        async_session: AsyncSession,
        async_sample_data: dict,
        registry: PolicyRegistry,
    ) -> None:
        """authorize() returns None when the actor is allowed."""
        registry.register(
            Post,
            "read",
            lambda actor: Post.is_published == True,  # noqa: E712
            name="published_only",
            description="Only published posts",
        )

        result = await async_session.execute(select(Post).where(Post.id == 1))
        published_post = result.scalars().one()

        # Should not raise
        result_val = authorize(MockActor(id=99), "read", published_post, registry=registry)
        assert result_val is None
