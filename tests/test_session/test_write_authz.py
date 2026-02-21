"""Tests for write authorization — UPDATE/DELETE interception."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, sessionmaker

from sqla_authz.config._config import AuthzConfig
from sqla_authz.exceptions import WriteDeniedError
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._interceptor import install_interceptor
from tests.conftest import MockActor, Post

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_session(
    engine,
    registry: PolicyRegistry,
    config: AuthzConfig,
    actor: MockActor,
) -> Session:
    """Create a session with the interceptor installed."""
    factory = sessionmaker(bind=engine)
    install_interceptor(
        factory,
        actor_provider=lambda: actor,
        action="read",
        registry=registry,
        config=config,
    )
    return factory()


# ---------------------------------------------------------------------------
# UPDATE interception
# ---------------------------------------------------------------------------


class TestInterceptUpdates:
    """UPDATE statements are intercepted when intercept_updates=True."""

    def test_update_filtered_by_policy(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "update",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        config = AuthzConfig(intercept_updates=True, on_write_denied="filter")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        # Actor 1 (Alice) owns posts 1 and 2
        sess.execute(update(Post).values(title="Updated"))
        sess.commit()

        # Verify only Alice's posts were updated
        plain_sess = sessionmaker(bind=engine)()
        posts = plain_sess.execute(select(Post).order_by(Post.id)).scalars().all()

        assert posts[0].title == "Updated"  # post1 by Alice
        assert posts[1].title == "Updated"  # post2 by Alice
        assert posts[2].title == "Bob's Post"  # post3 by Bob, untouched

    def test_update_no_policy_raises(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_updates=True, on_write_denied="raise")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        with pytest.raises(WriteDeniedError, match="not authorized to update"):
            sess.execute(update(Post).values(title="Updated"))

    def test_update_no_policy_filter_mode(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_updates=True, on_write_denied="filter")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        # No policy => WHERE FALSE => zero rows updated
        sess.execute(update(Post).values(title="Updated"))
        sess.commit()

        # No posts should have been updated
        plain_sess = sessionmaker(bind=engine)()
        posts = plain_sess.execute(select(Post)).scalars().all()
        assert all(p.title != "Updated" for p in posts)

    def test_update_not_intercepted_when_disabled(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_updates=False)
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        # Should pass through without interception
        sess.execute(update(Post).values(title="Updated"))
        sess.commit()

        plain_sess = sessionmaker(bind=engine)()
        posts = plain_sess.execute(select(Post)).scalars().all()
        assert all(p.title == "Updated" for p in posts)

    def test_update_skip_authz(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_updates=True, on_write_denied="raise")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        # skip_authz should bypass write interception
        sess.execute(
            update(Post).values(title="Updated"),
            execution_options={"skip_authz": True},
        )
        sess.commit()

        plain_sess = sessionmaker(bind=engine)()
        posts = plain_sess.execute(select(Post)).scalars().all()
        assert all(p.title == "Updated" for p in posts)

    def test_update_custom_action(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "bulk_update",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        config = AuthzConfig(intercept_updates=True, on_write_denied="raise")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        # Override action via execution_options
        sess.execute(
            update(Post).values(title="Updated"),
            execution_options={"authz_action": "bulk_update"},
        )
        sess.commit()

        plain_sess = sessionmaker(bind=engine)()
        posts = plain_sess.execute(select(Post).order_by(Post.id)).scalars().all()
        assert posts[0].title == "Updated"
        assert posts[2].title == "Bob's Post"


# ---------------------------------------------------------------------------
# DELETE interception
# ---------------------------------------------------------------------------


class TestInterceptDeletes:
    """DELETE statements are intercepted when intercept_deletes=True."""

    def test_delete_filtered_by_policy(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        registry.register(
            Post,
            "delete",
            lambda actor: Post.author_id == actor.id,
            name="own_posts",
            description="",
        )
        config = AuthzConfig(intercept_deletes=True, on_write_denied="filter")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        sess.execute(delete(Post))
        sess.commit()

        # Only Alice's posts should be deleted
        plain_sess = sessionmaker(bind=engine)()
        remaining = plain_sess.execute(select(Post)).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].title == "Bob's Post"

    def test_delete_no_policy_raises(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_deletes=True, on_write_denied="raise")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        with pytest.raises(WriteDeniedError, match="not authorized to delete"):
            sess.execute(delete(Post))

    def test_delete_no_policy_filter_mode(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_deletes=True, on_write_denied="filter")
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        sess.execute(delete(Post))
        sess.commit()

        # No policy => WHERE FALSE => zero rows deleted
        plain_sess = sessionmaker(bind=engine)()
        remaining = plain_sess.execute(select(Post)).scalars().all()
        assert len(remaining) == 3

    def test_delete_not_intercepted_when_disabled(self, engine, session, sample_data) -> None:
        registry = PolicyRegistry()
        config = AuthzConfig(intercept_deletes=False)
        actor = MockActor(id=1)

        sess = _setup_session(engine, registry, config, actor)
        sess.execute(delete(Post))
        sess.commit()

        plain_sess = sessionmaker(bind=engine)()
        remaining = plain_sess.execute(select(Post)).scalars().all()
        assert len(remaining) == 0


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestWriteAuthzConfig:
    """AuthzConfig validates write authorization settings."""

    def test_valid_on_write_denied_raise(self) -> None:
        config = AuthzConfig(on_write_denied="raise")
        assert config.on_write_denied == "raise"

    def test_valid_on_write_denied_filter(self) -> None:
        config = AuthzConfig(on_write_denied="filter")
        assert config.on_write_denied == "filter"

    def test_invalid_on_write_denied(self) -> None:
        with pytest.raises(ValueError, match="on_write_denied"):
            AuthzConfig(on_write_denied="invalid")  # type: ignore[arg-type]

    def test_defaults(self) -> None:
        config = AuthzConfig()
        assert config.intercept_updates is False
        assert config.intercept_deletes is False
        assert config.on_write_denied == "raise"

    def test_merge_preserves_write_config(self) -> None:
        config = AuthzConfig(intercept_updates=True, on_write_denied="filter")
        merged = config.merge(on_missing_policy="raise")
        assert merged.intercept_updates is True
        assert merged.on_write_denied == "filter"

    def test_merge_overrides_write_config(self) -> None:
        config = AuthzConfig()
        merged = config.merge(
            intercept_updates=True,
            intercept_deletes=True,
            on_write_denied="filter",
        )
        assert merged.intercept_updates is True
        assert merged.intercept_deletes is True
        assert merged.on_write_denied == "filter"


# ---------------------------------------------------------------------------
# WriteDeniedError
# ---------------------------------------------------------------------------


class TestWriteDeniedError:
    """WriteDeniedError carries context about the denied operation."""

    def test_attributes(self) -> None:
        actor = MockActor(id=1)
        err = WriteDeniedError(actor=actor, action="update", resource_type="Post")
        assert err.actor is actor
        assert err.action == "update"
        assert err.resource_type == "Post"
        assert "update" in str(err)
        assert "Post" in str(err)

    def test_custom_message(self) -> None:
        err = WriteDeniedError(
            actor=MockActor(id=1),
            action="delete",
            resource_type="Post",
            message="Custom denial message",
        )
        assert str(err) == "Custom denial message"
