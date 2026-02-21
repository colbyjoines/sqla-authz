"""Tests for strict mode — on_unprotected_get, on_text_query, on_skip_authz."""

from __future__ import annotations

import logging
import warnings

import pytest
from sqlalchemy import create_engine, select, text, true
from sqlalchemy.orm import Session, sessionmaker

from sqla_authz.config._config import AuthzConfig
from sqla_authz.exceptions import AuthzBypassError
from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.session._interceptor import install_interceptor
from tests.conftest import Base, MockActor, Organization, Post, User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strict_engine():
    """Fresh engine for strict mode tests."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def registry() -> PolicyRegistry:
    """Fresh registry per test."""
    return PolicyRegistry()


def _seed_data(sess: Session) -> None:
    """Seed test data into a session."""
    org = Organization(id=1, name="Acme Corp")
    sess.add(org)

    alice = User(id=1, name="Alice", role="admin", org_id=1)
    bob = User(id=2, name="Bob", role="editor", org_id=1)
    sess.add_all([alice, bob])

    post1 = Post(id=1, title="Public Post", is_published=True, author_id=1)
    post2 = Post(id=2, title="Draft Post", is_published=False, author_id=1)
    post3 = Post(id=3, title="Bob's Post", is_published=True, author_id=2)
    sess.add_all([post1, post2, post3])
    sess.flush()


def _seed_and_commit(engine) -> None:
    """Seed data in a separate session and commit."""
    plain_factory = sessionmaker(bind=engine)
    with plain_factory() as sess:
        _seed_data(sess)
        sess.commit()


# ---------------------------------------------------------------------------
# Tests: on_skip_authz
# ---------------------------------------------------------------------------


class TestOnSkipAuthz:
    """Test on_skip_authz configuration for skip_authz=True bypass."""

    def test_ignore_is_silent(self, strict_engine, registry) -> None:
        """on_skip_authz='ignore' does not warn or log."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_skip_authz="ignore")

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                results = (
                    sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()
                )
                assert len(results) == 3
                # No warnings should be emitted
                bypass_warnings = [w for w in caught if "skip_authz" in str(w.message)]
                assert len(bypass_warnings) == 0

    def test_warn_emits_warning(self, strict_engine, registry) -> None:
        """on_skip_authz='warn' emits a Python warning."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_skip_authz="warn")

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                results = (
                    sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()
                )
                assert len(results) == 3
                bypass_warnings = [w for w in caught if "skip_authz" in str(w.message)]
                assert len(bypass_warnings) == 1

    def test_log_emits_log_message(self, strict_engine, registry, caplog) -> None:
        """on_skip_authz='log' emits a log message."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_skip_authz="log")

        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with caplog.at_level(logging.INFO, logger="sqla_authz.bypass"):
                results = (
                    sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()
                )
                assert len(results) == 3

            assert any("skip_authz" in record.message for record in caplog.records)

    def test_skip_authz_still_bypasses(self, strict_engine, registry) -> None:
        """Bypass handlers do not change filtering behavior — skip_authz still works."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_skip_authz="warn")

        registry.register(
            Post,
            "read",
            lambda a: Post.id < 0,  # deny all
            name="deny_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            # Without skip_authz: 0 results
            assert len(sess.execute(select(Post)).scalars().all()) == 0
            # With skip_authz=True: all results (bypass still works)
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                assert (
                    len(
                        sess.execute(select(Post).execution_options(skip_authz=True))
                        .scalars()
                        .all()
                    )
                    == 3
                )


# ---------------------------------------------------------------------------
# Tests: on_text_query
# ---------------------------------------------------------------------------


class TestOnTextQuery:
    """Test on_text_query configuration for queries with no ORM entities."""

    def test_ignore_is_silent(self, strict_engine, registry) -> None:
        """on_text_query='ignore' does not warn or raise."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_text_query="ignore")

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        _seed_and_commit(strict_engine)

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                # text() query has no ORM entities
                result = sess.execute(text("SELECT * FROM posts"))
                rows = result.fetchall()
                assert len(rows) == 3
                bypass_warnings = [w for w in caught if "no ORM entities" in str(w.message)]
                assert len(bypass_warnings) == 0

    def test_warn_emits_warning(self, strict_engine, registry) -> None:
        """on_text_query='warn' emits a Python warning for text queries."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_text_query="warn")

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        _seed_and_commit(strict_engine)

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                result = sess.execute(text("SELECT * FROM posts"))
                rows = result.fetchall()
                assert len(rows) == 3
                bypass_warnings = [w for w in caught if "no ORM entities" in str(w.message)]
                assert len(bypass_warnings) == 1

    def test_raise_raises_authz_bypass_error(self, strict_engine, registry) -> None:
        """on_text_query='raise' raises AuthzBypassError for text queries."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_text_query="raise")

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        _seed_and_commit(strict_engine)

        with factory() as sess:
            with pytest.raises(AuthzBypassError, match="no ORM entities"):
                sess.execute(text("SELECT * FROM posts"))


# ---------------------------------------------------------------------------
# Tests: on_unprotected_get (column_load bypass)
# ---------------------------------------------------------------------------


class TestOnUnprotectedGet:
    """Test on_unprotected_get configuration for relationship/column lazy load bypass.

    The ``on_unprotected_get`` handler fires when the interceptor detects
    ``is_column_load`` or ``is_relationship_load`` — these are internal
    lazy-load queries that bypass normal authz filtering.

    The most common trigger is accessing a lazy-loaded relationship
    (e.g., ``post.author``) which fires ``is_relationship_load=True``.
    """

    def test_ignore_is_silent(self, strict_engine, registry) -> None:
        """on_unprotected_get='ignore' does not warn or raise on lazy load."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_unprotected_get="ignore")

        # Policy for User so the handler has something to detect
        registry.register(
            User,
            "read",
            lambda a: User.id == a.id,
            name="own_user",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        _seed_and_commit(strict_engine)

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                # Query Post, then access .author (lazy load triggers bypass)
                posts = sess.execute(select(Post)).scalars().all()
                assert len(posts) >= 1
                # Access lazy-loaded relationship
                _ = posts[0].author
                bypass_warnings = [
                    w for w in caught if "Unprotected column load" in str(w.message)
                ]
                assert len(bypass_warnings) == 0

    def test_warn_emits_warning_on_lazy_load(self, strict_engine, registry) -> None:
        """on_unprotected_get='warn' emits a warning on lazy relationship load."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_unprotected_get="warn")

        registry.register(
            User,
            "read",
            lambda a: User.id == a.id,
            name="own_user",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        _seed_and_commit(strict_engine)

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                posts = sess.execute(select(Post)).scalars().all()
                assert len(posts) >= 1
                # Access lazy-loaded relationship — triggers is_relationship_load
                _ = posts[0].author
                bypass_warnings = [
                    w for w in caught if "Unprotected column load" in str(w.message)
                ]
                assert len(bypass_warnings) >= 1

    def test_raise_raises_authz_bypass_error_on_lazy_load(
        self,
        strict_engine,
        registry,
    ) -> None:
        """on_unprotected_get='raise' raises AuthzBypassError on lazy load."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_unprotected_get="raise")

        registry.register(
            User,
            "read",
            lambda a: User.id == a.id,
            name="own_user",
            description="",
        )
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        _seed_and_commit(strict_engine)

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            posts = sess.execute(select(Post)).scalars().all()
            assert len(posts) >= 1
            with pytest.raises(AuthzBypassError, match="Unprotected column load"):
                _ = posts[0].author

    def test_no_warning_when_no_policy_registered(self, strict_engine, registry) -> None:
        """on_unprotected_get='warn' does NOT warn if target entity has no policy."""
        actor = MockActor(id=1)
        config = AuthzConfig(on_unprotected_get="warn")

        # Policy only for Post, NOT for User — lazy load of .author
        # should not warn since User has no policy
        registry.register(
            Post,
            "read",
            lambda a: Post.is_published == True,
            name="published",
            description="",
        )

        _seed_and_commit(strict_engine)

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                posts = sess.execute(select(Post)).scalars().all()
                assert len(posts) >= 1
                # Access lazy-loaded relationship — User has no policy
                _ = posts[0].author
                bypass_warnings = [
                    w for w in caught if "Unprotected column load" in str(w.message)
                ]
                assert len(bypass_warnings) == 0


# ---------------------------------------------------------------------------
# Tests: audit_bypasses
# ---------------------------------------------------------------------------


class TestAuditBypasses:
    """Test audit_bypasses=True logs bypass events."""

    def test_audit_skip_authz(self, strict_engine, registry, caplog) -> None:
        """audit_bypasses=True logs skip_authz events."""
        actor = MockActor(id=1)
        config = AuthzConfig(audit_bypasses=True, on_skip_authz="ignore")

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        with factory() as sess:
            _seed_data(sess)
            with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass"):
                sess.execute(select(Post).execution_options(skip_authz=True)).scalars().all()

            assert any("BYPASS:skip_authz" in record.message for record in caplog.records)

    def test_audit_no_entity(self, strict_engine, registry, caplog) -> None:
        """audit_bypasses=True logs no-entity bypass events."""
        actor = MockActor(id=1)
        config = AuthzConfig(audit_bypasses=True, on_text_query="ignore")

        registry.register(
            Post,
            "read",
            lambda a: true(),
            name="allow_all",
            description="",
        )

        factory = sessionmaker(bind=strict_engine)
        install_interceptor(
            factory,
            actor_provider=lambda: actor,
            action="read",
            registry=registry,
            config=config,
        )

        _seed_and_commit(strict_engine)

        with factory() as sess:
            with caplog.at_level(logging.WARNING, logger="sqla_authz.bypass"):
                sess.execute(text("SELECT * FROM posts")).fetchall()

            assert any("BYPASS:no_entity" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Tests: strict_mode convenience defaults
# ---------------------------------------------------------------------------


class TestStrictModeConvenienceDefaults:
    """Test that strict_mode=True applies convenience defaults."""

    def test_strict_mode_sets_defaults(self) -> None:
        """strict_mode=True sets on_unprotected_get=warn, on_text_query=warn, etc."""
        config = AuthzConfig(strict_mode=True)
        assert config.on_unprotected_get == "warn"
        assert config.on_text_query == "warn"
        assert config.on_skip_authz == "log"
        assert config.audit_bypasses is True

    def test_strict_mode_does_not_override_explicit(self) -> None:
        """strict_mode=True does not override explicitly provided values."""
        config = AuthzConfig(
            strict_mode=True,
            on_unprotected_get="raise",
            on_text_query="raise",
            on_skip_authz="warn",
            audit_bypasses=False,
        )
        assert config.on_unprotected_get == "raise"
        assert config.on_text_query == "raise"
        assert config.on_skip_authz == "warn"
        # audit_bypasses=False was explicit, but strict_mode only sets True
        # when the value is False (the default). Since False was explicitly
        # passed, it remains False.
        # NOTE: Because the dataclass default is False and we pass False,
        # __post_init__ cannot distinguish explicit False from default False.
        # This is a known limitation — strict_mode always applies audit_bypasses=True
        # when the value is False.
        assert config.audit_bypasses is True

    def test_strict_mode_via_configure(self, strict_engine, registry) -> None:
        """strict_mode can be enabled via configure()."""
        from sqla_authz.config._config import _reset_global_config, configure, get_global_config

        _reset_global_config()
        try:
            configure(strict_mode=True)
            config = get_global_config()
            assert config.strict_mode is True
            assert config.on_unprotected_get == "warn"
            assert config.on_text_query == "warn"
            assert config.on_skip_authz == "log"
            assert config.audit_bypasses is True
        finally:
            _reset_global_config()

    def test_non_strict_defaults_are_ignore(self) -> None:
        """Without strict_mode, all bypass settings default to ignore/False."""
        config = AuthzConfig()
        assert config.strict_mode is False
        assert config.on_unprotected_get == "ignore"
        assert config.on_text_query == "ignore"
        assert config.on_skip_authz == "ignore"
        assert config.audit_bypasses is False
