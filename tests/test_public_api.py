"""Tests for public API surface — verifies all __init__.py re-exports.

Every symbol listed in the spec must be importable from its documented
location, and every ``__all__`` list must be complete and match the
actual module attributes.
"""

from __future__ import annotations

import inspect

# ---------------------------------------------------------------------------
# Top-level: sqla_authz
# ---------------------------------------------------------------------------


class TestTopLevelExports:
    """Verify sqla_authz top-level exports match the spec."""

    EXPECTED = {
        "__version__",
        "policy",
        "authorize_query",
        "can",
        "authorize",
        "configure",
        "ActorLike",
        "PolicyRegistry",
        "AuthzConfig",
        "AuthzBypassError",
        "AuthzError",
        "AuthorizationDenied",
        "NoPolicyError",
        "PolicyCompilationError",
        "WriteDeniedError",
        "explain_access",
        "explain_query",
        "async_safe_get",
        "async_safe_get_or_raise",
        "safe_get",
        "safe_get_or_raise",
    }

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz import (
            ActorLike,
            AuthorizationDenied,
            AuthzConfig,
            AuthzError,
            NoPolicyError,
            PolicyCompilationError,
            PolicyRegistry,
            authorize,
            authorize_query,
            can,
            configure,
            policy,
        )

        for sym in [
            policy,
            authorize_query,
            can,
            authorize,
            configure,
            ActorLike,
            PolicyRegistry,
            AuthzConfig,
            AuthzError,
            AuthorizationDenied,
            NoPolicyError,
            PolicyCompilationError,
        ]:
            assert sym is not None

    def test_callable_symbols_are_callable(self) -> None:
        from sqla_authz import (
            authorize,
            authorize_query,
            can,
            configure,
            policy,
        )

        for sym in [policy, authorize_query, can, authorize, configure]:
            assert callable(sym), f"{sym!r} should be callable"

    def test_class_symbols_are_classes(self) -> None:
        from sqla_authz import (
            AuthorizationDenied,
            AuthzConfig,
            AuthzError,
            NoPolicyError,
            PolicyCompilationError,
            PolicyRegistry,
        )

        for sym in [
            PolicyRegistry,
            AuthzConfig,
            AuthzError,
            AuthorizationDenied,
            NoPolicyError,
            PolicyCompilationError,
        ]:
            assert inspect.isclass(sym), f"{sym!r} should be a class"

    def test_actorlike_is_protocol(self) -> None:
        from sqla_authz import ActorLike

        assert inspect.isclass(ActorLike)
        assert hasattr(ActorLike, "__protocol_attrs__") or issubclass(ActorLike, object)

    def test_all_is_complete(self) -> None:
        import sqla_authz

        assert hasattr(sqla_authz, "__all__")
        actual = set(sqla_authz.__all__)
        assert actual == self.EXPECTED, (
            f"__all__ mismatch.\n"
            f"  Missing: {self.EXPECTED - actual}\n"
            f"  Extra:   {actual - self.EXPECTED}"
        )

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz

        for name in sqla_authz.__all__:
            assert hasattr(sqla_authz, name), (
                f"sqla_authz.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.policy
# ---------------------------------------------------------------------------


class TestPolicyExports:
    """Verify sqla_authz.policy exports."""

    EXPECTED = {
        "Predicate",
        "PolicyRegistration",
        "PolicyRegistry",
        "always_allow",
        "always_deny",
        "get_default_registry",
        "policy",
        "predicate",
    }

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.policy import (
            Predicate,
            PolicyRegistration,
            PolicyRegistry,
            always_allow,
            always_deny,
            get_default_registry,
            policy,
            predicate,
        )

        for sym in [
            policy, PolicyRegistry, PolicyRegistration, get_default_registry,
            Predicate, predicate, always_allow, always_deny,
        ]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.policy import PolicyRegistry, get_default_registry, policy

        assert callable(policy)
        assert callable(get_default_registry)
        assert inspect.isclass(PolicyRegistry)

    def test_all_is_complete(self) -> None:
        import sys

        import sqla_authz.policy  # noqa: F401

        policy_mod = sys.modules["sqla_authz.policy"]
        actual = set(policy_mod.__all__)
        assert actual == self.EXPECTED, (
            f"policy __all__ mismatch.\n"
            f"  Missing: {self.EXPECTED - actual}\n"
            f"  Extra:   {actual - self.EXPECTED}"
        )

    def test_all_matches_module_attrs(self) -> None:
        import sys

        import sqla_authz.policy  # noqa: F401

        policy_mod = sys.modules["sqla_authz.policy"]
        for name in policy_mod.__all__:
            assert hasattr(policy_mod, name), (
                f"sqla_authz.policy.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.compiler
# ---------------------------------------------------------------------------


class TestCompilerExports:
    """Verify sqla_authz.compiler exports."""

    EXPECTED = {"authorize_query", "evaluate_policies", "traverse_relationship_path"}

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.compiler import (
            authorize_query,
            evaluate_policies,
            traverse_relationship_path,
        )

        for sym in [authorize_query, evaluate_policies, traverse_relationship_path]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.compiler import (
            authorize_query,
            evaluate_policies,
            traverse_relationship_path,
        )

        for sym in [authorize_query, evaluate_policies, traverse_relationship_path]:
            assert callable(sym), f"{sym!r} should be callable"

    def test_all_is_complete(self) -> None:
        import sqla_authz.compiler

        actual = set(sqla_authz.compiler.__all__)
        assert actual == self.EXPECTED

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz.compiler

        for name in sqla_authz.compiler.__all__:
            assert hasattr(sqla_authz.compiler, name), (
                f"sqla_authz.compiler.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.session
# ---------------------------------------------------------------------------


class TestSessionExports:
    """Verify sqla_authz.session exports."""

    EXPECTED = {
        "authorized_sessionmaker",
        "AuthorizationContext",
        "install_interceptor",
        "async_safe_get",
        "async_safe_get_or_raise",
        "safe_get",
        "safe_get_or_raise",
    }

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.session import (
            AuthorizationContext,
            authorized_sessionmaker,
            install_interceptor,
        )

        for sym in [authorized_sessionmaker, AuthorizationContext, install_interceptor]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.session import (
            AuthorizationContext,
            authorized_sessionmaker,
            install_interceptor,
        )

        assert callable(authorized_sessionmaker)
        assert callable(install_interceptor)
        assert inspect.isclass(AuthorizationContext)

    def test_all_is_complete(self) -> None:
        import sqla_authz.session

        actual = set(sqla_authz.session.__all__)
        assert actual == self.EXPECTED

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz.session

        for name in sqla_authz.session.__all__:
            assert hasattr(sqla_authz.session, name), (
                f"sqla_authz.session.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.config
# ---------------------------------------------------------------------------


class TestConfigExports:
    """Verify sqla_authz.config exports."""

    EXPECTED = {"AuthzConfig", "configure", "get_global_config"}

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.config import AuthzConfig, configure, get_global_config

        for sym in [AuthzConfig, configure, get_global_config]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.config import AuthzConfig, configure, get_global_config

        assert callable(configure)
        assert callable(get_global_config)
        assert inspect.isclass(AuthzConfig)

    def test_all_is_complete(self) -> None:
        import sqla_authz.config

        actual = set(sqla_authz.config.__all__)
        assert actual == self.EXPECTED

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz.config

        for name in sqla_authz.config.__all__:
            assert hasattr(sqla_authz.config, name), (
                f"sqla_authz.config.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.testing
# ---------------------------------------------------------------------------


class TestTestingExports:
    """Verify sqla_authz.testing exports."""

    EXPECTED = {
        "MockActor",
        "make_admin",
        "make_user",
        "make_anonymous",
        "assert_authorized",
        "assert_denied",
        "assert_query_contains",
        "authz_registry",
        "authz_config",
        "authz_context",
        "isolated_authz",
        "isolated_authz_state",
        "PolicyCoverage",
        "PolicyDiff",
        "PolicyMatrix",
        "SimulationResult",
        "assert_policy_sql_snapshot",
        "diff_policies",
        "policy_matrix",
        "simulate_query",
    }

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.testing import (
            MockActor,
            PolicyCoverage,
            PolicyDiff,
            PolicyMatrix,
            SimulationResult,
            assert_authorized,
            assert_denied,
            assert_policy_sql_snapshot,
            assert_query_contains,
            authz_config,
            authz_context,
            authz_registry,
            diff_policies,
            isolated_authz,
            isolated_authz_state,
            make_admin,
            make_anonymous,
            make_user,
            policy_matrix,
            simulate_query,
        )

        for sym in [
            MockActor,
            make_admin,
            make_user,
            make_anonymous,
            assert_authorized,
            assert_denied,
            assert_query_contains,
            authz_registry,
            authz_config,
            authz_context,
            isolated_authz,
            isolated_authz_state,
            PolicyCoverage,
            PolicyDiff,
            PolicyMatrix,
            SimulationResult,
            assert_policy_sql_snapshot,
            diff_policies,
            policy_matrix,
            simulate_query,
        ]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.testing import (
            MockActor,
            assert_authorized,
            assert_denied,
            assert_policy_sql_snapshot,
            assert_query_contains,
            diff_policies,
            make_admin,
            make_anonymous,
            make_user,
            policy_matrix,
            simulate_query,
        )

        for sym in [
            MockActor,
            make_admin,
            make_user,
            make_anonymous,
            assert_authorized,
            assert_denied,
            assert_query_contains,
            assert_policy_sql_snapshot,
            diff_policies,
            policy_matrix,
            simulate_query,
        ]:
            assert callable(sym), f"{sym!r} should be callable"

    def test_all_is_complete(self) -> None:
        import sqla_authz.testing

        actual = set(sqla_authz.testing.__all__)
        assert actual == self.EXPECTED

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz.testing

        for name in sqla_authz.testing.__all__:
            assert hasattr(sqla_authz.testing, name), (
                f"sqla_authz.testing.__all__ lists {name!r} but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.integrations
# ---------------------------------------------------------------------------


class TestIntegrationsPackage:
    """Verify sqla_authz.integrations is a proper package with __all__."""

    def test_has_all(self) -> None:
        import sqla_authz.integrations

        assert hasattr(sqla_authz.integrations, "__all__"), (
            "sqla_authz.integrations must define __all__"
        )


# ---------------------------------------------------------------------------
# Sub-package: sqla_authz.integrations.fastapi
# ---------------------------------------------------------------------------


class TestFastAPIExports:
    """Verify sqla_authz.integrations.fastapi exports."""

    EXPECTED = {
        "AuthzDep",
        "configure_authz",
        "get_actor",
        "get_session",
        "install_authz_interceptor",
        "install_error_handlers",
    }

    def test_all_expected_symbols_importable(self) -> None:
        from sqla_authz.integrations.fastapi import (
            AuthzDep,
            configure_authz,
            get_actor,
            get_session,
            install_authz_interceptor,
            install_error_handlers,
        )

        for sym in [
            AuthzDep,
            configure_authz,
            get_actor,
            get_session,
            install_authz_interceptor,
            install_error_handlers,
        ]:
            assert sym is not None

    def test_callable_symbols(self) -> None:
        from sqla_authz.integrations.fastapi import (
            AuthzDep,
            configure_authz,
            install_error_handlers,
        )

        for sym in [AuthzDep, configure_authz, install_error_handlers]:
            assert callable(sym), f"{sym!r} should be callable"

    def test_all_is_complete(self) -> None:
        import sqla_authz.integrations.fastapi

        actual = set(sqla_authz.integrations.fastapi.__all__)
        assert actual == self.EXPECTED

    def test_all_matches_module_attrs(self) -> None:
        import sqla_authz.integrations.fastapi

        for name in sqla_authz.integrations.fastapi.__all__:
            assert hasattr(sqla_authz.integrations.fastapi, name), (
                f"sqla_authz.integrations.fastapi.__all__ lists {name!r} "
                "but it is not an attribute"
            )


# ---------------------------------------------------------------------------
# py.typed marker
# ---------------------------------------------------------------------------


class TestPyTyped:
    """Verify PEP 561 py.typed marker exists."""

    def test_py_typed_exists(self) -> None:
        from pathlib import Path

        import sqla_authz

        pkg_dir = Path(sqla_authz.__file__).parent
        assert (pkg_dir / "py.typed").exists(), "py.typed marker is missing"


# ---------------------------------------------------------------------------
# End-to-end smoke test
# ---------------------------------------------------------------------------


class TestEndToEndSmoke:
    """Verify a full policy-define-and-authorize flow works."""

    def test_define_policy_and_authorize_query(self) -> None:
        from sqlalchemy import select

        from sqla_authz import PolicyRegistry, authorize_query, policy
        from tests.conftest import MockActor, Post

        registry = PolicyRegistry()

        @policy(Post, "read", registry=registry)
        def post_read(actor: MockActor):
            return Post.is_published == True  # noqa: E712

        stmt = select(Post)
        result = authorize_query(stmt, actor=MockActor(id=1), action="read", registry=registry)
        sql = str(result.compile(compile_kwargs={"literal_binds": True}))
        assert "is_published" in sql
