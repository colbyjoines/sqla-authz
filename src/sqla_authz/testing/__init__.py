"""sqla-authz testing utilities — MockActor, assertions, and fixtures.

Provides test helpers for verifying authorization policies:

- **MockActor / factories**: Lightweight actors for tests.
- **Assertion helpers**: ``assert_authorized``, ``assert_denied``,
  ``assert_query_contains``.
- **Fixtures**: ``authz_registry``, ``authz_config``, ``authz_context``.

Example::

    from sqla_authz.testing import MockActor, assert_authorized
    from sqlalchemy import select

    def test_admin_reads_all(session, sample_data):
        assert_authorized(session, select(Post), MockActor(id=1, role="admin"), "read")
"""

from sqla_authz.testing._actors import MockActor, make_admin, make_anonymous, make_user
from sqla_authz.testing._assertions import (
    assert_authorized,
    assert_denied,
    assert_query_contains,
)
from sqla_authz.testing._fixtures import (
    authz_config,
    authz_context,
    authz_registry,
    isolated_authz_state,
)
from sqla_authz.testing._isolation import isolated_authz
from sqla_authz.testing._simulation import (
    PolicyCoverage,
    PolicyDiff,
    PolicyMatrix,
    SimulationResult,
    assert_policy_sql_snapshot,
    diff_policies,
    policy_matrix,
    simulate_query,
)

__all__ = [
    "MockActor",
    "PolicyCoverage",
    "PolicyDiff",
    "PolicyMatrix",
    "SimulationResult",
    "assert_authorized",
    "assert_denied",
    "assert_policy_sql_snapshot",
    "assert_query_contains",
    "authz_config",
    "authz_context",
    "authz_registry",
    "diff_policies",
    "isolated_authz",
    "isolated_authz_state",
    "make_admin",
    "make_anonymous",
    "make_user",
    "policy_matrix",
    "simulate_query",
]
