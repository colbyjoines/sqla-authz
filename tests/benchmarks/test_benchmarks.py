"""Performance benchmarks for sqla-authz core operations."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from sqla_authz.compiler._expression import evaluate_policies
from sqla_authz.compiler._query import authorize_query
from sqla_authz.compiler._relationship import traverse_relationship_path
from sqla_authz.policy._registry import PolicyRegistry

from .conftest import BenchAuthor, BenchOrg, BenchPost, _make_multi_registry

# ---------------------------------------------------------------------------
# Policy evaluation benchmarks (no DB)
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestPolicyEvaluation:
    """Benchmark policy evaluation — no database involved."""

    def test_simple_policy_eval(self, benchmark, simple_registry, mock_actor):
        """evaluate_policies with a single attribute check."""
        benchmark(evaluate_policies, simple_registry, BenchPost, "read", mock_actor)

    def test_complex_policy_eval(self, benchmark, complex_registry, mock_actor):
        """evaluate_policies with OR + relationship traversal."""
        benchmark(evaluate_policies, complex_registry, BenchPost, "read", mock_actor)


# ---------------------------------------------------------------------------
# authorize_query benchmarks (filter injection, no DB execution)
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestAuthorizeQuery:
    """Benchmark authorize_query filter injection — no DB execution."""

    def test_authorize_simple(self, benchmark, simple_registry, mock_actor):
        """authorize_query with a simple attribute policy."""
        stmt = select(BenchPost)
        benchmark(
            authorize_query,
            stmt,
            actor=mock_actor,
            action="read",
            registry=simple_registry,
        )

    def test_authorize_complex(self, benchmark, complex_registry, mock_actor):
        """authorize_query with OR + relationship policy."""
        stmt = select(BenchPost)
        benchmark(
            authorize_query,
            stmt,
            actor=mock_actor,
            action="read",
            registry=complex_registry,
        )


# ---------------------------------------------------------------------------
# Full query execution benchmarks (with DB)
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestFullQueryExecution:
    """Benchmark full query execution with database."""

    def test_query_1k_rows(self, benchmark, populated_session_1k, simple_registry, mock_actor):
        """Full authorized query against 1K rows."""

        def run():
            stmt = select(BenchPost)
            stmt = authorize_query(stmt, actor=mock_actor, action="read", registry=simple_registry)
            populated_session_1k.execute(stmt).scalars().all()

        benchmark(run)

    def test_query_10k_rows(self, benchmark, populated_session_10k, simple_registry, mock_actor):
        """Full authorized query against 10K rows."""

        def run():
            stmt = select(BenchPost)
            stmt = authorize_query(stmt, actor=mock_actor, action="read", registry=simple_registry)
            populated_session_10k.execute(stmt).scalars().all()

        benchmark(run)

    def test_query_100k_rows(self, benchmark, populated_session_100k, simple_registry, mock_actor):
        """Full authorized query against 100K rows."""

        def run():
            stmt = select(BenchPost)
            stmt = authorize_query(stmt, actor=mock_actor, action="read", registry=simple_registry)
            populated_session_100k.execute(stmt).scalars().all()

        benchmark(run)


# ---------------------------------------------------------------------------
# can() point check benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestCanPointCheck:
    """Benchmark can() for a single resource instance."""

    def test_can_check(self, benchmark, bench_session, simple_registry, mock_actor):
        """can() point check against a single post."""
        from sqla_authz._checks import can

        # Create a detached instance to avoid session overhead in the benchmark
        post = BenchPost(id=9999, title="Bench Post", is_published=True, author_id=1)
        bench_session.add(post)
        bench_session.flush()
        bench_session.expunge(post)

        benchmark(can, mock_actor, "read", post, registry=simple_registry)

    def test_can_check_denied(self, benchmark, bench_session, simple_registry, mock_actor):
        """can() point check for a denied resource."""
        from sqla_authz._checks import can

        post = BenchPost(id=9998, title="Draft", is_published=False, author_id=1)
        bench_session.add(post)
        bench_session.flush()
        bench_session.expunge(post)

        benchmark(can, mock_actor, "read", post, registry=simple_registry)


# ---------------------------------------------------------------------------
# Policy scaling benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestPolicyScaling:
    """Benchmark evaluation with varying numbers of registered policies."""

    def test_1_policy(self, benchmark, mock_actor):
        """evaluate_policies with 1 policy."""
        reg = _make_multi_registry(1)
        benchmark(evaluate_policies, reg, BenchPost, "read", mock_actor)

    def test_5_policies(self, benchmark, mock_actor):
        """evaluate_policies with 5 policies."""
        reg = _make_multi_registry(5)
        benchmark(evaluate_policies, reg, BenchPost, "read", mock_actor)

    def test_10_policies(self, benchmark, mock_actor):
        """evaluate_policies with 10 policies."""
        reg = _make_multi_registry(10)
        benchmark(evaluate_policies, reg, BenchPost, "read", mock_actor)

    def test_20_policies(self, benchmark, mock_actor):
        """evaluate_policies with 20 policies."""
        reg = _make_multi_registry(20)
        benchmark(evaluate_policies, reg, BenchPost, "read", mock_actor)


# ---------------------------------------------------------------------------
# Relationship traversal benchmarks
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestRelationshipTraversal:
    """Benchmark relationship traversal at varying depths."""

    def test_1_hop(self, benchmark):
        """traverse_relationship_path with 1-hop: Post -> author."""
        leaf = BenchAuthor.id == 1
        benchmark(traverse_relationship_path, BenchPost, ["author"], leaf)

    def test_2_hop(self, benchmark):
        """traverse_relationship_path with 2-hop: Post -> author -> org."""
        leaf = BenchOrg.id == 1
        benchmark(
            traverse_relationship_path,
            BenchPost,
            ["author", "organization"],
            leaf,
        )

    def test_1_hop_query_execution(self, benchmark, relationship_session, mock_actor):
        """Full query with 1-hop relationship filter."""
        reg = PolicyRegistry()
        reg.register(
            BenchPost,
            "read",
            lambda actor: BenchPost.author.has(BenchAuthor.id == actor.id),
            name="own_posts",
            description="Posts by actor",
        )

        def run():
            stmt = select(BenchPost)
            stmt = authorize_query(stmt, actor=mock_actor, action="read", registry=reg)
            relationship_session.execute(stmt).scalars().all()

        benchmark(run)

    def test_2_hop_query_execution(self, benchmark, relationship_session, mock_actor):
        """Full query with 2-hop relationship filter."""
        reg = PolicyRegistry()
        reg.register(
            BenchPost,
            "read",
            lambda actor: BenchPost.author.has(
                BenchAuthor.organization.has(BenchOrg.id == actor.org_id)
            ),
            name="org_posts",
            description="Posts by org member",
        )

        def run():
            stmt = select(BenchPost)
            stmt = authorize_query(stmt, actor=mock_actor, action="read", registry=reg)
            relationship_session.execute(stmt).scalars().all()

        benchmark(run)
