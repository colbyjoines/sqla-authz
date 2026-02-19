# Changelog

All notable changes to sqla-authz are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-02-19

### Added

- **Flask integration** (`AuthzExtension`) — Blueprint-aware authorization via a Flask extension with `init_app()` support and automatic error handler registration.
- **Composable predicates** — `@predicate` decorator with `&`, `|`, and `~` operators for building reusable, composable authorization conditions without boilerplate.
- **Audit logging** — Configurable `AuditLogger` that records policy decisions (actor, action, resource, result) to any sink via a pluggable interface.
- **Performance benchmark suite** — `pytest-benchmark` integration under `tests/benchmarks/` for tracking query compilation and filter application overhead.
- **GitHub Actions CI/CD pipeline** — Automated test, lint, type-check, and publish workflows for Python 3.10–3.12 on Ubuntu and Windows.
- **Comprehensive edge case coverage** — Test suite coverage at 95%+, including NULL handling, empty result sets, nested relationship traversal, and concurrent session scenarios.

### Changed

- Finalized all public API surfaces with a 1.0 stability guarantee — no breaking changes without a major version bump.
- Improved docstrings across all public functions and classes to include parameter descriptions, return types, and usage examples.

---

## [0.2.0] - 2026-02-19

### Added

- **FastAPI integration** — `AuthzDep` dependency, `configure_authz()` app setup helper, and `install_error_handlers()` for automatic 403 response generation on `AuthorizationDenied`.
- **Session interception** — Opt-in automatic query filtering via `do_orm_execute` event hook. `authorized_sessionmaker()` creates pre-configured sessions; `install_interceptor()` adds filtering to an existing session.
- **Point checks** — `can(actor, action, resource)` returns a boolean; `authorize(actor, action, resource)` raises `AuthorizationDenied` on failure.
- **`AuthorizationContext` dataclass** — Carries `actor`, `action`, and optional `resource` through the session interception pipeline.
- **Testing utilities** — `MockActor` factory class with `make_admin()`, `make_user()`, and `make_anonymous()` constructors for building test actors without a real user model.
- **Assertion helpers** — `assert_authorized()`, `assert_denied()`, and `assert_query_contains()` for expressive policy test assertions.
- **Pytest plugin** — Registered via `pytest11` entry point; provides `authz_registry`, `authz_config`, and `authz_context` fixtures automatically when the package is installed.
- **Layered configuration** — `AuthzConfig` dataclass with `merge()` for composing global, session-level, and per-query configuration. `configure()` sets the global config; `get_global_config()` retrieves it.

---

## [0.1.0] - 2026-02-19

### Added

- **`@policy` decorator** — Registers a function as an authorization policy for a `(model, action)` pair. Multiple policies for the same pair are OR'd together.
- **`PolicyRegistry`** — Thread-safe registry mapping `(model, action)` pairs to lists of policy functions. Supports `register()`, `lookup()`, `has_policy()`, `registered_entities()`, and `clear()`.
- **`authorize_query()`** — Primary public API. Accepts a SQLAlchemy 2.0 `Select` statement, an actor, and an action; returns the statement with authorization filters applied via `.where()`.
- **SQL compilation layer** — Evaluates registered policy functions and combines their results into a single `ColumnElement[bool]` using OR logic. Missing policies produce `WHERE FALSE` (deny-by-default).
- **Relationship traversal** — `has()` and `any()` (EXISTS subquery) chaining for filtering across SQLAlchemy relationships. Automatically selects `has()` for `MANYTOONE` and `any()` for `ONETOMANY`/`MANYTOMANY` via `sqlalchemy.inspect()`.
- **`ActorLike` protocol** — Structural typing protocol (PEP 544) for actors. Any object with an `id` attribute satisfies the protocol — no forced inheritance.
- **Exception hierarchy** — `AuthzError` (base), `AuthorizationDenied`, `NoPolicyError`, and `PolicyCompilationError`.
- **Deny-by-default** — Queries against models with no registered policy return `WHERE FALSE` (zero rows). Configurable to raise `NoPolicyError` instead via `on_missing_policy="raise"`.
- **Sync and async support** — The entire policy and compiler pipeline is synchronous (no I/O). The same `authorize_query()` call works unchanged with both `Session` and `AsyncSession`.
- **PEP 561 `py.typed` marker** — Signals to type checkers that the package ships inline type annotations.
