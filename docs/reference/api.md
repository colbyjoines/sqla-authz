# API Reference

## Core

::: sqla_authz.policy
    options:
      show_root_heading: true
      members:
        - policy

::: sqla_authz.authorize_query
    options:
      show_root_heading: true

::: sqla_authz.can
    options:
      show_root_heading: true

::: sqla_authz.authorize
    options:
      show_root_heading: true

::: sqla_authz.configure
    options:
      show_root_heading: true

## Types

::: sqla_authz.ActorLike
    options:
      show_root_heading: true

::: sqla_authz.PolicyRegistry
    options:
      show_root_heading: true
      members:
        - register
        - lookup
        - has_policy
        - registered_entities
        - clear

## Configuration

::: sqla_authz.AuthzConfig
    options:
      show_root_heading: true
      members:
        - merge

## Predicates

::: sqla_authz.policy._predicate.Predicate
    options:
      show_root_heading: true

::: sqla_authz.policy._predicate.predicate
    options:
      show_root_heading: true

::: sqla_authz.policy._predicate.always_allow
    options:
      show_root_heading: true

::: sqla_authz.policy._predicate.always_deny
    options:
      show_root_heading: true

## Session

::: sqla_authz.session.authorized_sessionmaker
    options:
      show_root_heading: true

::: sqla_authz.session.install_interceptor
    options:
      show_root_heading: true

::: sqla_authz.session._context.AuthorizationContext
    options:
      show_root_heading: true

## Exceptions

::: sqla_authz.exceptions
    options:
      show_root_heading: true
      members:
        - AuthzError
        - AuthorizationDenied
        - NoPolicyError
        - PolicyCompilationError

## FastAPI Integration

::: sqla_authz.integrations.fastapi.AuthzDep
    options:
      show_root_heading: true

::: sqla_authz.integrations.fastapi.configure_authz
    options:
      show_root_heading: true

::: sqla_authz.integrations.fastapi.install_error_handlers
    options:
      show_root_heading: true

## Testing

::: sqla_authz.testing
    options:
      show_root_heading: true
      members:
        - MockActor
        - make_admin
        - make_user
        - make_anonymous
        - assert_authorized
        - assert_denied
        - assert_query_contains
        - authz_registry
        - authz_config
        - authz_context
