"""sqla-authz — Embedded SQLAlchemy 2.0-native authorization library.

Converts declarative Python policies into SQL WHERE clauses.
No external servers, no network round-trips.

Example::

    from sqla_authz import policy, authorize_query

    @policy(Post, "read")
    def post_read(actor: User) -> ColumnElement[bool]:
        return (Post.is_published == True) | (Post.author_id == actor.id)

    stmt = select(Post).order_by(Post.created_at.desc())
    stmt = authorize_query(stmt, actor=current_user, action="read")
    result = await session.execute(stmt)
"""

from importlib.metadata import PackageNotFoundError, version

from sqla_authz._checks import authorize, can
from sqla_authz._types import ActorLike
from sqla_authz.compiler._query import authorize_query
from sqla_authz.config._config import AuthzConfig, configure
from sqla_authz.exceptions import (
    AuthorizationDenied,
    AuthzError,
    NoPolicyError,
    PolicyCompilationError,
)
from sqla_authz.policy._decorator import policy
from sqla_authz.policy._registry import PolicyRegistry

try:
    __version__ = version("sqla-authz")
except PackageNotFoundError:
    __version__ = "dev"

__all__ = [
    "__version__",
    "ActorLike",
    "AuthorizationDenied",
    "AuthzConfig",
    "AuthzError",
    "NoPolicyError",
    "PolicyCompilationError",
    "PolicyRegistry",
    "authorize",
    "authorize_query",
    "can",
    "configure",
    "policy",
]
