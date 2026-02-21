"""Explain/dry-run mode — structured insight into authorization decisions."""

from sqla_authz.explain._access import explain_access
from sqla_authz.explain._models import (
    AccessExplanation,
    AccessPolicyEvaluation,
    AuthzExplanation,
    EntityExplanation,
    PolicyEvaluation,
)
from sqla_authz.explain._query import explain_query

__all__ = [
    "AccessExplanation",
    "AccessPolicyEvaluation",
    "AuthzExplanation",
    "EntityExplanation",
    "PolicyEvaluation",
    "explain_access",
    "explain_query",
]
