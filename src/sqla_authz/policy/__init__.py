"""Policy engine — registration and lookup of authorization policies."""

from sqla_authz.policy._base import PolicyRegistration
from sqla_authz.policy._decorator import policy
from sqla_authz.policy._predicate import Predicate, always_allow, always_deny, predicate
from sqla_authz.policy._registry import PolicyRegistry, get_default_registry

__all__ = [
    "Predicate",
    "PolicyRegistration",
    "PolicyRegistry",
    "always_allow",
    "always_deny",
    "get_default_registry",
    "policy",
    "predicate",
]
