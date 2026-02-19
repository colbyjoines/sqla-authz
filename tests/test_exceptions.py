"""Tests for exceptions.py — AuthzError hierarchy."""

from __future__ import annotations

import pytest

from sqla_authz.exceptions import (
    AuthorizationDenied,
    AuthzError,
    NoPolicyError,
    PolicyCompilationError,
)


class TestAuthzError:
    """Base exception for all sqla-authz errors."""

    def test_is_exception(self):
        assert issubclass(AuthzError, Exception)

    def test_message(self):
        err = AuthzError("something went wrong")
        assert str(err) == "something went wrong"

    def test_catchable_as_exception(self):
        with pytest.raises(Exception):
            raise AuthzError("test")


class TestAuthorizationDenied:
    """Raised when actor is not authorized."""

    def test_is_authz_error(self):
        assert issubclass(AuthorizationDenied, AuthzError)

    def test_attributes(self):
        err = AuthorizationDenied(
            actor="user-1",
            action="delete",
            resource_type="Post",
        )
        assert err.actor == "user-1"
        assert err.action == "delete"
        assert err.resource_type == "Post"

    def test_default_message(self):
        err = AuthorizationDenied(
            actor="user-1",
            action="delete",
            resource_type="Post",
        )
        msg = str(err)
        assert "user-1" in msg
        assert "delete" in msg
        assert "Post" in msg

    def test_custom_message(self):
        err = AuthorizationDenied(
            actor="user-1",
            action="delete",
            resource_type="Post",
            message="Custom denial message",
        )
        assert str(err) == "Custom denial message"

    def test_catchable_as_authz_error(self):
        with pytest.raises(AuthzError):
            raise AuthorizationDenied(actor="user-1", action="read", resource_type="Post")


class TestNoPolicyError:
    """Raised when no policy is registered for (resource_type, action)."""

    def test_is_authz_error(self):
        assert issubclass(NoPolicyError, AuthzError)

    def test_attributes(self):
        err = NoPolicyError(resource_type="Post", action="delete")
        assert err.resource_type == "Post"
        assert err.action == "delete"

    def test_default_message(self):
        err = NoPolicyError(resource_type="Post", action="delete")
        msg = str(err)
        assert "Post" in msg
        assert "delete" in msg

    def test_catchable_as_authz_error(self):
        with pytest.raises(AuthzError):
            raise NoPolicyError(resource_type="Post", action="read")


class TestPolicyCompilationError:
    """Raised when a policy returns an invalid expression."""

    def test_is_authz_error(self):
        assert issubclass(PolicyCompilationError, AuthzError)

    def test_message(self):
        err = PolicyCompilationError("Policy returned None instead of ColumnElement")
        assert "None" in str(err)

    def test_catchable_as_authz_error(self):
        with pytest.raises(AuthzError):
            raise PolicyCompilationError("bad expression")
