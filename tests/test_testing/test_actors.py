"""Tests for sqla_authz.testing._actors — MockActor and factory functions."""

from __future__ import annotations

import dataclasses

import pytest

from sqla_authz._types import ActorLike
from sqla_authz.testing._actors import MockActor, make_admin, make_anonymous, make_user


class TestMockActor:
    """MockActor satisfies ActorLike and has correct defaults."""

    def test_satisfies_actor_like_protocol(self) -> None:
        actor = MockActor(id=1)
        assert isinstance(actor, ActorLike)

    def test_default_role_is_viewer(self) -> None:
        actor = MockActor(id=1)
        assert actor.role == "viewer"

    def test_default_org_id_is_none(self) -> None:
        actor = MockActor(id=1)
        assert actor.org_id is None

    def test_with_string_id(self) -> None:
        actor = MockActor(id="user-abc")
        assert actor.id == "user-abc"
        assert isinstance(actor, ActorLike)

    def test_is_frozen_immutable(self) -> None:
        actor = MockActor(id=1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            actor.id = 2  # type: ignore[misc]

    def test_custom_attributes(self) -> None:
        actor = MockActor(id=5, role="editor", org_id=10)
        assert actor.id == 5
        assert actor.role == "editor"
        assert actor.org_id == 10


class TestMakeAdmin:
    """make_admin() creates admin MockActors."""

    def test_creates_admin_role(self) -> None:
        actor = make_admin()
        assert actor.role == "admin"

    def test_default_id_is_one(self) -> None:
        actor = make_admin()
        assert actor.id == 1

    def test_custom_id(self) -> None:
        actor = make_admin(id=99)
        assert actor.id == 99
        assert actor.role == "admin"

    def test_satisfies_actor_like(self) -> None:
        assert isinstance(make_admin(), ActorLike)


class TestMakeUser:
    """make_user() creates regular MockActors."""

    def test_default_role_is_viewer(self) -> None:
        actor = make_user()
        assert actor.role == "viewer"

    def test_default_id_is_one(self) -> None:
        actor = make_user()
        assert actor.id == 1

    def test_custom_values(self) -> None:
        actor = make_user(id=5, role="editor", org_id=3)
        assert actor.id == 5
        assert actor.role == "editor"
        assert actor.org_id == 3

    def test_satisfies_actor_like(self) -> None:
        assert isinstance(make_user(), ActorLike)


class TestMakeAnonymous:
    """make_anonymous() creates anonymous actors."""

    def test_id_is_zero(self) -> None:
        actor = make_anonymous()
        assert actor.id == 0

    def test_role_is_anonymous(self) -> None:
        actor = make_anonymous()
        assert actor.role == "anonymous"

    def test_satisfies_actor_like(self) -> None:
        assert isinstance(make_anonymous(), ActorLike)
