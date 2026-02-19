"""Tests for _types.py — ActorLike protocol and type aliases."""

from __future__ import annotations

from dataclasses import dataclass

from sqla_authz._types import ActorLike


class TestActorLikeProtocol:
    """ActorLike is a runtime_checkable Protocol requiring an `id` attribute."""

    def test_dataclass_with_int_id_satisfies_protocol(self):
        @dataclass
        class UserWithIntId:
            id: int

        user = UserWithIntId(id=42)
        assert isinstance(user, ActorLike)

    def test_dataclass_with_str_id_satisfies_protocol(self):
        @dataclass
        class UserWithStrId:
            id: str

        user = UserWithStrId(id="abc-123")
        assert isinstance(user, ActorLike)

    def test_sqlalchemy_model_satisfies_protocol(self):
        """SA models with an `id` column should satisfy ActorLike."""
        from tests.conftest import User

        user = User(id=1, name="test")
        assert isinstance(user, ActorLike)

    def test_plain_object_with_id_satisfies_protocol(self):
        class PlainActor:
            def __init__(self, id: int):
                self.id = id

        actor = PlainActor(id=99)
        assert isinstance(actor, ActorLike)

    def test_object_without_id_does_not_satisfy_protocol(self):
        @dataclass
        class NoIdActor:
            name: str

        actor = NoIdActor(name="nobody")
        assert not isinstance(actor, ActorLike)

    def test_dict_does_not_satisfy_protocol(self):
        """Dicts with 'id' key should NOT satisfy the protocol."""
        actor = {"id": 1}
        assert not isinstance(actor, ActorLike)

    def test_named_tuple_with_id_satisfies_protocol(self):
        from typing import NamedTuple

        class TupleActor(NamedTuple):
            id: int
            name: str

        actor = TupleActor(id=1, name="tuple-user")
        assert isinstance(actor, ActorLike)
