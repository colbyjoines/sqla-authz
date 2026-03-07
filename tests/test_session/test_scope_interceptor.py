"""Integration test: session interceptor applies scopes automatically."""

from __future__ import annotations

from sqlalchemy import Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from sqla_authz.policy._registry import PolicyRegistry
from sqla_authz.policy._scope import ScopeRegistration
from sqla_authz.session._interceptor import install_interceptor

from tests.conftest import MockActor


# ---------------------------------------------------------------------------
# Test-local models with org_id
# ---------------------------------------------------------------------------


class InterceptBase(DeclarativeBase):
    pass


class TenantItem(InterceptBase):
    __tablename__ = "intercept_tenant_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    org_id: Mapped[int] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(default=True)


class TestScopeWithInterceptor:
    """Test that scopes are applied automatically via the session interceptor."""

    def test_interceptor_applies_scope_filter(self) -> None:
        """Session interceptor produces SQL containing scope filters."""
        engine = create_engine("sqlite:///:memory:")
        InterceptBase.metadata.create_all(engine)

        registry = PolicyRegistry()

        # Register a policy
        registry.register(
            TenantItem, "read",
            lambda actor: TenantItem.is_active == True,  # noqa: E712
            name="active_only", description="",
        )

        # Register a scope
        registry.register_scope(ScopeRegistration(
            applies_to=(TenantItem,),
            fn=lambda actor, Model: Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        actor = MockActor(id=1, org_id=42)
        factory = sessionmaker(bind=engine)
        install_interceptor(factory, actor_provider=lambda: actor, registry=registry)

        # Seed data
        with Session(engine) as seed_session:
            seed_session.add_all([
                TenantItem(id=1, name="mine-active", org_id=42, is_active=True),
                TenantItem(id=2, name="mine-inactive", org_id=42, is_active=False),
                TenantItem(id=3, name="other-active", org_id=99, is_active=True),
                TenantItem(id=4, name="other-inactive", org_id=99, is_active=False),
            ])
            seed_session.commit()

        # Query through authorized session
        with factory() as session:
            items = session.execute(select(TenantItem)).scalars().all()

        # Should only see active items in org 42
        names = {item.name for item in items}
        assert names == {"mine-active"}

    def test_interceptor_admin_bypass(self) -> None:
        """Admin scope bypass (true()) works through session interceptor."""
        engine = create_engine("sqlite:///:memory:")
        InterceptBase.metadata.create_all(engine)

        registry = PolicyRegistry()

        registry.register(
            TenantItem, "read",
            lambda actor: TenantItem.is_active == True,  # noqa: E712
            name="active_only", description="",
        )

        from sqlalchemy import true

        registry.register_scope(ScopeRegistration(
            applies_to=(TenantItem,),
            fn=lambda actor, Model: true() if actor.role == "admin" else Model.org_id == actor.org_id,
            name="tenant", description="", actions=None,
        ))

        admin = MockActor(id=1, role="admin", org_id=1)
        factory = sessionmaker(bind=engine)
        install_interceptor(factory, actor_provider=lambda: admin, registry=registry)

        with Session(engine) as seed_session:
            seed_session.add_all([
                TenantItem(id=1, name="org1-active", org_id=1, is_active=True),
                TenantItem(id=2, name="org2-active", org_id=2, is_active=True),
                TenantItem(id=3, name="org2-inactive", org_id=2, is_active=False),
            ])
            seed_session.commit()

        with factory() as session:
            items = session.execute(select(TenantItem)).scalars().all()

        # Admin sees all active items across orgs (scope bypassed, policy still applied)
        names = {item.name for item in items}
        assert names == {"org1-active", "org2-active"}
