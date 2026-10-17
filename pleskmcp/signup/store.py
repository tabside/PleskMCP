"""Orders and their audit events (table signup_orders, signup_events).

The order row holds the customer's data (it is the order) plus every external
identifier the flows need to be idempotent. Events never carry personal data,
only the order id, codes and external ids.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, func, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base

AWAITING_CONFIRMATION = "awaiting_confirmation"
AWAITING_PAYMENT = "awaiting_payment"
ACTIVATING = "activating"
ACTIVE = "active"
SUSPENDED = "suspended"
PENDING_DELETION = "pending_deletion"
DELETED = "deleted"
NEEDS_ATTENTION = "needs_attention"
EXPIRED = "expired"  # e-mail never confirmed
STATUSES = (AWAITING_CONFIRMATION, AWAITING_PAYMENT, ACTIVATING, ACTIVE, SUSPENDED, PENDING_DELETION, DELETED, NEEDS_ATTENTION, EXPIRED)
# statuses that reserve the domain (an unconfirmed order does not, so a fake order cannot block a domain)
OPEN_STATUSES = (AWAITING_PAYMENT, ACTIVATING, ACTIVE, SUSPENDED, PENDING_DELETION, NEEDS_ATTENTION)


class SignupOrder(Base):
    __tablename__ = "signup_orders"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    attention_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # the order
    company: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_name: Mapped[str] = mapped_column(String(60), nullable=False)
    last_name: Mapped[str] = mapped_column(String(60), nullable=False)
    street: Mapped[str] = mapped_column(String(120), nullable=False)
    zip: Mapped[str] = mapped_column(String(16), nullable=False)
    city: Mapped[str] = mapped_column(String(60), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
    domain_mode: Mapped[str] = mapped_column(String(8), nullable=False)  # own | new
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    tld: Mapped[str | None] = mapped_column(String(32), nullable=True)
    domain_price: Mapped[float | None] = mapped_column(Float, nullable=True)
    hosting_price: Mapped[float] = mapped_column(Float, nullable=False)
    terms_version: Mapped[str] = mapped_column(String(32), nullable=False)
    terms_accepted_at: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # billing
    bexio_contact_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rebill_external_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rebill_recurring_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bexio_invoice_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # first invoice
    invoice_due_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    paid_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    subscription_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    period_end: Mapped[str | None] = mapped_column(String(10), nullable=True)  # last day of the paid period
    last_invoice_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # newest invoice of the subscription
    last_invoice_due: Mapped[str | None] = mapped_column(String(10), nullable=True)
    last_invoice_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # paid | open | cancelled | unknown
    last_invoice_checked_at: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # support
    zammad_ticket_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # domain registration
    netim_owner_contact_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    netim_operation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    netim_operation_started: Mapped[int | None] = mapped_column(Integer, nullable=True)
    domain_status: Mapped[str] = mapped_column(String(16), nullable=False, default="none")  # none | pending | registered | failed
    domain_expires: Mapped[str | None] = mapped_column(String(10), nullable=True)
    domain_renewed_until: Mapped[str | None] = mapped_column(String(10), nullable=True)
    domain_renew_notice_for: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # Plesk
    plesk_login: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plesk_customer_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plesk_webspace_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sysuser: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # lifecycle
    activated_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    suspended_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    suspend_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cancelled_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    delete_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    backup_started_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    backup_done_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    backup_result: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deleted_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confirm_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confirm_expires: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confirmed_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    welcome_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    welcome_token_expires: Mapped[int | None] = mapped_column(Integer, nullable=True)
    welcome_sent_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    __table_args__ = (Index("signup_orders_status", "status"), Index("signup_orders_email", "email"), Index("signup_orders_domain", "domain"))

    def as_dict(self) -> dict[str, Any]:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SignupEvent(Base):
    __tablename__ = "signup_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(String(32), nullable=False)
    ts: Mapped[int] = mapped_column(Integer, nullable=False)
    event: Mapped[str] = mapped_column(String(48), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    __table_args__ = (Index("signup_events_order", "order_id"),)


@dataclass
class Order:
    """Detached copy of an order row."""

    data: dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        try:
            return self.data[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def display_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()


def new_order_id() -> str:
    return secrets.token_hex(8)


class SignupStore:
    def __init__(self, engine: AsyncEngine):
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def create_order(self, **fields: Any) -> Order:
        now = int(time.time())
        row = SignupOrder(id=fields.pop("id", None) or new_order_id(), created_at=now, updated_at=now, **fields)
        async with self._sessions() as session:
            session.add(row)
            await session.commit()
        return Order(row.as_dict())

    async def get(self, order_id: str) -> Order | None:
        async with self._sessions() as session:
            row = await session.get(SignupOrder, order_id)
        return Order(row.as_dict()) if row else None

    async def update(self, order_id: str, **fields: Any) -> None:
        fields["updated_at"] = int(time.time())
        async with self._sessions() as session:
            await session.execute(update(SignupOrder).where(SignupOrder.id == order_id).values(**fields))
            await session.commit()

    async def set_status(self, order_id: str, status: str, **fields: Any) -> None:
        await self.update(order_id, status=status, **fields)

    async def list(self, *, status: str | tuple[str, ...] | None = None, limit: int = 500) -> list[Order]:
        stmt = select(SignupOrder).order_by(SignupOrder.created_at.desc()).limit(limit)
        if isinstance(status, str):
            stmt = stmt.where(SignupOrder.status == status)
        elif status:
            stmt = stmt.where(SignupOrder.status.in_(status))
        async with self._sessions() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return [Order(r.as_dict()) for r in rows]

    async def find_open_by_domain(self, domain: str) -> Order | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(SignupOrder).where(func.lower(SignupOrder.domain) == domain.lower(), SignupOrder.status.in_(OPEN_STATUSES)).limit(1)
                )
            ).scalar_one_or_none()
        return Order(row.as_dict()) if row else None

    async def find_awaiting_duplicate(self, email: str, domain: str) -> Order | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(SignupOrder)
                    .where(func.lower(SignupOrder.email) == email.lower(), func.lower(SignupOrder.domain) == domain.lower(), SignupOrder.status.in_((AWAITING_CONFIRMATION, AWAITING_PAYMENT)))
                    .limit(1)
                )
            ).scalar_one_or_none()
        return Order(row.as_dict()) if row else None

    async def find_by_confirm_token(self, token_hash: str) -> Order | None:
        async with self._sessions() as session:
            row = (await session.execute(select(SignupOrder).where(SignupOrder.confirm_token_hash == token_hash).limit(1))).scalar_one_or_none()
        return Order(row.as_dict()) if row else None

    async def confirm(self, order_id: str, token_hash: str) -> bool:
        """awaiting_confirmation -> awaiting_payment, exactly once per token."""
        now = int(time.time())
        async with self._sessions() as session:
            result = await session.execute(
                update(SignupOrder)
                .where(SignupOrder.id == order_id, SignupOrder.confirm_token_hash == token_hash, SignupOrder.status == AWAITING_CONFIRMATION)
                .values(status=AWAITING_PAYMENT, confirm_token_hash=None, confirmed_at=now, updated_at=now)
            )
            await session.commit()
            return result.rowcount == 1

    async def expire_unconfirmed(self, older_than: int) -> list[str]:
        """Orders still awaiting confirmation whose link expired; returns their ids after marking them expired."""
        now = int(time.time())
        async with self._sessions() as session:
            rows = (
                await session.execute(select(SignupOrder.id).where(SignupOrder.status == AWAITING_CONFIRMATION, SignupOrder.confirm_expires < older_than))
            ).scalars().all()
            if rows:
                await session.execute(update(SignupOrder).where(SignupOrder.id.in_(list(rows))).values(status=EXPIRED, confirm_token_hash=None, updated_at=now))
                await session.commit()
        return list(rows)

    async def find_by_welcome_token(self, token_hash: str) -> Order | None:
        async with self._sessions() as session:
            row = (await session.execute(select(SignupOrder).where(SignupOrder.welcome_token_hash == token_hash).limit(1))).scalar_one_or_none()
        return Order(row.as_dict()) if row else None

    async def consume_welcome_token(self, order_id: str, token_hash: str) -> bool:
        async with self._sessions() as session:
            result = await session.execute(
                update(SignupOrder).where(SignupOrder.id == order_id, SignupOrder.welcome_token_hash == token_hash).values(welcome_token_hash=None, updated_at=int(time.time()))
            )
            await session.commit()
            return result.rowcount == 1

    async def plesk_login_taken(self, login: str) -> bool:
        async with self._sessions() as session:
            return (await session.execute(select(func.count()).select_from(SignupOrder).where(SignupOrder.plesk_login == login))).scalar_one() > 0

    async def add_event(self, order_id: str, event: str, **data: Any) -> None:
        async with self._sessions() as session:
            session.add(SignupEvent(order_id=order_id, ts=int(time.time()), event=event, data_json=json.dumps({k: v for k, v in data.items() if v is not None}, ensure_ascii=False)))
            await session.commit()

    async def events(self, order_id: str, limit: int = 200) -> list[dict[str, Any]]:
        async with self._sessions() as session:
            rows = (await session.execute(select(SignupEvent).where(SignupEvent.order_id == order_id).order_by(SignupEvent.ts.desc(), SignupEvent.id.desc()).limit(limit))).scalars().all()
        return [{"ts": r.ts, "event": r.event, **json.loads(r.data_json)} for r in rows]

    async def counts(self) -> dict[str, int]:
        async with self._sessions() as session:
            rows = (await session.execute(select(SignupOrder.status, func.count()).group_by(SignupOrder.status))).all()
        return {r[0]: int(r[1]) for r in rows}
