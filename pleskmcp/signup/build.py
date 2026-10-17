"""Wires the signup service from Settings (None when SIGNUP_ENABLED is off)."""

from __future__ import annotations

from typing import Any

from redis.asyncio import Redis

from ..audit import AuditLog
from ..config import Settings
from ..db import Store
from ..plesk_api import PleskClient
from .clients import BexioClient, Mailer, NetimClient, RebillClient, ZammadClient
from .pricelist import load_price_list
from .service import SignupService
from .store import SignupStore


class _Closing(SignupService):
    async def aclose(self) -> None:
        await self.rebill.aclose()
        await self.bexio.aclose()
        await self.zammad.aclose()


def build_signup(settings: Settings, store: Store, redis: Redis, plesk: PleskClient, audit: AuditLog, *, transports: dict[str, Any] | None = None, mailer: Any | None = None) -> SignupService | None:
    cfg = settings.signup
    if cfg is None:
        return None
    transports = transports or {}
    price_list = load_price_list(cfg.price_list_file)
    netim = NetimClient(cfg.netim_api_url, cfg.netim_login, cfg.netim_secret, transport=transports.get("netim")) if cfg.new_domains_enabled else None
    return _Closing(
        settings,
        cfg,
        SignupStore(store.engine),
        redis,
        plesk,
        audit,
        price_list,
        rebill=RebillClient(cfg.rebill_api_url, cfg.rebill_api_token, transport=transports.get("rebill")),
        bexio=BexioClient(cfg.bexio_api_url, cfg.bexio_api_token, transport=transports.get("bexio")),
        netim=netim,
        zammad=ZammadClient(cfg.zammad_url, cfg.zammad_token, cfg.zammad_group, transport=transports.get("zammad")),
        mailer=mailer
        or Mailer(
            host=cfg.smtp_host,
            port=cfg.smtp_port,
            user=cfg.smtp_user,
            password=cfg.smtp_password,
            starttls=cfg.smtp_starttls,
            ssl=cfg.smtp_ssl,
            sender=cfg.mail_from,
            reply_to=cfg.mail_reply_to,
            bcc=cfg.mail_bcc,
        ),
    )
