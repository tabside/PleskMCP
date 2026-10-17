"""Mail templates of the signup service (German, UTF-8, real umlauts)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ...config import Settings
    from ..config import SignupSettings
    from ..store import Order

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name: str) -> str:
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return fh.read()


def dns_block(order: "Order", cfg: "SignupSettings") -> str:
    if order.domain_mode == "new":
        lines = [
            f"   Die Domain {order.domain} wurde für Sie registriert und zeigt bereits auf Ihr Hosting.",
            "   Die Registrierung kann einige Stunden dauern, bis sie überall sichtbar ist.",
        ]
        if cfg.nameservers_text:
            lines.append(f"   Nameserver: {cfg.nameservers_text}")
        return "\n".join(lines)
    lines = [
        f"   Damit {order.domain} auf Ihr neues Hosting zeigt, stellen Sie bei Ihrem Domain-Anbieter eines von beidem ein:",
        f"   a) Nameserver auf {cfg.nameservers_text or 'die Nameserver des Hostings (siehe Plesk)'} wechseln, oder",
        f"   b) einen A-Record für {order.domain} und www.{order.domain} auf die IP-Adresse {cfg.plesk_ip_address} setzen.",
        "   Die Umstellung braucht bis zu 24 Stunden. Bis dahin erreichen Sie Ihr Hosting über Plesk.",
    ]
    return "\n".join(lines)


def render_welcome(order: "Order", cfg: "SignupSettings", settings: "Settings", *, token: str) -> tuple[str, str]:
    template = _load("welcome_de.txt")
    sender_name = cfg.mail_from.split("<")[0].strip().strip('"') or settings.service_name
    text = template.format(
        name=order.display_name,
        product=cfg.product_title,
        domain=order.domain,
        welcome_link=f"{settings.public_base_url}/signup/welcome/{token}",
        link_days=cfg.welcome_link_ttl_days,
        panel_url=cfg.panel_login_url,
        login=order.plesk_login or "",
        dns_block=dns_block(order, cfg),
        mcp_url=settings.resource_url,
        account_url=cfg.account_url,
        suspend_days=cfg.suspend_after_days,
        sender_name=sender_name,
    )
    return f"{cfg.product_title} für {order.domain} ist freigeschaltet", text
