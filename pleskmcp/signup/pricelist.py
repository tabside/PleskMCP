"""The shared price list (JSON): hosting price and orderable TLDs.

The same file renders the website's /domains/ page. The bundled copy lives in
pleskmcp/signup/data/domains.json; SIGNUP_PRICE_LIST_FILE points to a mounted
file instead. Prices are in the organisation's currency (CHF) incl. VAT.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from ..config import ConfigError

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED = os.path.join(HERE, "data", "domains.json")


@dataclass(frozen=True)
class Tld:
    tld: str
    price_per_year: float | None
    orderable: bool
    owner_fields: tuple[str, ...]
    note: str | None


@dataclass(frozen=True)
class PriceList:
    currency: str
    hosting_name: str
    hosting_price: float
    hosting_storage_gb: int
    tlds: dict[str, Tld]
    raw: dict[str, Any]

    def tld_for(self, domain: str) -> Tld | None:
        """Longest matching TLD entry of a domain name (co.uk before uk)."""
        parts = domain.lower().strip(".").split(".")
        for i in range(1, len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self.tlds:
                return self.tlds[candidate]
        return None

    def public(self) -> dict[str, Any]:
        """What the website and the order form may see."""
        return {
            "currency": self.currency,
            "hosting": {"name": self.hosting_name, "price_per_year": self.hosting_price, "storage_gb": self.hosting_storage_gb},
            "tlds": [
                {"tld": t.tld, "price_per_year": t.price_per_year, "orderable": t.orderable, "note": t.note, "owner_fields": list(t.owner_fields)}
                for t in self.tlds.values()
            ],
        }


def load_price_list(path: str | None) -> PriceList:
    file = path or BUNDLED
    try:
        with open(file, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"price list {file} cannot be read: {exc}") from exc
    try:
        hosting = raw["hosting"]
        tlds: dict[str, Tld] = {}
        for entry in raw["tlds"]:
            tld = str(entry["tld"]).lower().strip(".")
            if not tld or tld in tlds:
                raise ValueError(f"duplicate or empty tld entry {tld!r}")
            price = entry.get("price_per_year")
            orderable = bool(entry.get("orderable", False))
            if orderable and (price is None or float(price) <= 0):
                raise ValueError(f"tld {tld} is orderable but has no price")
            tlds[tld] = Tld(
                tld=tld,
                price_per_year=float(price) if price is not None else None,
                orderable=orderable,
                owner_fields=tuple(str(f) for f in entry.get("owner_fields", [])),
                note=entry.get("note"),
            )
        return PriceList(
            currency=str(raw.get("currency", "CHF")),
            hosting_name=str(hosting["name"]),
            hosting_price=float(hosting["price_per_year"]),
            hosting_storage_gb=int(hosting.get("storage_gb", 0)),
            tlds=tlds,
            raw=raw,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"price list {file} is invalid: {exc}") from exc
