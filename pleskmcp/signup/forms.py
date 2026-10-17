"""Server-side validation of the order form.

Errors are reported per field in German for the customer. Nothing here reveals
whether an e-mail address is already a customer.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .pricelist import PriceList, Tld

# ISO 3166-1 alpha-2 codes offered in the form (Europe first, then the rest). The list is also used
# to validate the country field; Plesk, bexio and Netim all take the alpha-2 code.
COUNTRIES: list[tuple[str, str]] = [
    ("CH", "Schweiz"), ("LI", "Liechtenstein"), ("DE", "Deutschland"), ("AT", "Österreich"), ("FR", "Frankreich"), ("IT", "Italien"),
    ("ES", "Spanien"), ("PT", "Portugal"), ("NL", "Niederlande"), ("BE", "Belgien"), ("LU", "Luxemburg"), ("GB", "Vereinigtes Königreich"),
    ("IE", "Irland"), ("DK", "Dänemark"), ("SE", "Schweden"), ("NO", "Norwegen"), ("FI", "Finnland"), ("IS", "Island"), ("PL", "Polen"),
    ("CZ", "Tschechien"), ("SK", "Slowakei"), ("HU", "Ungarn"), ("SI", "Slowenien"), ("HR", "Kroatien"), ("RO", "Rumänien"), ("BG", "Bulgarien"),
    ("GR", "Griechenland"), ("EE", "Estland"), ("LV", "Lettland"), ("LT", "Litauen"), ("MT", "Malta"), ("CY", "Zypern"), ("US", "USA"),
    ("CA", "Kanada"), ("AU", "Australien"), ("NZ", "Neuseeland"), ("JP", "Japan"), ("SG", "Singapur"), ("AE", "Vereinigte Arabische Emirate"),
    ("ZA", "Südafrika"), ("BR", "Brasilien"), ("MX", "Mexiko"), ("IN", "Indien"), ("TR", "Türkei"), ("IL", "Israel"),
]
COUNTRY_CODES = {code for code, _ in COUNTRIES}

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
PHONE_RE = re.compile(r"^\+[1-9][0-9]{5,15}$")
NAME_RE = re.compile(r"^[^\x00-\x1f<>\"\\/{}\[\]=;]{1,60}$")


@dataclass
class OrderInput:
    company: str | None
    first_name: str
    last_name: str
    street: str
    zip: str
    city: str
    country: str
    email: str
    phone: str | None
    domain_mode: str  # own | new
    domain: str
    tld: Tld | None
    terms_version: str
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors


def normalize_domain(value: str) -> str:
    """Lower-case, trailing dot and leading www. removed, IDN converted to ACE."""
    name = (value or "").strip().lower().rstrip(".")
    if name.startswith("www."):
        name = name[4:]
    if any(ord(ch) > 127 for ch in name):
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return name
    return name


def domain_format_ok(name: str) -> bool:
    if not name or len(name) > 253 or "." not in name:
        return False
    labels = name.split(".")
    if len(labels[-1]) < 2 or labels[-1].isdigit():
        return False
    return all(LABEL_RE.match(label) for label in labels)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"[\s().\-/]", "", value.strip())
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    return digits


def ascii_slug(value: str) -> str:
    text = unicodedata.normalize("NFKD", value)
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]", "", text)


def _clean(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def parse_order(form: dict[str, Any], price_list: PriceList, *, terms_version: str, new_domains_enabled: bool) -> OrderInput:
    company = _clean(form.get("company"), 100) or None
    first_name = _clean(form.get("first_name"), 60)
    last_name = _clean(form.get("last_name"), 60)
    street = _clean(form.get("street"), 120)
    zip_code = _clean(form.get("zip"), 16)
    city = _clean(form.get("city"), 60)
    country = _clean(form.get("country"), 2).upper()
    email = _clean(form.get("email"), 255).lower()
    phone_raw = _clean(form.get("phone"), 32)
    phone = normalize_phone(phone_raw) if phone_raw else None
    domain_mode = _clean(form.get("domain_mode"), 8).lower()
    domain = normalize_domain(_clean(form.get("domain"), 253))
    terms = form.get("terms") in ("1", "on", "true", "yes", True)

    data = OrderInput(company, first_name, last_name, street, zip_code, city, country, email, phone, domain_mode, domain, None, terms_version)
    errors = data.errors
    if not first_name or not NAME_RE.match(first_name):
        errors["first_name"] = "Bitte den Vornamen angeben."
    if not last_name or not NAME_RE.match(last_name):
        errors["last_name"] = "Bitte den Nachnamen angeben."
    if company and not NAME_RE.match(company[:60]):
        errors["company"] = "Der Firmenname enthält ungültige Zeichen."
    if not street or len(street) < 3:
        errors["street"] = "Bitte Strasse und Hausnummer angeben."
    if not zip_code or not re.match(r"^[A-Za-z0-9 -]{3,16}$", zip_code):
        errors["zip"] = "Bitte eine gültige Postleitzahl angeben."
    if not city:
        errors["city"] = "Bitte den Ort angeben."
    if country not in COUNTRY_CODES:
        errors["country"] = "Bitte ein Land aus der Liste wählen."
    if not email or not EMAIL_RE.match(email) or len(email) > 254:
        errors["email"] = "Bitte eine gültige E-Mail-Adresse angeben."
    if phone and not PHONE_RE.match(phone):
        errors["phone"] = "Bitte die Telefonnummer international angeben, z.B. +41 44 123 45 67."
    if domain_mode not in ("own", "new"):
        errors["domain_mode"] = "Bitte wählen, ob eine eigene oder eine neue Domain genutzt wird."
    if not domain_format_ok(domain):
        errors["domain"] = "Bitte einen gültigen Domainnamen angeben, z.B. meine-firma.ch."
    elif domain_mode == "new":
        if not new_domains_enabled:
            errors["domain_mode"] = "Neue Domains können derzeit nicht online bestellt werden. Bitte eine eigene Domain angeben."
        else:
            tld = price_list.tld_for(domain)
            if tld is None or not tld.orderable or tld.price_per_year is None:
                errors["domain"] = "Diese Endung ist online nicht bestellbar. Sie erhalten die Domain auf Anfrage."
            else:
                data.tld = tld
                if len(domain.split(".")) != len(tld.tld.split(".")) + 1:
                    errors["domain"] = "Bitte nur die Hauptdomain angeben, ohne Subdomain."
                if "phone" in tld.owner_fields and not phone:
                    errors["phone"] = "Für die Registrierung einer Domain braucht die Registrierungsstelle eine Telefonnummer."
                if "company" in tld.owner_fields and not company:
                    errors["company"] = "Diese Endung kann nur von Firmen registriert werden."
    if not terms:
        errors["terms"] = "Bitte die AGB akzeptieren."
    return data


def honeypot_filled(form: dict[str, Any]) -> bool:
    return bool(str(form.get("website") or "").strip())
