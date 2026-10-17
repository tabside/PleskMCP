"""Configuration of the signup service (all from environment variables, see .env.example).

The whole feature is off unless SIGNUP_ENABLED=true. With it on, the credentials of
reBill (which carries the bexio connection), Netim (only when new domains are orderable), Plesk, Zammad and SMTP are
required and the api refuses to start when one is missing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..config import ConfigError, _env, _env_bool, _env_float, _env_int, _env_list

DEFAULT_PRICE_LIST = "pleskmcp/signup/data/domains.json"  # relative to the package root; see pricelist.py


@dataclass(frozen=True)
class SignupSettings:
    enabled: bool
    price_list_file: str | None  # None: the bundled list
    allowed_origins: list[str]  # website origins allowed to call the signup endpoints (CORS)
    token_secret: bytes  # HMAC key for the stateless form tokens
    min_fill_seconds: int
    token_max_age: int
    rate_limit_ip: int
    rate_limit_ip_window: int
    rate_limit_email: int
    rate_limit_email_window: int
    terms_version: str
    terms_url: str
    success_url: str | None  # confirmation page on the website; empty: built-in page
    account_url: str

    # product
    plan_name: str
    hosting_price: float
    hosting_item_text: str
    domain_item_text: str
    currency_id: int
    mwst_type: int
    lead_months: int
    external_ref_prefix: str
    language: str
    product_title: str

    # reBill
    rebill_api_url: str
    rebill_api_token: str

    # Netim
    netim_api_url: str
    netim_login: str | None
    netim_secret: str | None
    netim_contact_admin: str | None
    netim_contact_tech: str | None
    netim_contact_billing: str | None
    netim_nameservers: list[str]
    netim_owner_language: str

    # Plesk (administrator key with write access, separate from PLESK_ADMIN_API_KEY)
    plesk_api_key: str
    plesk_ip_address: str
    plesk_panel_url: str
    plesk_login_link_mode: str  # session | reset_page
    plesk_password_page_path: str

    # Zammad
    zammad_url: str
    zammad_token: str
    zammad_group: str

    # mail
    smtp_host: str
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_starttls: bool
    smtp_ssl: bool
    mail_from: str
    mail_reply_to: str | None
    mail_bcc: str | None
    panel_login_url: str

    # scheduler
    payment_poll_seconds: int
    lifecycle_seconds: int
    suspend_after_days: int
    delete_after_days: int
    domain_renew_days_before: int
    delete_backup_mode: str  # plesk | manual | none
    backup_timeout: int  # seconds the pleskbackup call may take
    max_attempts: int
    welcome_link_ttl_days: int
    confirm_ttl_hours: int  # how long the e-mail confirmation link is valid
    netim_operation_timeout_hours: int

    # admin overview
    admin_user: str | None
    admin_password: str | None

    nameservers_text: str = field(default="")

    @property
    def new_domains_enabled(self) -> bool:
        return bool(self.netim_login and self.netim_secret)


def load_signup_settings(*, public_base_url: str, plesk_url: str, data_encryption_key: str | None, require_runtime: bool) -> SignupSettings | None:
    enabled = _env_bool("SIGNUP_ENABLED", False)
    if not enabled:
        return None
    missing: list[str] = []

    def req(name: str) -> str:
        value = _env(name)
        if value is None:
            missing.append(name)
            return ""
        return value

    secret = _env("SIGNUP_TOKEN_SECRET") or data_encryption_key or ""
    if not secret:
        missing.append("SIGNUP_TOKEN_SECRET or DATA_ENCRYPTION_KEY")
    netim_login = _env("NETIM_LOGIN")
    netim_secret = _env("NETIM_SECRET")
    nameservers = _env_list("NETIM_NAMESERVERS", [])
    if netim_login or netim_secret:
        for name in ("NETIM_LOGIN", "NETIM_SECRET", "NETIM_CONTACT_ADMIN", "NETIM_CONTACT_TECH", "NETIM_CONTACT_BILLING"):
            req(name)
        if len(nameservers) < 2:
            missing.append("NETIM_NAMESERVERS (at least two)")
    mode = _env("PLESK_LOGIN_LINK_MODE", "session") or "session"
    if mode not in ("session", "reset_page"):
        raise ConfigError("PLESK_LOGIN_LINK_MODE must be session or reset_page")
    backup_mode = _env("SIGNUP_DELETE_BACKUP_MODE", "plesk") or "plesk"
    if backup_mode not in ("plesk", "manual", "none"):
        raise ConfigError("SIGNUP_DELETE_BACKUP_MODE must be plesk, manual or none")
    admin_user = _env("SIGNUP_ADMIN_USER")
    admin_password = _env("SIGNUP_ADMIN_PASSWORD")
    if bool(admin_user) != bool(admin_password):
        missing.append("SIGNUP_ADMIN_USER and SIGNUP_ADMIN_PASSWORD (both or none)")

    settings = SignupSettings(
        enabled=True,
        price_list_file=_env("SIGNUP_PRICE_LIST_FILE"),
        allowed_origins=[o.rstrip("/") for o in _env_list("SIGNUP_ALLOWED_ORIGINS", [])],
        token_secret=hashlib.sha256(("pleskmcp-signup:" + secret).encode("utf-8")).digest(),
        min_fill_seconds=_env_int("SIGNUP_MIN_FILL_SECONDS", 5),
        token_max_age=_env_int("SIGNUP_TOKEN_MAX_AGE", 7200),
        rate_limit_ip=_env_int("SIGNUP_RATE_LIMIT_IP", 5),
        rate_limit_ip_window=_env_int("SIGNUP_RATE_LIMIT_IP_WINDOW", 3600),
        rate_limit_email=_env_int("SIGNUP_RATE_LIMIT_EMAIL", 3),
        rate_limit_email_window=_env_int("SIGNUP_RATE_LIMIT_EMAIL_WINDOW", 86400),
        terms_version=req("SIGNUP_TERMS_VERSION"),
        terms_url=req("SIGNUP_TERMS_URL"),
        success_url=_env("SIGNUP_SUCCESS_URL"),
        account_url=_env("SIGNUP_ACCOUNT_URL", public_base_url + "/account") or "",
        plan_name=_env("SIGNUP_PLAN_NAME", "AI Hosting") or "AI Hosting",
        hosting_price=_env_float("SIGNUP_HOSTING_PRICE", 60.0),
        hosting_item_text=_env("SIGNUP_HOSTING_ITEM_TEXT", "AI Hosting {{year}}/{{nextYear}}") or "",
        domain_item_text=_env("SIGNUP_DOMAIN_ITEM_TEXT", "Domain {domain}") or "Domain {domain}",
        currency_id=_env_int("SIGNUP_CURRENCY_ID", 1),
        mwst_type=_env_int("SIGNUP_MWST_TYPE", 0),
        lead_months=_env_int("SIGNUP_LEAD_MONTHS", 1),
        external_ref_prefix=_env("SIGNUP_EXTERNAL_REF_PREFIX", "aihosting-") or "aihosting-",
        language=_env("SIGNUP_LANGUAGE", "de") or "de",
        product_title=_env("SIGNUP_PRODUCT_TITLE", "AI Hosting") or "AI Hosting",
        rebill_api_url=req("REBILL_API_URL").rstrip("/"),
        rebill_api_token=req("REBILL_API_TOKEN"),
        netim_api_url=(_env("NETIM_API_URL", "https://rest.netim.com/1.0") or "").rstrip("/"),
        netim_login=netim_login,
        netim_secret=netim_secret,
        netim_contact_admin=_env("NETIM_CONTACT_ADMIN"),
        netim_contact_tech=_env("NETIM_CONTACT_TECH"),
        netim_contact_billing=_env("NETIM_CONTACT_BILLING"),
        netim_nameservers=nameservers,
        netim_owner_language=(_env("NETIM_OWNER_LANGUAGE", "EN") or "EN").upper(),
        plesk_api_key=req("PLESK_SIGNUP_API_KEY"),
        plesk_ip_address=req("PLESK_SIGNUP_IP"),
        plesk_panel_url=(_env("PLESK_PANEL_URL", plesk_url) or plesk_url).rstrip("/"),
        plesk_login_link_mode=mode,
        plesk_password_page_path=_env("PLESK_PASSWORD_PAGE_PATH", "") or "",
        zammad_url=req("ZAMMAD_URL").rstrip("/"),
        zammad_token=req("ZAMMAD_TOKEN"),
        zammad_group=_env("ZAMMAD_GROUP", "Web TAB") or "Web TAB",
        smtp_host=req("SMTP_HOST"),
        smtp_port=_env_int("SMTP_PORT", 587),
        smtp_user=_env("SMTP_USER"),
        smtp_password=_env("SMTP_PASSWORD"),
        smtp_starttls=_env_bool("SMTP_STARTTLS", True),
        smtp_ssl=_env_bool("SMTP_SSL", False),
        mail_from=req("MAIL_FROM"),
        mail_reply_to=_env("MAIL_REPLY_TO"),
        mail_bcc=_env("MAIL_BCC"),
        panel_login_url=(_env("PLESK_PANEL_URL", plesk_url) or plesk_url).rstrip("/") + "/login_up.php",
        payment_poll_seconds=_env_int("SIGNUP_PAYMENT_POLL_SECONDS", 300),
        lifecycle_seconds=_env_int("SIGNUP_LIFECYCLE_SECONDS", 3600),
        suspend_after_days=_env_int("SIGNUP_SUSPEND_AFTER_DAYS", 10),
        delete_after_days=_env_int("SIGNUP_DELETE_AFTER_DAYS", 60),
        domain_renew_days_before=_env_int("SIGNUP_DOMAIN_RENEW_DAYS_BEFORE", 30),
        delete_backup_mode=backup_mode,
        backup_timeout=_env_int("SIGNUP_BACKUP_TIMEOUT", 3600),
        max_attempts=_env_int("SIGNUP_MAX_ATTEMPTS", 5),
        welcome_link_ttl_days=_env_int("SIGNUP_WELCOME_LINK_TTL_DAYS", 7),
        confirm_ttl_hours=_env_int("SIGNUP_CONFIRM_TTL_HOURS", 48),
        netim_operation_timeout_hours=_env_int("NETIM_OPERATION_TIMEOUT_HOURS", 72),
        admin_user=admin_user,
        admin_password=admin_password,
        nameservers_text=", ".join(nameservers),
    )
    if require_runtime and missing:
        raise ConfigError("SIGNUP_ENABLED=true but these variables are missing: " + ", ".join(missing))
    return settings
