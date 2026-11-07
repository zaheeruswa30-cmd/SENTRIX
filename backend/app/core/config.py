"""Sentrix — runtime configuration.

All settings come from environment variables (or a local ``.env`` file). Secrets such as
``SECRET_KEY``, ``SMTP_PASSWORD`` and ``SENDGRID_API_KEY`` must only ever be supplied through the
environment; they are never returned by any API and never written to logs.

Backwards compatibility: environment variable names are unchanged from SecureWatch AI, so an
existing ``.env`` keeps working after the Sentrix rebrand.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[3]  # repository root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"), env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # ── App / brand ──────────────────────────────────────────────────────────────
    APP_NAME: str = "Sentrix"
    APP_TAGLINE: str = (
        "Intelligent Security Operations, Threat Detection and Digital Identity Intelligence Platform"
    )
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:5500,http://localhost:8000"
    PUBLIC_BASE_URL: str = "http://localhost:8000"  # used to build verification links
    SERVE_FRONTEND: bool = True  # serve ui-prototype/ at "/" from the API process

    # ── Security ────────────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-generate-with-openssl-rand-hex-32"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    PASSWORD_MIN_LENGTH: int = 12
    ALLOW_SELF_REGISTRATION: bool = True

    # ── Database ───────────────────────────────────────────────────────────────
    # Default is a local SQLite file so the project runs immediately in VS Code.
    # Production / docker-compose use PostgreSQL (DATABASE_URL in .env).
    DATABASE_URL: str = f"sqlite+pysqlite:///{(ROOT_DIR / 'sentrix.db').as_posix()}"
    AUTO_CREATE_SCHEMA: bool = True  # dev convenience; use Alembic in staging/production

    # ── DNS ────────────────────────────────────────────────────────────────────
    DNS_TIMEOUT_SECONDS: float = 4.0
    DOMAIN_CACHE_HOURS: int = 6  # DomainAnalysis.expires_at = analyzed_at + this
    DNS_RESOLVER: Literal["system", "doh"] = "system"
    DNS_DOH_URL: str = "https://cloudflare-dns.com/dns-query"
    DNS_DOH_FALLBACK: bool = True  # if the system resolver is blocked, retry over DoH (RFC 8484)
    DKIM_COMMON_SELECTORS: str = (
        "default,selector1,selector2,google,k1,k2,s1,s2,dkim,mail,smtp,mx,everlytickey1,mandrill,"
        "zoho,protonmail,protonmail2,protonmail3,fm1,fm2,fm3"
    )

    # ── Enrichment (opt-in third-party lookups, privacy-conscious defaults) ──────
    ENRICHMENT_RDAP_ENABLED: bool = False  # domain registration age via public RDAP
    RDAP_BASE_URL: str = "https://rdap.org/domain/"
    ENRICHMENT_DNSBL_ENABLED: bool = False  # domain reputation via a DNS blocklist
    DNSBL_DOMAIN_ZONES: str = "dbl.spamhaus.org"
    PROTECTED_BRAND_DOMAINS: str = (
        "paypal.com,microsoft.com,google.com,apple.com,amazon.com,facebook.com,linkedin.com,"
        "office365.com,outlook.com,dropbox.com,docusign.com,netflix.com"
    )

    # ── Email delivery (ownership verification) ───────────────────────────────────
    EMAIL_PROVIDER: Literal["smtp", "sendgrid", "dev_outbox", "disabled"] = "dev_outbox"
    EMAIL_FROM_ADDRESS: str = "no-reply@sentrix.local"
    EMAIL_FROM_NAME: str = "Sentrix Identity Intelligence"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_STARTTLS: bool = False
    SMTP_SSL: bool = False
    SENDGRID_API_KEY: str = ""
    DEV_OUTBOX_DIR: str = str(ROOT_DIR / "outbox")

    # ── Ownership verification policy ─────────────────────────────────────────
    OWNERSHIP_TOKEN_TTL_MINUTES: int = 15
    OWNERSHIP_MAX_ATTEMPTS: int = 5
    OWNERSHIP_MAX_SENDS_PER_DAY: int = 5
    OWNERSHIP_RESEND_COOLDOWN_SECONDS: int = 60

    # ── API rate limits (per user, rolling window) ───────────────────────────────
    EMAIL_CHECKS_PER_HOUR: int = 120

    # ── LLM (optional; deterministic grounded composer is used when unset) ──────
    LLM_PROVIDER: Literal["none", "ollama", "openai"] = "none"
    LLM_REPORT_MODEL: str = "llama3.1:8b"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    LLM_TIMEOUT_SECONDS: int = 60

    # ── Files ─────────────────────────────────────────────────────────────────
    INCIDENT_NOTIFY_EMAIL: str = ""  # optional: notify this address when email incidents are opened
    REPORTS_DIR: str = str(ROOT_DIR / "reports")

    # ── Demo ──────────────────────────────────────────────────────────────────
    SEED_DEMO_DATA: bool = True

    @field_validator("DATABASE_URL")
    @classmethod
    def _normalise_db(cls, v: str) -> str:
        if v.startswith("postgres://"):
            v = "postgresql+psycopg://" + v[len("postgres://"):]
        return v

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def dkim_selectors(self) -> list[str]:
        return [s.strip() for s in self.DKIM_COMMON_SELECTORS.split(",") if s.strip()]

    @property
    def protected_brands(self) -> list[str]:
        return [s.strip().lower() for s in self.PROTECTED_BRAND_DOMAINS.split(",") if s.strip()]

    @property
    def dnsbl_zones(self) -> list[str]:
        return [s.strip() for s in self.DNSBL_DOMAIN_ZONES.split(",") if s.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    def assert_safe_for_production(self) -> None:
        """Fail fast on insecure production configuration."""
        if not self.is_production:
            return
        problems = []
        if self.SECRET_KEY.startswith("change-me") or len(self.SECRET_KEY) < 32:
            problems.append("SECRET_KEY must be a random value of at least 32 characters")
        if self.EMAIL_PROVIDER == "dev_outbox":
            problems.append("EMAIL_PROVIDER=dev_outbox is development-only; configure smtp or sendgrid")
        if self.DEBUG:
            problems.append("DEBUG must be false in production")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
