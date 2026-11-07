"""Sentrix — Email Identity Intelligence data model.

Layers are stored separately on purpose so the platform can never conflate them:

  syntax_status      → is the address well-formed?               (technical validity)
  dns_status         → does the domain exist in DNS?             (domain existence)
  mx_status          → can the domain receive mail?              (mail infrastructure)
  spf/dkim/dmarc     → is sender authentication configured?      (domain authentication posture)
  ownership_status   → did someone prove control of the mailbox? (mailbox ownership)

Real-world identity is never inferred from any of these, and no column exists for it.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, IdMixin, TimestampMixin, utcnow
from .foundation import _in

SYNTAX = ("valid", "invalid")
DNS = ("resolves", "nxdomain", "no_address", "error", "not_checked")
MX = ("present", "implicit", "null_mx", "absent", "error", "not_checked")
SPF = ("valid", "permissive", "missing", "invalid", "multiple", "error", "not_checked")
DKIM = ("selector_found", "not_found", "signature_pass", "signature_fail", "error", "not_checked")
DMARC = ("enforced", "monitoring", "missing", "invalid", "error", "not_checked")
DISPOSABLE = ("disposable", "not_disposable", "unknown")
OWNERSHIP = ("unverified", "pending", "verified", "expired", "failed", "locked")
RISK_BANDS = ("low", "guarded", "elevated", "high")
TOKEN_STATUS = ("active", "consumed", "expired", "revoked", "locked")
AUTH_MECH = ("spf", "dkim", "dmarc", "dkim_signature", "mx", "dns")


class DomainAnalysis(IdMixin, TimestampMixin, Base):
    """Per-tenant cached analysis of a mail domain. ``expires_at`` bounds DNS cache freshness."""
    __tablename__ = "email_domain_analyses"
    __table_args__ = (
        UniqueConstraint("tenant_id", "domain", name="tenant_domain"),
        Index("ix_eda_tenant_analyzed", "tenant_id", "analyzed_at"),
        Index("ix_eda_expires", "expires_at"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    ascii_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    is_idn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dns_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    mx_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    a_records: Mapped[list | None] = mapped_column(JSON)
    aaaa_records: Mapped[list | None] = mapped_column(JSON)
    mx_records: Mapped[list | None] = mapped_column(JSON)
    ns_records: Mapped[list | None] = mapped_column(JSON)
    is_disposable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    disposable_source: Mapped[str | None] = mapped_column(String(120))
    is_free_provider: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    registration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    domain_age_days: Mapped[int | None] = mapped_column(Integer)
    age_source: Mapped[str] = mapped_column(String(40), default="not_checked", nullable=False)
    reputation_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    reputation_detail: Mapped[dict | None] = mapped_column(JSON)
    suspicious_indicators: Mapped[list | None] = mapped_column(JSON)
    threat_matches: Mapped[list | None] = mapped_column(JSON)
    resolver_used: Mapped[str | None] = mapped_column(String(40))
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    auth_results: Mapped[list["DnsAuthenticationResult"]] = relationship(
        back_populates="domain_analysis", cascade="all, delete-orphan", passive_deletes=True
    )


class EmailVerificationRecord(IdMixin, TimestampMixin, Base):
    __tablename__ = "email_verification_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="tenant_email"),
        CheckConstraint(_in("syntax_status", SYNTAX), name="syntax_valid"),
        CheckConstraint(_in("dns_status", DNS), name="dns_valid"),
        CheckConstraint(_in("mx_status", MX), name="mx_valid"),
        CheckConstraint(_in("spf_status", SPF), name="spf_valid"),
        CheckConstraint(_in("dkim_status", DKIM), name="dkim_valid"),
        CheckConstraint(_in("dmarc_status", DMARC), name="dmarc_valid"),
        CheckConstraint(_in("disposable_status", DISPOSABLE), name="disposable_valid"),
        CheckConstraint(_in("ownership_status", OWNERSHIP), name="ownership_valid"),
        CheckConstraint("risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="risk_range"),
        Index("ix_evr_tenant_checked", "tenant_id", "last_checked_at"),
        Index("ix_evr_tenant_domain", "tenant_id", "domain"),
        Index("ix_evr_tenant_ownership", "tenant_id", "ownership_status"),
        Index("ix_evr_tenant_risk", "tenant_id", "risk_score"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)  # normalised (domain lower-cased)
    local_part: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    domain: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    domain_analysis_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_domain_analyses.id", ondelete="SET NULL")
    )
    purpose: Mapped[str] = mapped_column(String(200), default="", nullable=False)  # documented basis
    syntax_status: Mapped[str] = mapped_column(String(16), default="invalid", nullable=False)
    syntax_detail: Mapped[dict | None] = mapped_column(JSON)
    dns_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    mx_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    spf_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    dkim_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    dmarc_status: Mapped[str] = mapped_column(String(16), default="not_checked", nullable=False)
    disposable_status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    is_role_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ownership_status: Mapped[str] = mapped_column(String(16), default="unverified", nullable=False)
    ownership_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ownership_method: Mapped[str | None] = mapped_column(String(16))  # code | link
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_band: Mapped[str | None] = mapped_column(String(16))
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_technically_invalid: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    check_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))

    domain_analysis: Mapped[DomainAnalysis | None] = relationship()
    risk_assessments: Mapped[list["EmailRiskAssessment"]] = relationship(
        back_populates="email_record", cascade="all, delete-orphan", passive_deletes=True,
        order_by="EmailRiskAssessment.created_at.desc()",
    )
    tokens: Mapped[list["OwnershipVerificationToken"]] = relationship(
        back_populates="email_record", cascade="all, delete-orphan", passive_deletes=True
    )


class DnsAuthenticationResult(IdMixin, Base):
    """One row per mechanism lookup (SPF / DKIM selector / DMARC / message DKIM signature)."""
    __tablename__ = "email_dns_auth_results"
    __table_args__ = (
        CheckConstraint(_in("mechanism", AUTH_MECH), name="mechanism_valid"),
        Index("ix_edar_domain_mech", "domain_analysis_id", "mechanism"),
        Index("ix_edar_tenant_checked", "tenant_id", "checked_at"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    domain_analysis_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_domain_analyses.id", ondelete="CASCADE")
    )
    email_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_verification_records.id", ondelete="CASCADE")
    )
    mechanism: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    query_name: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    selector: Mapped[str | None] = mapped_column(String(100))
    raw_records: Mapped[list | None] = mapped_column(JSON)
    parsed: Mapped[dict | None] = mapped_column(JSON)
    issues: Mapped[list | None] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_analysis: Mapped[DomainAnalysis | None] = relationship(back_populates="auth_results")


class OwnershipVerificationToken(IdMixin, TimestampMixin, Base):
    """Only HMAC digests of the link token and numeric code are stored — never the secrets."""
    __tablename__ = "email_ownership_tokens"
    __table_args__ = (
        UniqueConstraint("link_token_hash", name="link_hash"),
        CheckConstraint(_in("status", TOKEN_STATUS), name="status_valid"),
        CheckConstraint("attempts >= 0", name="attempts_nonneg"),
        CheckConstraint("max_attempts > 0", name="max_attempts_pos"),
        Index("ix_eot_record_status", "email_record_id", "status"),
        Index("ix_eot_expires", "expires_at"),
        Index("ix_eot_tenant_created", "tenant_id", "created_at"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email_record_id: Mapped[str] = mapped_column(
        ForeignKey("email_verification_records.id", ondelete="CASCADE"), nullable=False
    )
    link_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(12), default="active", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_provider: Mapped[str] = mapped_column(String(20), default="", nullable=False)
    delivery_status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    delivery_message_id: Mapped[str | None] = mapped_column(String(200))
    delivery_error: Mapped[str | None] = mapped_column(String(300))
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    requester_ip: Mapped[str | None] = mapped_column(String(64))

    email_record: Mapped[EmailVerificationRecord] = relationship(back_populates="tokens")


class EmailRiskAssessment(IdMixin, Base):
    __tablename__ = "email_risk_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="score_range"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="confidence_range"),
        CheckConstraint(_in("band", RISK_BANDS), name="band_valid"),
        Index("ix_era_record_created", "email_record_id", "created_at"),
        Index("ix_era_tenant_band", "tenant_id", "band"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email_record_id: Mapped[str] = mapped_column(
        ForeignKey("email_verification_records.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    band: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    findings: Mapped[list] = mapped_column(JSON, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    engine_version: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    email_record: Mapped[EmailVerificationRecord] = relationship(back_populates="risk_assessments")


class EmailInvestigationReport(IdMixin, TimestampMixin, Base):
    __tablename__ = "email_investigation_reports"
    __table_args__ = (Index("ix_eir_tenant_created", "tenant_id", "created_at"),)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_verification_records.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)  # frozen evidence at report time
    report_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    kb_document_id: Mapped[str | None] = mapped_column(ForeignKey("documents.id", ondelete="SET NULL"))
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class VerificationAuditLog(IdMixin, Base):
    """Email-module audit trail (append-only). Never contains tokens or codes."""
    __tablename__ = "email_verification_audit_logs"
    __table_args__ = (
        Index("ix_eval_tenant_at", "tenant_id", "at"),
        Index("ix_eval_record_at", "email_record_id", "at"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("email_verification_records.id", ondelete="SET NULL")
    )
    actor_id: Mapped[str | None] = mapped_column(String(36))
    actor_type: Mapped[str] = mapped_column(String(16), default="user", nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), default="success", nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
