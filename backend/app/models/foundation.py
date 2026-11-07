"""Sentrix foundation models: tenants, users, security audit log, incidents, threat intelligence,
knowledge base and reports. Every tenant-owned row carries ``tenant_id`` and every query in the
API layer is scoped by it (tenant isolation)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, IdMixin, TimestampMixin, utcnow

ROLES = ("admin", "analyst", "viewer")
SEVERITIES = ("info", "low", "medium", "high", "critical")
INCIDENT_STAGES = ("detection", "analysis", "correlation", "risk_assessment", "investigation", "resolution")
INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


class Tenant(IdMixin, TimestampMixin, Base):
    __tablename__ = "tenants"
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class User(IdMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="email"),
        CheckConstraint(_in("role", ROLES), name="role_valid"),
        Index("ix_users_tenant", "tenant_id"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship()


class AuditLog(IdMixin, Base):
    """Security audit log — append-only (the API never updates or deletes rows)."""
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_tenant_at", "tenant_id", "at"),
        Index("ix_audit_object", "object_type", "object_id"),
    )
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    actor_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(60))
    object_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    detail: Mapped[dict | None] = mapped_column(JSON)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Incident(IdMixin, TimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "incident_key", name="tenant_key"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        CheckConstraint(_in("stage", INCIDENT_STAGES), name="stage_valid"),
        CheckConstraint(_in("status", INCIDENT_STATUSES), name="status_valid"),
        Index("ix_incidents_tenant_opened", "tenant_id", "opened_at"),
        Index("ix_incidents_source", "tenant_id", "source", "source_ref"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    incident_key: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="medium", nullable=False)
    stage: Mapped[str] = mapped_column(String(20), default="detection", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    kind: Mapped[str] = mapped_column(String(20), default="incident", nullable=False)  # incident | investigation
    source: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(64))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    tags: Mapped[list | None] = mapped_column(JSON)
    evidence: Mapped[dict | None] = mapped_column(JSON)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_note: Mapped[str | None] = mapped_column(Text)


class ThreatIndicator(IdMixin, TimestampMixin, Base):
    """Tenant threat-intelligence indicators, including analyst-submitted abuse reports."""
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("tenant_id", "indicator_type", "value", name="tenant_type_value"),
        CheckConstraint(_in("indicator_type", ("domain", "email", "ip", "url")), name="type_valid"),
        CheckConstraint(_in("source", ("analyst", "abuse_report", "feed", "demo")), name="source_valid"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="confidence_range"),
        Index("ix_ti_lookup", "tenant_id", "indicator_type", "value"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="analyst", nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="medium", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reference: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Document(IdMixin, TimestampMixin, Base):
    """Knowledge-base document (RAG). Email investigations are indexed here as well."""
    __tablename__ = "documents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sha256", name="tenant_sha"),
        Index("ix_documents_tenant_type", "tenant_id", "doc_type"),
        Index("ix_documents_ref", "tenant_id", "ref_type", "ref_id"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    doc_type: Mapped[str] = mapped_column(String(32), default="other", nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="upload", nullable=False)
    classification: Mapped[str] = mapped_column(String(16), default="internal", nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="ready", nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ref_type: Mapped[str | None] = mapped_column(String(40))
    ref_id: Mapped[str | None] = mapped_column(String(36))
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    chunks: Mapped[list["DocumentChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan", passive_deletes=True
    )


class DocumentChunk(IdMixin, Base):
    __tablename__ = "document_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_index", name="doc_idx"),
        Index("ix_chunks_tenant", "tenant_id"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    section: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    document: Mapped[Document] = relationship(back_populates="chunks")


class Report(IdMixin, TimestampMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(_in("format", ("pdf", "md", "json")), name="format_valid"),
        Index("ix_reports_tenant_created", "tenant_id", "created_at"),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    format: Mapped[str] = mapped_column(String(8), default="pdf", nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ref_type: Mapped[str | None] = mapped_column(String(40))
    ref_id: Mapped[str | None] = mapped_column(String(36))
    generated_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    params: Mapped[dict | None] = mapped_column(JSON)
