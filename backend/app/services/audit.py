"""Security audit logging (global ``audit_log``) and the email-module verification audit trail.

Callers pass structured ``detail`` dicts. Secrets are stripped defensively before persistence.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog, VerificationAuditLog

_FORBIDDEN_KEYS = {"token", "code", "password", "secret", "link", "link_token", "otp"}


def _clean(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    if not detail:
        return detail
    return {k: ("[REDACTED]" if k.lower() in _FORBIDDEN_KEYS else v) for k, v in detail.items()}


def audit(db: Session, *, tenant_id: str | None, actor_id: str | None, action: str,
          object_type: str | None = None, object_id: str | None = None, detail: dict | None = None,
          ip: str | None = None, user_agent: str | None = None, actor_type: str = "user") -> AuditLog:
    row = AuditLog(tenant_id=tenant_id, actor_id=actor_id, actor_type=actor_type, action=action,
                   object_type=object_type, object_id=object_id, detail=_clean(detail), ip=ip,
                   user_agent=(user_agent or "")[:300] or None)
    db.add(row)
    return row


def verification_audit(db: Session, *, tenant_id: str, record_id: str | None, actor_id: str | None,
                       action: str, outcome: str = "success", detail: dict | None = None,
                       ip: str | None = None, user_agent: str | None = None,
                       actor_type: str = "user") -> VerificationAuditLog:
    row = VerificationAuditLog(tenant_id=tenant_id, email_record_id=record_id, actor_id=actor_id,
                               actor_type=actor_type, action=action, outcome=outcome, detail=_clean(detail),
                               ip=ip, user_agent=(user_agent or "")[:300] or None)
    db.add(row)
    # mirror into the platform-wide security audit log so SOC tooling sees one stream
    audit(db, tenant_id=tenant_id, actor_id=actor_id, actor_type=actor_type, action=f"email.{action}",
          object_type="email_record", object_id=record_id, detail={"outcome": outcome, **(_clean(detail) or {})},
          ip=ip, user_agent=user_agent)
    return row
