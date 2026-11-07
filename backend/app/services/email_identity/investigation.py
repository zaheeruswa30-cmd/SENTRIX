"""Investigation artefacts for email records: markdown summary (RAG indexing), incident /
investigation case creation, and EmailInvestigationReport bookkeeping."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...models import EmailInvestigationReport, EmailVerificationRecord, Incident, Tenant, User
from ..audit import audit, verification_audit
from ..errors import ServiceError
from ..knowledge import rag
from .risk_engine import DISCLAIMER
from .service import layers, serialize_record


def record_markdown(rec: EmailVerificationRecord) -> str:
    d = serialize_record(rec, detail=True)
    da = d.get("domain_analysis") or {}
    lines = [f"# Email investigation: {rec.email}", "",
             f"Domain: {rec.domain}. Purpose: {rec.purpose or 'not stated'}. Last checked: {d['last_checked_at']}.", "",
             "## Validity layers"]
    for l in layers(rec):
        lines.append(f"- {l['label']}: {l['state']} ({l['detail']}).")
    lines += ["", "## Authentication records"]
    for mech in ("spf", "dkim", "dmarc"):
        a = da.get(mech) or {}
        lines.append(f"- {mech.upper()}: {a.get('status', 'not_checked')}. {a.get('explanation') or ''} "
                     f"Records: {'; '.join(a.get('raw_records') or []) or 'none'}."
                     + "".join(f" Issue: {i.get('message', i) if isinstance(i, dict) else i}." for i in (a.get("issues") or [])[:4]))
    risk = d.get("risk") or {}
    lines += ["", "## Risk findings",
              f"Score {risk.get('score')} ({risk.get('band')}), confidence {risk.get('confidence')}. {risk.get('summary', '')}"]
    for f in risk.get("findings", []):
        lines.append(f"- [{f['severity']}] {f['title']} — evidence: {f['evidence']} (confidence {f['confidence']}). "
                     f"Recommendation: {f['recommendation']}")
    lines += ["", "## Ownership", f"Status: {rec.ownership_status}. "
              + (f"Verified {d['ownership_verified_at']} via {rec.ownership_method}." if rec.ownership_verified_at else ""),
              "", "## Scope note", DISCLAIMER]
    return "\n".join(lines)


def index_record(db: Session, *, rec: EmailVerificationRecord, user: User, ip=None, user_agent=None):
    doc = rag.add_document(db, tenant_id=rec.tenant_id, title=f"Email investigation — {rec.email}",
                           text=record_markdown(rec), doc_type="email_investigation", source="email_identity",
                           ref_type="email_record", ref_id=rec.id, created_by=user.id, replace_ref=True)
    verification_audit(db, tenant_id=rec.tenant_id, record_id=rec.id, actor_id=user.id, action="kb.index",
                       detail={"document_id": doc.id, "chunks": doc.chunk_count}, ip=ip, user_agent=user_agent)
    db.commit()
    return doc


def _next_key(db: Session, tenant_id: str, prefix: str) -> str:
    n = db.scalar(select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id)) or 0
    while True:
        n += 1
        key = f"{prefix}-{n:04d}"
        if not db.scalar(select(Incident.id).where(Incident.tenant_id == tenant_id, Incident.incident_key == key)):
            return key


def create_incident(db: Session, *, tenant: Tenant, user: User, rec: EmailVerificationRecord, kind: str,
                    severity: str | None, title: str | None, note: str | None, ip=None, user_agent=None) -> Incident:
    if kind not in ("incident", "investigation"):
        raise ServiceError(400, "kind must be 'incident' or 'investigation'.")
    if rec.incident_id:
        existing = db.get(Incident, rec.incident_id)
        if existing and existing.tenant_id == tenant.id:
            raise ServiceError(409, f"This record is already linked to {existing.incident_key}.")
    d = serialize_record(rec, detail=True)
    risk = d.get("risk") or {}
    sev = severity or {"high": "high", "elevated": "medium", "guarded": "low", "low": "info"}.get(rec.risk_band or "", "low")
    inc = Incident(
        tenant_id=tenant.id, incident_key=_next_key(db, tenant.id, "INC" if kind == "incident" else "INV"),
        title=(title or f"Suspicious email indicators: {rec.email}")[:300],
        description=(note or "") + ("\n\n" if note else "") + (risk.get("summary") or "") + "\n\n" + DISCLAIMER,
        severity=sev, stage="analysis" if kind == "investigation" else "detection", status="open", kind=kind,
        source="email_identity", source_ref=rec.id, risk_score=rec.risk_score,
        tags=["email-identity", rec.domain] + rec_classes(rec),
        evidence={"email": rec.email, "domain": rec.domain, "layers": d["layers"],
                  "findings": [f for f in risk.get("findings", []) if f["impact"] > 0],
                  "risk": {k: risk.get(k) for k in ("score", "band", "confidence", "engine_version")}},
        created_by=user.id,
    )
    db.add(inc)
    db.flush()
    rec.incident_id = inc.id
    verification_audit(db, tenant_id=tenant.id, record_id=rec.id, actor_id=user.id, action="incident.create",
                       detail={"incident_id": inc.id, "incident_key": inc.incident_key, "kind": kind}, ip=ip,
                       user_agent=user_agent)
    audit(db, tenant_id=tenant.id, actor_id=user.id, action="incident.create", object_type="incident",
          object_id=inc.id, detail={"source": "email_identity", "key": inc.incident_key}, ip=ip, user_agent=user_agent)
    db.commit()
    _notify_incident(db, tenant, inc)
    return inc


def rec_classes(rec) -> list[str]:
    from .service import classifications
    return classifications(rec)


def _notify_incident(db: Session, tenant: Tenant, inc: Incident) -> None:
    """Optional analyst notification (INCIDENT_NOTIFY_EMAIL). Failures never block incident creation."""
    s = get_settings()
    to = getattr(s, "INCIDENT_NOTIFY_EMAIL", "") or ""
    if not to:
        return
    from ..notifications import mailer
    try:
        mailer.send(to, f"{s.APP_NAME}: {inc.incident_key} opened", "incident_created",
                    {"kind": inc.kind, "incident_key": inc.incident_key, "title": inc.title, "severity": inc.severity,
                     "source": inc.source, "opened_by": tenant.name, "organisation": tenant.name,
                     "link": f"{s.PUBLIC_BASE_URL.rstrip('/')}/#/incidents"})
    except Exception:  # noqa: BLE001
        pass


def save_report_row(db: Session, *, rec: EmailVerificationRecord, user: User, report_id: str | None,
                    kb_document_id: str | None = None, notes: str = "") -> EmailInvestigationReport:
    d = serialize_record(rec, detail=True)
    row = EmailInvestigationReport(tenant_id=rec.tenant_id, email_record_id=rec.id, report_id=report_id,
                                   title=f"Email investigation — {rec.email}"[:300],
                                   summary=((d.get("risk") or {}).get("summary") or ""), analyst_notes=notes or "",
                                   snapshot={k: v for k, v in d.items() if k != "domain_analysis"} | {
                                       "domain": {k: (d.get("domain_analysis") or {}).get(k) for k in
                                                  ("dns_status", "mx_status", "mx_records", "spf", "dkim", "dmarc",
                                                   "is_disposable", "suspicious_indicators", "threat_matches")}},
                                   incident_id=rec.incident_id, kb_document_id=kb_document_id, created_by=user.id)
    db.add(row)
    db.flush()
    return row
