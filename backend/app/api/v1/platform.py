"""Platform APIs that the Email Identity module integrates with: Incident Management, Threat
Intelligence, Security Audit Logs, RAG knowledge base, AI Security Center and Reporting."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.base import as_aware
from ...db.session import get_db
from ...models import AuditLog, Document, DocumentChunk, Incident, Report, ThreatIndicator, User
from ...models.foundation import INCIDENT_STAGES, INCIDENT_STATUSES, SEVERITIES
from ...services.ai import email_assistant
from ...services.audit import audit
from ...services.knowledge import rag
from ..deps import Ctx, analyst, current, require

router = APIRouter(tags=["platform"])


# ── Incidents ────────────────────────────────────────────────────────────────

def _inc(i: Incident) -> dict:
    return {"id": i.id, "key": i.incident_key, "title": i.title, "description": i.description, "severity": i.severity,
            "stage": i.stage, "status": i.status, "kind": i.kind, "source": i.source, "source_ref": i.source_ref,
            "risk_score": i.risk_score, "tags": i.tags or [], "evidence": i.evidence or {},
            "opened_at": as_aware(i.opened_at), "closed_at": as_aware(i.closed_at), "resolution_note": i.resolution_note}


@router.get("/incidents")
def list_incidents(source: str | None = None, status: str | None = None, ctx: Ctx = Depends(current),
                   db: Session = Depends(get_db)):
    stmt = select(Incident).where(Incident.tenant_id == ctx.tenant.id)
    if source:
        stmt = stmt.where(Incident.source == source)
    if status:
        stmt = stmt.where(Incident.status == status)
    return {"items": [_inc(i) for i in db.scalars(stmt.order_by(Incident.opened_at.desc()).limit(300))]}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i or i.tenant_id != ctx.tenant.id:
        raise HTTPException(404, "Incident not found.")
    return _inc(i)


class IncidentPatch(BaseModel):
    status: str | None = None
    stage: str | None = None
    severity: str | None = None
    resolution_note: str | None = Field(default=None, max_length=4000)


@router.patch("/incidents/{incident_id}")
def patch_incident(incident_id: str, body: IncidentPatch, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i or i.tenant_id != ctx.tenant.id:
        raise HTTPException(404, "Incident not found.")
    for field, allowed in (("status", INCIDENT_STATUSES), ("stage", INCIDENT_STAGES), ("severity", SEVERITIES)):
        v = getattr(body, field)
        if v is not None:
            if v not in allowed:
                raise HTTPException(422, f"{field} must be one of {', '.join(allowed)}")
            setattr(i, field, v)
    if body.resolution_note is not None:
        i.resolution_note = body.resolution_note
    if i.status in ("resolved", "false_positive") and not i.closed_at:
        i.closed_at = datetime.now(timezone.utc)
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="incident.update", object_type="incident",
          object_id=i.id, detail=body.model_dump(exclude_none=True), ip=ctx.ip, user_agent=ctx.user_agent)
    db.commit()
    return _inc(i)


# ── Threat intelligence ────────────────────────────────────────────────────

class IndicatorIn(BaseModel):
    indicator_type: str = Field(pattern="^(domain|email|ip|url)$")
    value: str = Field(min_length=2, max_length=512)
    source: str = Field(default="analyst", pattern="^(analyst|abuse_report|feed)$")
    severity: str = Field(default="medium", pattern="^(info|low|medium|high|critical)$")
    confidence: int = Field(default=60, ge=0, le=100)
    description: str = Field(default="", max_length=2000)
    reference: str | None = Field(default=None, max_length=500)


def _ti(t: ThreatIndicator) -> dict:
    return {"id": t.id, "indicator_type": t.indicator_type, "value": t.value, "source": t.source,
            "severity": t.severity, "confidence": t.confidence, "description": t.description,
            "reference": t.reference, "is_active": t.is_active, "created_at": as_aware(t.created_at)}


@router.get("/threat-intel/indicators")
def list_indicators(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    rows = db.scalars(select(ThreatIndicator).where(ThreatIndicator.tenant_id == ctx.tenant.id)
                      .order_by(ThreatIndicator.created_at.desc()).limit(500))
    return {"items": [_ti(t) for t in rows]}


@router.post("/threat-intel/indicators", status_code=201)
def add_indicator(body: IndicatorIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    value = body.value.strip().lower().rstrip(".")
    if db.scalar(select(ThreatIndicator.id).where(ThreatIndicator.tenant_id == ctx.tenant.id,
                                                  ThreatIndicator.indicator_type == body.indicator_type,
                                                  ThreatIndicator.value == value)):
        raise HTTPException(409, "This indicator already exists.")
    t = ThreatIndicator(tenant_id=ctx.tenant.id, **(body.model_dump() | {"value": value}), created_by=ctx.user.id)
    db.add(t)
    db.flush()
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="threat_intel.add", object_type="indicator",
          object_id=t.id, detail={"type": t.indicator_type, "value": t.value, "source": t.source}, ip=ctx.ip,
          user_agent=ctx.user_agent)
    db.commit()
    return _ti(t)


@router.delete("/threat-intel/indicators/{indicator_id}", status_code=204)
def delete_indicator(indicator_id: str, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    t = db.get(ThreatIndicator, indicator_id)
    if not t or t.tenant_id != ctx.tenant.id:
        raise HTTPException(404, "Indicator not found.")
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="threat_intel.delete", object_type="indicator",
          object_id=t.id, detail={"value": t.value}, ip=ctx.ip, user_agent=ctx.user_agent)
    db.delete(t)
    db.commit()


# ── Security audit log ───────────────────────────────────────────────────────

@router.get("/audit-logs")
def audit_logs(action: str | None = None, limit: int = Query(default=200, le=1000), ctx: Ctx = Depends(analyst),
               db: Session = Depends(get_db)):
    stmt = select(AuditLog, User.email).outerjoin(User, User.id == AuditLog.actor_id).where(
        AuditLog.tenant_id == ctx.tenant.id)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    rows = db.execute(stmt.order_by(AuditLog.at.desc()).limit(limit)).all()
    return {"items": [{"id": a.id, "action": a.action, "actor": email or a.actor_type, "object_type": a.object_type,
                       "object_id": a.object_id, "detail": a.detail or {}, "ip": a.ip, "at": as_aware(a.at)}
                      for a, email in rows]}


# ── Knowledge base (RAG) ──────────────────────────────────────────────────

@router.get("/knowledge/search")
def kb_search(q: str = Query(min_length=2, max_length=500), k: int = Query(default=6, le=20),
              doc_type: str | None = None, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    return {"query": q, "hits": rag.search(db, ctx.tenant.id, q, k=k, doc_types=[doc_type] if doc_type else None)}


@router.get("/knowledge/documents")
def kb_documents(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    rows = db.scalars(select(Document).where(Document.tenant_id == ctx.tenant.id).order_by(Document.created_at.desc()))
    return {"items": [{"id": d.id, "title": d.title, "doc_type": d.doc_type, "source": d.source,
                       "chunk_count": d.chunk_count, "ref_type": d.ref_type, "ref_id": d.ref_id,
                       "created_at": as_aware(d.created_at)} for d in rows]}


@router.get("/knowledge/documents/{doc_id}")
def kb_document(doc_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    d = db.get(Document, doc_id)
    if not d or d.tenant_id != ctx.tenant.id:
        raise HTTPException(404, "Document not found.")
    chunks = db.scalars(select(DocumentChunk).where(DocumentChunk.document_id == d.id).order_by(DocumentChunk.chunk_index))
    return {"id": d.id, "title": d.title, "doc_type": d.doc_type,
            "chunks": [{"id": c.id, "index": c.chunk_index, "section": c.section, "text": c.text} for c in chunks]}


class DocIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    text: str = Field(min_length=1, max_length=500_000)
    doc_type: str = Field(default="other", max_length=32)


@router.post("/knowledge/documents", status_code=201)
def kb_add(body: DocIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    d = rag.add_document(db, tenant_id=ctx.tenant.id, title=body.title, text=body.text, doc_type=body.doc_type,
                         created_by=ctx.user.id)
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="knowledge.add", object_type="document",
          object_id=d.id, detail={"title": d.title, "chunks": d.chunk_count}, ip=ctx.ip, user_agent=ctx.user_agent)
    db.commit()
    return {"id": d.id, "title": d.title, "chunk_count": d.chunk_count}


# ── AI Security Center: email analysis ───────────────────────────────────────

class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    record_id: str | None = None
    email: str | None = Field(default=None, max_length=320)
    run_if_missing: bool = True


@router.post("/ai/email/ask")
def ai_email_ask(body: AskIn, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    return email_assistant.answer(db, tenant=ctx.tenant, user=ctx.user, question=body.question,
                                  record_id=body.record_id, email=body.email, run_if_missing=body.run_if_missing,
                                  ip=ctx.ip, user_agent=ctx.user_agent)


# ── Reports ────────────────────────────────────────────────────────────────

@router.get("/reports")
def list_reports(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    rows = db.scalars(select(Report).where(Report.tenant_id == ctx.tenant.id).order_by(Report.created_at.desc()).limit(200))
    return {"items": [{"id": r.id, "kind": r.kind, "title": r.title, "format": r.format, "size_bytes": r.size_bytes,
                       "sha256": r.sha256, "ref_type": r.ref_type, "ref_id": r.ref_id,
                       "created_at": as_aware(r.created_at)} for r in rows]}


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    r = db.get(Report, report_id)
    if not r or r.tenant_id != ctx.tenant.id:
        raise HTTPException(404, "Report not found.")
    p = Path(r.path).resolve()
    root = Path(get_settings().REPORTS_DIR).resolve()
    if root not in p.parents or not p.exists():
        raise HTTPException(410, "Report file is no longer available.")
    return FileResponse(p, media_type="application/pdf", filename=f"sentrix-{r.kind}-{r.created_at:%Y%m%d}.pdf")


# ── Meta ────────────────────────────────────────────────────────────────

@router.get("/meta")
def meta(db: Session = Depends(get_db)):
    s = get_settings()
    return {"name": s.APP_NAME, "tagline": s.APP_TAGLINE, "version": s.APP_VERSION, "environment": s.ENVIRONMENT,
            "email_provider": s.EMAIL_PROVIDER, "dns_resolver": s.DNS_RESOLVER, "doh_fallback": s.DNS_DOH_FALLBACK,
            "enrichment": {"rdap": s.ENRICHMENT_RDAP_ENABLED, "dnsbl": s.ENRICHMENT_DNSBL_ENABLED},
            "llm_provider": s.LLM_PROVIDER, "self_registration": s.ALLOW_SELF_REGISTRATION}
