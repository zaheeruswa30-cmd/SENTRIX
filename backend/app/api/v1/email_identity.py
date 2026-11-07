"""Email Identity Intelligence API (/api/v1/email-identity)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.base import as_aware
from ...db.session import get_db
from ...models import (
    DnsAuthenticationResult, DomainAnalysis, EmailInvestigationReport, EmailVerificationRecord, Incident,
    VerificationAuditLog,
)
from ...services.audit import audit, verification_audit
from ...services.email_identity import investigation, ownership
from ...services.email_identity import service as svc
from ...services.email_identity.syntax import validate_email_syntax
from ...services.reports import pdf
from ..deps import Ctx, analyst, client_meta, current, limiter, require

router = APIRouter(prefix="/email-identity", tags=["email-identity"])
FILTERS = ("verified", "unverified", "invalid", "suspicious", "pending")


class CheckIn(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    purpose: str = Field(min_length=3, max_length=200,
                         description="Why this address is being checked (recorded for privacy accountability).")
    dkim_selectors: list[str] = Field(default_factory=list, max_length=10)
    force: bool = False


class BulkIn(BaseModel):
    emails: list[str] = Field(min_length=1, max_length=25)
    purpose: str = Field(min_length=3, max_length=200)


class StartIn(BaseModel):
    consent: bool = Field(description="Analyst confirms they are authorised to send a verification message.")


class CodeIn(BaseModel):
    code: str = Field(min_length=1, max_length=12)


class ConfirmIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class IncidentIn(BaseModel):
    kind: str = "investigation"
    severity: str | None = None
    title: str | None = Field(default=None, max_length=300)
    note: str | None = Field(default=None, max_length=4000)


def _rec(db: Session, ctx: Ctx, record_id: str) -> EmailVerificationRecord:
    rec = db.get(EmailVerificationRecord, record_id)
    if not rec or rec.tenant_id != ctx.tenant.id:  # tenant isolation: other tenants' ids look like 404
        raise HTTPException(404, "Email record not found.")
    return rec


def _clean_selectors(sel: list[str]) -> list[str]:
    import re
    out = []
    for s in sel:
        s = s.strip().lower()
        if s and re.fullmatch(r"[a-z0-9][a-z0-9\-_.]{0,62}", s):
            out.append(s)
    return out


# ── stats + records ─────────────────────────────────────────────────────────

@router.get("/stats")
def stats(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    E = EmailVerificationRecord
    base = select(func.count(E.id)).where(E.tenant_id == ctx.tenant.id)
    out = {"total": db.scalar(base) or 0}
    for f in FILTERS:
        out[f] = db.scalar(base.where(svc.filter_clause(f))) or 0
    out["domains"] = db.scalar(select(func.count(DomainAnalysis.id)).where(DomainAnalysis.tenant_id == ctx.tenant.id)) or 0
    out["linked_cases"] = db.scalar(base.where(E.incident_id.is_not(None))) or 0
    out["avg_risk"] = round(db.scalar(select(func.avg(E.risk_score)).where(E.tenant_id == ctx.tenant.id)) or 0, 1)
    bands = db.execute(select(E.risk_band, func.count()).where(E.tenant_id == ctx.tenant.id).group_by(E.risk_band)).all()
    out["bands"] = {b or "unscored": n for b, n in bands}
    auth = {}
    for col in ("spf_status", "dkim_status", "dmarc_status", "mx_status"):
        rows = db.execute(select(getattr(E, col), func.count()).where(E.tenant_id == ctx.tenant.id)
                          .group_by(getattr(E, col))).all()
        auth[col] = {k: n for k, n in rows}
    out["status_breakdown"] = auth
    return out


@router.get("/records")
def list_records(filter: str | None = Query(default=None), q: str | None = None, domain: str | None = None,
                 sort: str = "recent", limit: int = Query(default=50, le=200), offset: int = 0,
                 ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    E = EmailVerificationRecord
    stmt = select(E).where(E.tenant_id == ctx.tenant.id)
    if filter:
        if filter not in FILTERS:
            raise HTTPException(422, f"filter must be one of {', '.join(FILTERS)}")
        stmt = stmt.where(svc.filter_clause(filter))
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(E.email.like(like), E.domain.like(like)))
    if domain:
        stmt = stmt.where(E.domain == domain.strip().lower())
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    order = {"risk": E.risk_score.desc(), "email": E.email.asc()}.get(sort, E.last_checked_at.desc())
    rows = db.scalars(stmt.order_by(order).limit(limit).offset(offset)).all()
    return {"total": total, "items": [svc.serialize_record(r) for r in rows]}


@router.post("/records", status_code=201)
def create_check(body: CheckIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    limiter.hit(f"check:{ctx.user.id}", get_settings().EMAIL_CHECKS_PER_HOUR, 3600)
    rec = svc.run_check(db, tenant=ctx.tenant, user=ctx.user, email=body.email, purpose=body.purpose,
                        selectors=_clean_selectors(body.dkim_selectors), force=body.force, ip=ctx.ip,
                        user_agent=ctx.user_agent)
    return svc.serialize_record(rec, detail=True)


@router.post("/records/bulk", status_code=201)
def bulk_check(body: BulkIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    out = []
    for e in dict.fromkeys(x.strip() for x in body.emails if x.strip()):
        limiter.hit(f"check:{ctx.user.id}", get_settings().EMAIL_CHECKS_PER_HOUR, 3600)
        rec = svc.run_check(db, tenant=ctx.tenant, user=ctx.user, email=e, purpose=body.purpose, ip=ctx.ip,
                            user_agent=ctx.user_agent)
        out.append(svc.serialize_record(rec))
    return {"items": out}


@router.get("/records/{record_id}")
def get_record(record_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    return svc.serialize_record(_rec(db, ctx, record_id), detail=True)


@router.post("/records/{record_id}/recheck")
def recheck(record_id: str, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    rec = _rec(db, ctx, record_id)
    limiter.hit(f"check:{ctx.user.id}", get_settings().EMAIL_CHECKS_PER_HOUR, 3600)
    rec = svc.run_check(db, tenant=ctx.tenant, user=ctx.user, email=rec.email, purpose=rec.purpose, force=True,
                        ip=ctx.ip, user_agent=ctx.user_agent)
    return svc.serialize_record(rec, detail=True)


@router.delete("/records/{record_id}", status_code=204)
def delete_record(record_id: str, ctx: Ctx = Depends(require("admin")), db: Session = Depends(get_db)):
    """Data-minimisation: remove a record (and its tokens / assessments). The audit trail keeps a hashed reference."""
    rec = _rec(db, ctx, record_id)
    from ...core.security import hash_secret
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="email.record.delete", object_type="email_record",
          object_id=rec.id, detail={"email_ref": hash_secret(rec.email, "audit-ref")[:16]}, ip=ctx.ip,
          user_agent=ctx.user_agent)
    db.delete(rec)
    db.commit()
    return Response(status_code=204)


# ── domains + authentication ────────────────────────────────────────────────

@router.get("/domains")
def list_domains(q: str | None = None, limit: int = Query(default=100, le=300), ctx: Ctx = Depends(current),
                 db: Session = Depends(get_db)):
    D, E = DomainAnalysis, EmailVerificationRecord
    stmt = select(D).where(D.tenant_id == ctx.tenant.id)
    if q:
        stmt = stmt.where(D.domain.like(f"%{q.strip().lower()}%"))
    rows = db.scalars(stmt.order_by(D.analyzed_at.desc()).limit(limit)).all()
    counts = dict(db.execute(select(E.domain_analysis_id, func.count()).where(E.tenant_id == ctx.tenant.id)
                             .group_by(E.domain_analysis_id)).all())
    items = []
    for d in rows:
        full = svc.serialize_domain(d)
        items.append({k: full[k] for k in ("id", "domain", "dns_status", "mx_status", "is_disposable", "is_free_provider",
                                           "domain_age_days", "reputation_status", "analyzed_at", "expires_at")}
                     | {"spf_status": full["spf"]["status"], "dkim_status": full["dkim"]["status"],
                        "dmarc_status": full["dmarc"]["status"], "suspicious_count": len(full["suspicious_indicators"]),
                        "threat_match_count": len(full["threat_matches"]), "address_count": counts.get(d.id, 0)})
    return {"items": items}


@router.get("/domains/{domain}")
def get_domain(domain: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    d = db.scalar(select(DomainAnalysis).where(DomainAnalysis.tenant_id == ctx.tenant.id,
                                               DomainAnalysis.domain == domain.strip().lower()))
    if not d:
        raise HTTPException(404, "Domain has not been analysed yet.")
    out = svc.serialize_domain(d)
    out["addresses"] = [svc.serialize_record(r) for r in db.scalars(select(EmailVerificationRecord).where(
        EmailVerificationRecord.tenant_id == ctx.tenant.id, EmailVerificationRecord.domain_analysis_id == d.id)
        .order_by(EmailVerificationRecord.last_checked_at.desc()).limit(50))]
    return out


class DomainIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    dkim_selectors: list[str] = Field(default_factory=list, max_length=10)


@router.post("/domains/analyze")
def analyze_domain(body: DomainIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    """Domain-only analysis (no mailbox involved) — e.g. auditing your own sending domains."""
    limiter.hit(f"check:{ctx.user.id}", get_settings().EMAIL_CHECKS_PER_HOUR, 3600)
    syn = validate_email_syntax(f"postmaster@{body.domain.strip().lstrip('@')}")
    if not syn.valid:
        raise HTTPException(422, "Enter a valid domain name.")
    d = svc.analyze_domain(db, ctx.tenant, ascii_domain=syn.ascii_domain, unicode_domain=syn.domain, is_idn=syn.is_idn,
                           selectors=_clean_selectors(body.dkim_selectors), force=True)
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="email.domain.analyze", object_type="domain",
          object_id=d.id, detail={"domain": d.domain}, ip=ctx.ip, user_agent=ctx.user_agent)
    db.commit()
    return svc.serialize_domain(d)


@router.get("/auth-results")
def auth_results(mechanism: str | None = None, status: str | None = None, limit: int = Query(default=200, le=500),
                 ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    A = DnsAuthenticationResult
    stmt = select(A, DomainAnalysis.domain).outerjoin(DomainAnalysis, DomainAnalysis.id == A.domain_analysis_id).where(
        A.tenant_id == ctx.tenant.id)
    if mechanism:
        stmt = stmt.where(A.mechanism == mechanism)
    if status:
        stmt = stmt.where(A.status == status)
    rows = db.execute(stmt.order_by(A.checked_at.desc()).limit(limit)).all()
    return {"items": [{"id": a.id, "domain": dom or a.query_name, "mechanism": a.mechanism, "status": a.status,
                       "query_name": a.query_name, "selector": a.selector, "raw_records": a.raw_records or [],
                       "issues": a.issues or [], "explanation": a.explanation, "checked_at": as_aware(a.checked_at),
                       "email_record_id": a.email_record_id}
                      for a, dom in rows if not (a.parsed or {}).get("summary") or a.mechanism == "dkim"]}


@router.post("/dkim/verify")
async def dkim_verify(file: UploadFile | None = File(default=None), raw: str | None = Form(default=None),
                      record_id: str | None = Form(default=None), ctx: Ctx = Depends(analyst),
                      db: Session = Depends(get_db)):
    """Verify DKIM signatures on a real message (.eml with full headers). Body is not stored."""
    data = (await file.read(2_000_001)) if file else (raw or "").encode("utf-8", "replace")
    if not data.strip():
        raise HTTPException(422, "Upload an .eml file or paste the raw message including headers.")
    if len(data) > 2_000_000:
        raise HTTPException(413, "Message too large (2 MB limit).")
    rec = _rec(db, ctx, record_id) if record_id else None
    return svc.verify_dkim_message(db, tenant=ctx.tenant, user=ctx.user, raw=data, record=rec, ip=ctx.ip,
                                   user_agent=ctx.user_agent)


# ── ownership verification ──────────────────────────────────────────────────

@router.get("/records/{record_id}/ownership")
def ownership_status(record_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    return ownership.status_view(db, _rec(db, ctx, record_id))


@router.post("/records/{record_id}/ownership/start")
def ownership_start(record_id: str, body: StartIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    return ownership.start(db, record=_rec(db, ctx, record_id), actor=ctx.user, tenant=ctx.tenant,
                           consent=body.consent, ip=ctx.ip, user_agent=ctx.user_agent)


@router.post("/records/{record_id}/ownership/resend")
def ownership_resend(record_id: str, body: StartIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    return ownership.start(db, record=_rec(db, ctx, record_id), actor=ctx.user, tenant=ctx.tenant,
                           consent=body.consent, ip=ctx.ip, user_agent=ctx.user_agent, resend=True)


@router.post("/records/{record_id}/ownership/verify")
def ownership_verify(record_id: str, body: CodeIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    limiter.hit(f"code:{ctx.user.id}", 30, 600)
    return ownership.verify_code(db, record=_rec(db, ctx, record_id), actor=ctx.user, code=body.code, ip=ctx.ip,
                                 user_agent=ctx.user_agent)


@router.post("/ownership/confirm")
def ownership_confirm(body: ConfirmIn, request: Request, db: Session = Depends(get_db)):
    """Public endpoint used by the recipient's verification link (token travels in the body, never the URL)."""
    ip, ua = client_meta(request)
    limiter.hit(f"confirm:{ip}", 10, 600)
    return ownership.confirm_link(db, token=body.token, ip=ip, user_agent=ua)


@router.get("/ownership")
def ownership_overview(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    E = EmailVerificationRecord
    rows = db.scalars(select(E).where(E.tenant_id == ctx.tenant.id).order_by(E.updated_at.desc()).limit(200)).all()
    items = []
    for r in rows:
        v = ownership.status_view(db, r)
        items.append({"record": svc.serialize_record(r), "ownership": v})
    return {"items": items, "settings": {
        "ttl_minutes": get_settings().OWNERSHIP_TOKEN_TTL_MINUTES, "max_attempts": get_settings().OWNERSHIP_MAX_ATTEMPTS,
        "max_sends_per_day": get_settings().OWNERSHIP_MAX_SENDS_PER_DAY,
        "resend_cooldown_seconds": get_settings().OWNERSHIP_RESEND_COOLDOWN_SECONDS,
        "provider": get_settings().EMAIL_PROVIDER}}


# ── audit, history, incidents, reports, knowledge ───────────────────────────

def _audit_out(a: VerificationAuditLog) -> dict:
    return {"id": a.id, "record_id": a.email_record_id, "action": a.action, "outcome": a.outcome,
            "actor_type": a.actor_type, "actor_id": a.actor_id, "detail": a.detail or {}, "ip": a.ip,
            "at": as_aware(a.at)}


@router.get("/records/{record_id}/audit")
def record_audit(record_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    rec = _rec(db, ctx, record_id)
    rows = db.scalars(select(VerificationAuditLog).where(VerificationAuditLog.tenant_id == ctx.tenant.id,
                                                         VerificationAuditLog.email_record_id == rec.id)
                      .order_by(VerificationAuditLog.at.desc()).limit(300)).all()
    return {"items": [_audit_out(a) for a in rows]}


@router.get("/audit")
def module_audit(action: str | None = None, limit: int = Query(default=200, le=1000), ctx: Ctx = Depends(analyst),
                 db: Session = Depends(get_db)):
    V = VerificationAuditLog
    stmt = select(V, EmailVerificationRecord.email).outerjoin(EmailVerificationRecord,
                                                              EmailVerificationRecord.id == V.email_record_id).where(
        V.tenant_id == ctx.tenant.id)
    if action:
        stmt = stmt.where(V.action.like(f"{action}%"))
    rows = db.execute(stmt.order_by(V.at.desc()).limit(limit)).all()
    return {"items": [_audit_out(a) | {"email": e} for a, e in rows]}


@router.get("/history")
def history(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    R = EmailInvestigationReport
    reps = db.execute(select(R, EmailVerificationRecord.email).outerjoin(
        EmailVerificationRecord, EmailVerificationRecord.id == R.email_record_id).where(R.tenant_id == ctx.tenant.id)
        .order_by(R.created_at.desc()).limit(100)).all()
    incs = db.scalars(select(Incident).where(Incident.tenant_id == ctx.tenant.id, Incident.source == "email_identity")
                      .order_by(Incident.opened_at.desc()).limit(100)).all()
    checks = db.execute(select(VerificationAuditLog, EmailVerificationRecord.email).join(
        EmailVerificationRecord, EmailVerificationRecord.id == VerificationAuditLog.email_record_id).where(
        VerificationAuditLog.tenant_id == ctx.tenant.id, VerificationAuditLog.action.like("check.%"))
        .order_by(VerificationAuditLog.at.desc()).limit(100)).all()
    return {
        "reports": [{"id": r.id, "title": r.title, "email": e, "record_id": r.email_record_id, "report_id": r.report_id,
                     "incident_id": r.incident_id, "kb_document_id": r.kb_document_id, "summary": r.summary,
                     "created_at": as_aware(r.created_at)} for r, e in reps],
        "cases": [{"id": i.id, "key": i.incident_key, "title": i.title, "kind": i.kind, "severity": i.severity,
                   "status": i.status, "record_id": i.source_ref, "opened_at": as_aware(i.opened_at)} for i in incs],
        "checks": [_audit_out(a) | {"email": e} for a, e in checks],
    }


@router.post("/records/{record_id}/incident", status_code=201)
def create_incident(record_id: str, body: IncidentIn, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    rec = _rec(db, ctx, record_id)
    inc = investigation.create_incident(db, tenant=ctx.tenant, user=ctx.user, rec=rec, kind=body.kind,
                                        severity=body.severity, title=body.title, note=body.note, ip=ctx.ip,
                                        user_agent=ctx.user_agent)
    investigation.save_report_row(db, rec=rec, user=ctx.user, report_id=None, notes=body.note or "")
    db.commit()
    return {"id": inc.id, "incident_key": inc.incident_key, "kind": inc.kind, "severity": inc.severity,
            "title": inc.title, "status": inc.status}


@router.post("/records/{record_id}/knowledge", status_code=201)
def add_to_kb(record_id: str, ctx: Ctx = Depends(analyst), db: Session = Depends(get_db)):
    rec = _rec(db, ctx, record_id)
    doc = investigation.index_record(db, rec=rec, user=ctx.user, ip=ctx.ip, user_agent=ctx.user_agent)
    investigation.save_report_row(db, rec=rec, user=ctx.user, report_id=None, kb_document_id=doc.id)
    db.commit()
    return {"document_id": doc.id, "title": doc.title, "chunks": doc.chunk_count}


@router.get("/records/{record_id}/report.pdf")
def record_pdf(record_id: str, ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    rec = _rec(db, ctx, record_id)
    data = pdf.email_record_pdf(rec, ctx.tenant, ctx.user)
    rep = pdf.store_report(db, tenant=ctx.tenant, user=ctx.user, kind="email_investigation",
                           title=f"Email investigation — {rec.email}", data=data, ref_type="email_record", ref_id=rec.id)
    investigation.save_report_row(db, rec=rec, user=ctx.user, report_id=rep.id)
    verification_audit(db, tenant_id=ctx.tenant.id, record_id=rec.id, actor_id=ctx.user.id, action="report.pdf",
                       detail={"report_id": rep.id, "sha256": rep.sha256}, ip=ctx.ip, user_agent=ctx.user_agent)
    db.commit()
    fname = f"sentrix-email-{rec.email.replace('@', '_at_')}.pdf"
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"', "X-Report-Id": rep.id})


@router.get("/report/summary.pdf")
def summary_pdf(ctx: Ctx = Depends(current), db: Session = Depends(get_db)):
    st = stats(ctx, db)
    recs = db.scalars(select(EmailVerificationRecord).where(EmailVerificationRecord.tenant_id == ctx.tenant.id)).all()
    data = pdf.summary_pdf(ctx.tenant, ctx.user, st, recs)
    rep = pdf.store_report(db, tenant=ctx.tenant, user=ctx.user, kind="email_summary",
                           title="Email Identity Intelligence summary", data=data)
    audit(db, tenant_id=ctx.tenant.id, actor_id=ctx.user.id, action="report.generate", object_type="report",
          object_id=rep.id, detail={"kind": "email_summary"}, ip=ctx.ip, user_agent=ctx.user_agent)
    db.commit()
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="sentrix-email-identity-summary.pdf"',
                             "X-Report-Id": rep.id})
