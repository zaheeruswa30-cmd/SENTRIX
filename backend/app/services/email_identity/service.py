"""Email Identity Intelligence orchestration: run checks, persist layered results, score risk,
and serialise records with an explicit separation of validity, reputation and ownership."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.base import as_aware, utcnow
from ...models import (
    DnsAuthenticationResult, DomainAnalysis, EmailRiskAssessment, EmailVerificationRecord, Tenant,
    ThreatIndicator, User,
)
from ..audit import verification_audit
from ..errors import ServiceError
from . import auth_records, dkim_verify, mail_infra, reputation, suspicious
from .dns_client import DnsClient
from .risk_engine import DISCLAIMER, assess
from .syntax import validate_email_syntax

# Swappable for tests / offline demos (see tests/conftest.py)
DNS_FACTORY: Callable[[], DnsClient] = DnsClient

LAYER_ORDER = ["syntax", "domain", "mail_infrastructure", "authentication", "ownership", "real_world_identity"]
LAYER_COPY = {
    "syntax": ("Valid email syntax", "The text is a well-formed address (RFC 5322). Says nothing about delivery."),
    "domain": ("Existing email domain", "The domain exists in public DNS."),
    "mail_infrastructure": ("Configured mail infrastructure", "MX (or implicit) hosts exist, so the domain can receive mail. "
                            "Individual mailboxes are never probed."),
    "authentication": ("SPF / DKIM / DMARC configuration", "Sender-authentication controls the domain owner has published. "
                       "Protects against spoofing of the domain; not a statement about the user."),
    "ownership": ("Verified mailbox ownership", "Someone completed a one-time challenge sent to this inbox."),
    "real_world_identity": ("Real-world identity", "NOT verified by Sentrix. No email check can establish who a person is; "
                            "use a dedicated identity-proofing process if required."),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── threat intelligence ─────────────────────────────────────────────────────

def threat_matches(db: Session, tenant_id: str, *, email: str | None, domain: str, mx_hosts: list[str],
                   ips: list[str]) -> list[dict]:
    labels = domain.split(".")
    parents = {".".join(labels[i:]) for i in range(len(labels) - 1)}
    mx_doms = set()
    for h in mx_hosts:
        hl = h.lower().split(".")
        mx_doms |= {".".join(hl[i:]) for i in range(max(0, len(hl) - 3), len(hl) - 1)}
    conds = [and_(ThreatIndicator.indicator_type == "domain", ThreatIndicator.value.in_(parents | mx_doms))]
    if email:
        conds.append(and_(ThreatIndicator.indicator_type == "email", ThreatIndicator.value == email.lower()))
    if ips:
        conds.append(and_(ThreatIndicator.indicator_type == "ip", ThreatIndicator.value.in_(ips)))
    rows = db.scalars(select(ThreatIndicator).where(
        ThreatIndicator.tenant_id == tenant_id, ThreatIndicator.is_active.is_(True), or_(*conds))).all()
    out = []
    for r in rows:
        if r.expires_at and as_aware(r.expires_at) < _now():
            continue
        via = "address" if r.indicator_type == "email" else ("mail host" if r.value in mx_doms and r.value not in parents
                                                             else "domain" if r.indicator_type == "domain" else "mail host IP")
        out.append({"indicator_id": r.id, "indicator_type": r.indicator_type, "value": r.value, "source": r.source,
                    "severity": r.severity, "confidence": r.confidence, "description": r.description, "matched_via": via})
    return out


# ── domain analysis ─────────────────────────────────────────────────────────

def analyze_domain(db: Session, tenant: Tenant, *, ascii_domain: str, unicode_domain: str, is_idn: bool,
                   selectors: list[str] | None = None, force: bool = False) -> DomainAnalysis:
    s = get_settings()
    da = db.scalar(select(DomainAnalysis).where(DomainAnalysis.tenant_id == tenant.id,
                                                DomainAnalysis.domain == ascii_domain))
    if da and not force and not selectors and as_aware(da.expires_at) > _now():
        return da
    dns = DNS_FACTORY()
    infra = mail_infra.analyze_mail_infrastructure(dns, ascii_domain)
    if da is None:
        da = DomainAnalysis(tenant_id=tenant.id, domain=ascii_domain, ascii_domain=ascii_domain, expires_at=_now())
        db.add(da)
    da.is_idn = is_idn
    da.dns_status, da.mx_status = infra.dns_status, infra.mx_status
    da.a_records, da.aaaa_records, da.ns_records = infra.a_records, infra.aaaa_records, infra.ns_records
    da.mx_records = infra.mx_records
    da.resolver_used = infra.resolver
    disp, src = reputation.check_disposable(ascii_domain)
    da.is_disposable, da.disposable_source = disp, src
    da.is_free_provider = reputation.is_free_provider(ascii_domain)

    age = reputation.rdap_domain_age(ascii_domain) if infra.dns_status == "resolves" else {"status": "not_checked"}
    da.age_source = "rdap" if age.get("status") == "ok" else age.get("status", "not_checked")
    da.domain_age_days = age.get("age_days")
    da.registration_date = datetime.fromisoformat(age["registration_date"]) if age.get("registration_date") else None
    rep = reputation.dnsbl_reputation(dns, ascii_domain) if infra.dns_status == "resolves" else {"status": "not_checked"}
    da.reputation_status = rep.get("status", "not_checked")
    da.reputation_detail = {"dnsbl": rep, "rdap": age}
    da.suspicious_indicators = suspicious.find_indicators(ascii_domain, s.protected_brands, da.domain_age_days)
    mx_hosts = [m["host"] for m in infra.mx_records if m.get("host") not in (None, ".")]
    ips = infra.a_records + [a for m in infra.mx_records for a in m.get("addresses", [])]
    da.threat_matches = threat_matches(db, tenant.id, email=None, domain=ascii_domain, mx_hosts=mx_hosts, ips=ips)

    # authentication records (fresh rows replace previous configuration rows)
    for old in list(da.auth_results):
        if old.mechanism != "dkim_signature":
            db.delete(old)
    db.flush()
    rows: list[DnsAuthenticationResult] = [
        DnsAuthenticationResult(tenant_id=tenant.id, mechanism="dns", status=infra.dns_status, query_name=ascii_domain,
                                raw_records=[f"{l['type']} {l['status']}: {', '.join(l['records'][:6])}" for l in infra.lookups],
                                parsed={"lookups": infra.lookups}, issues=[], explanation=infra.explanation),
        DnsAuthenticationResult(tenant_id=tenant.id, mechanism="mx", status=infra.mx_status, query_name=ascii_domain,
                                raw_records=[f"{m['preference']} {m['host']}" for m in infra.mx_records],
                                parsed={"mx": infra.mx_records}, issues=[], explanation=infra.explanation),
    ]
    if infra.dns_status in ("resolves", "no_address"):
        spf = auth_records.check_spf(dns, ascii_domain)
        dmarc = auth_records.check_dmarc(dns, ascii_domain)
        dkim_sum, dkim_found = auth_records.check_dkim(dns, ascii_domain, (selectors or []) + s.dkim_selectors)
        for res in [spf, dmarc, dkim_sum] + dkim_found:
            rows.append(DnsAuthenticationResult(
                tenant_id=tenant.id, mechanism=res.mechanism, status=res.status, query_name=res.query_name,
                selector=res.selector, raw_records=res.raw_records, parsed=res.parsed | ({"summary": True} if res is dkim_sum else {}),
                issues=res.issues, explanation=res.explanation))
    for r in rows:
        da.auth_results.append(r)
    da.analyzed_at = utcnow()
    da.expires_at = _now() + timedelta(hours=s.DOMAIN_CACHE_HOURS)
    db.flush()
    return da


def _latest(da: DomainAnalysis | None, mechanism: str, summary_only: bool = False) -> DnsAuthenticationResult | None:
    if not da:
        return None
    rows = [r for r in da.auth_results if r.mechanism == mechanism and (not summary_only or (r.parsed or {}).get("summary"))]
    return max(rows, key=lambda r: as_aware(r.checked_at)) if rows else None


def _auth_dict(r: DnsAuthenticationResult | None) -> dict:
    if not r:
        return {"status": "not_checked"}
    return {"status": r.status, "query_name": r.query_name, "raw_records": r.raw_records or [], "parsed": r.parsed or {},
            "issues": r.issues or [], "explanation": r.explanation, "selector": r.selector,
            "checked_at": as_aware(r.checked_at)}


# ── risk ────────────────────────────────────────────────────────────────────

def recompute_risk(db: Session, record: EmailVerificationRecord) -> EmailRiskAssessment:
    da = record.domain_analysis
    sig = None
    if record.dkim_status in ("signature_pass", "signature_fail"):
        sig = {"status": record.dkim_status}
    ev = {
        "syntax": record.syntax_detail or {},
        "infra": {"domain": record.domain, "dns_status": record.dns_status, "mx_status": record.mx_status,
                  "mx_records": (da.mx_records if da else []) or [],
                  "explanation": (_latest(da, "mx").explanation if _latest(da, "mx") else "")},
        "spf": _auth_dict(_latest(da, "spf")), "dmarc": _auth_dict(_latest(da, "dmarc")),
        "dkim": sig or _auth_dict(_latest(da, "dkim", summary_only=True)),
        "disposable": bool(da and da.is_disposable), "disposable_source": da.disposable_source if da else None,
        "free_provider": bool(da and da.is_free_provider), "role_account": record.is_role_account,
        "reputation": (da.reputation_detail or {}).get("dnsbl") if da else None,
        "age": (da.reputation_detail or {}).get("rdap") if da else None,
        "suspicious": (da.suspicious_indicators or []) if da else [],
        "threat_matches": ((da.threat_matches if da else None) or []) + (threat_matches(
            db, record.tenant_id, email=record.email, domain=record.domain, mx_hosts=[], ips=[]) if record.domain else []),
        "ownership_status": record.ownership_status,
    }
    # de-duplicate TI matches
    seen, tm = set(), []
    for m in ev["threat_matches"]:
        if m["indicator_id"] not in seen:
            seen.add(m["indicator_id"])
            tm.append(m)
    ev["threat_matches"] = tm
    a = assess(ev)
    ra = EmailRiskAssessment(tenant_id=record.tenant_id, email_record_id=record.id, score=a.score, band=a.band,
                             confidence=a.confidence, findings=a.findings, summary=a.summary,
                             engine_version=a.engine_version)
    db.add(ra)
    record.risk_score, record.risk_band = a.score, a.band
    record.findings_count = sum(1 for f in a.findings if f["impact"] > 0)
    record.is_suspicious, record.is_technically_invalid = a.is_suspicious, a.is_technically_invalid
    db.flush()
    return ra


# ── check orchestration ─────────────────────────────────────────────────────

def run_check(db: Session, *, tenant: Tenant, user: User, email: str, purpose: str,
              selectors: list[str] | None = None, force: bool = False,
              ip: str | None = None, user_agent: str | None = None) -> EmailVerificationRecord:
    syn = validate_email_syntax(email)
    key = syn.normalized or email.strip().lower()
    if not key:
        raise ServiceError(400, "Enter an email address.")
    rec = db.scalar(select(EmailVerificationRecord).where(EmailVerificationRecord.tenant_id == tenant.id,
                                                          EmailVerificationRecord.email == key[:320]))
    created = rec is None
    if rec is None:
        rec = EmailVerificationRecord(tenant_id=tenant.id, email=key[:320], submitted_by=user.id, check_count=0,
                                      ownership_status="unverified", dkim_status="not_checked")
        db.add(rec)
    rec.purpose = (purpose or rec.purpose or "")[:200]
    rec.local_part = syn.local_part[:128]
    rec.domain = (syn.ascii_domain or syn.domain or "")[:253]
    rec.syntax_status = "valid" if syn.valid else "invalid"
    rec.syntax_detail = syn.to_dict()
    rec.is_role_account = syn.is_role_account
    if syn.valid:
        da = analyze_domain(db, tenant, ascii_domain=syn.ascii_domain, unicode_domain=syn.domain, is_idn=syn.is_idn,
                            selectors=selectors, force=force)
        rec.domain_analysis = da
        rec.dns_status, rec.mx_status = da.dns_status, da.mx_status
        rec.spf_status = (_latest(da, "spf").status if _latest(da, "spf") else "not_checked")
        rec.dmarc_status = (_latest(da, "dmarc").status if _latest(da, "dmarc") else "not_checked")
        if rec.dkim_status not in ("signature_pass", "signature_fail") or force:
            d = _latest(da, "dkim", summary_only=True)
            rec.dkim_status = d.status if d else "not_checked"
        rec.disposable_status = "disposable" if da.is_disposable else "not_disposable"
    else:
        rec.domain_analysis = None
        rec.dns_status = rec.mx_status = rec.spf_status = rec.dkim_status = rec.dmarc_status = "not_checked"
        rec.disposable_status = "unknown"
    rec.check_count += 1
    rec.last_checked_at = utcnow()
    db.flush()
    ra = recompute_risk(db, rec)
    verification_audit(db, tenant_id=tenant.id, record_id=rec.id, actor_id=user.id,
                       action="check.create" if created else "check.recheck",
                       detail={"syntax": rec.syntax_status, "dns": rec.dns_status, "mx": rec.mx_status,
                               "risk_score": ra.score, "band": ra.band, "purpose": rec.purpose},
                       ip=ip, user_agent=user_agent)
    db.commit()
    db.refresh(rec)
    return rec


def verify_dkim_message(db: Session, *, tenant: Tenant, user: User, raw: bytes, record: EmailVerificationRecord | None,
                        ip: str | None, user_agent: str | None) -> dict:
    try:
        result = dkim_verify.verify_message(raw, DNS_FACTORY())
    except ValueError as exc:
        raise ServiceError(413, str(exc)) from exc
    da = record.domain_analysis if record else None
    row = DnsAuthenticationResult(
        tenant_id=tenant.id, domain_analysis_id=da.id if da else None, email_record_id=record.id if record else None,
        mechanism="dkim_signature", status=result.status, query_name=result.from_domain or "",
        selector=",".join(s.selector for s in result.signatures)[:100] or None,
        raw_records=result.receiver_claims, parsed=result.to_dict(), issues=[], explanation=result.explanation)
    db.add(row)
    if record and result.status in ("signature_pass", "signature_fail"):
        record.dkim_status = result.status
        recompute_risk(db, record)
    if record:
        verification_audit(db, tenant_id=tenant.id, record_id=record.id, actor_id=user.id, action="dkim.verify_message",
                           detail={"status": result.status, "message_sha256": result.message_sha256}, ip=ip,
                           user_agent=user_agent)
    else:
        from ..audit import audit
        audit(db, tenant_id=tenant.id, actor_id=user.id, action="email.dkim.verify_message", object_type="message",
              object_id=result.message_sha256[:64], detail={"status": result.status}, ip=ip, user_agent=user_agent)
    db.commit()
    out = result.to_dict()
    out["result_id"] = row.id
    out["note"] = ("Only the message fingerprint and header summary were stored; the message body was discarded. "
                   "Authentication-Results lines are claims by the receiving server and were not re-verified.")
    return out


# ── classification + serialisation ───────────────────────────────────────────

def classifications(rec: EmailVerificationRecord) -> list[str]:
    c = []
    if rec.ownership_status == "verified":
        c.append("verified")
    elif rec.ownership_status == "pending":
        c.append("pending")
    else:
        c.append("unverified")
    if rec.is_technically_invalid or rec.syntax_status == "invalid":
        c.append("invalid")
    if rec.is_suspicious:
        c.append("suspicious")
    return c


def filter_clause(name: str):
    E = EmailVerificationRecord
    return {
        "verified": E.ownership_status == "verified",
        "pending": E.ownership_status == "pending",
        "unverified": E.ownership_status.in_(("unverified", "expired", "failed", "locked")),
        "invalid": or_(E.is_technically_invalid.is_(True), E.syntax_status == "invalid"),
        "suspicious": E.is_suspicious.is_(True),
    }.get(name)


def layers(rec: EmailVerificationRecord) -> list[dict]:
    auth_ok = rec.spf_status in ("valid",) and rec.dmarc_status in ("enforced", "monitoring")
    state = {
        "syntax": "pass" if rec.syntax_status == "valid" else "fail",
        "domain": {"resolves": "pass", "nxdomain": "fail", "no_address": "warn"}.get(rec.dns_status, "unknown"),
        "mail_infrastructure": {"present": "pass", "implicit": "warn", "null_mx": "fail", "absent": "fail"}.get(rec.mx_status, "unknown"),
        "authentication": "unknown" if rec.spf_status == "not_checked" else ("pass" if auth_ok else "warn"),
        "ownership": {"verified": "pass", "pending": "pending", "locked": "fail", "failed": "fail"}.get(rec.ownership_status, "unknown"),
        "real_world_identity": "not_assessed",
    }
    detail = {
        "syntax": rec.syntax_status, "domain": rec.dns_status, "mail_infrastructure": rec.mx_status,
        "authentication": f"SPF {rec.spf_status} · DKIM {rec.dkim_status} · DMARC {rec.dmarc_status}",
        "ownership": rec.ownership_status + (f" ({rec.ownership_method}, {as_aware(rec.ownership_verified_at).strftime("%Y-%m-%d %H:%M UTC")})"
                                             if rec.ownership_verified_at else ""),
        "real_world_identity": "outside the scope of email analysis",
    }
    return [{"key": k, "label": LAYER_COPY[k][0], "meaning": LAYER_COPY[k][1], "state": state[k], "detail": detail[k]}
            for k in LAYER_ORDER]


def serialize_record(rec: EmailVerificationRecord, detail: bool = False) -> dict:
    latest = rec.risk_assessments[0] if rec.risk_assessments else None
    out = {
        "id": rec.id, "email": rec.email, "domain": rec.domain, "purpose": rec.purpose,
        "syntax_status": rec.syntax_status, "dns_status": rec.dns_status, "mx_status": rec.mx_status,
        "spf_status": rec.spf_status, "dkim_status": rec.dkim_status, "dmarc_status": rec.dmarc_status,
        "disposable_status": rec.disposable_status, "ownership_status": rec.ownership_status,
        "ownership_verified_at": as_aware(rec.ownership_verified_at), "ownership_method": rec.ownership_method,
        "is_role_account": rec.is_role_account,
        "risk_score": rec.risk_score, "risk_band": rec.risk_band,
        "risk_confidence": latest.confidence if latest else None,
        "findings_count": rec.findings_count, "top_findings": [
            f["title"] for f in sorted((latest.findings if latest else []), key=lambda f: -f["impact"]) if f["impact"] > 0][:3],
        "classifications": classifications(rec), "incident_id": rec.incident_id,
        "check_count": rec.check_count, "last_checked_at": as_aware(rec.last_checked_at),
        "created_at": as_aware(rec.created_at),
    }
    if detail:
        da = rec.domain_analysis
        out["layers"] = layers(rec)
        out["syntax"] = rec.syntax_detail
        out["risk"] = None if not latest else {
            "score": latest.score, "band": latest.band, "confidence": latest.confidence, "summary": latest.summary,
            "findings": latest.findings, "engine_version": latest.engine_version, "assessed_at": as_aware(latest.created_at),
            "disclaimer": DISCLAIMER}
        out["risk_history"] = [{"score": r.score, "band": r.band, "at": as_aware(r.created_at)} for r in rec.risk_assessments[:20]]
        out["domain_analysis"] = serialize_domain(da) if da else None
    return out


def serialize_domain(da: DomainAnalysis) -> dict:
    sel = [r for r in da.auth_results if r.mechanism == "dkim" and not (r.parsed or {}).get("summary")]
    sigs = [r for r in da.auth_results if r.mechanism == "dkim_signature"]
    return {
        "id": da.id, "domain": da.domain, "is_idn": da.is_idn, "dns_status": da.dns_status, "mx_status": da.mx_status,
        "a_records": da.a_records or [], "aaaa_records": da.aaaa_records or [], "ns_records": da.ns_records or [],
        "mx_records": da.mx_records or [], "is_disposable": da.is_disposable, "disposable_source": da.disposable_source,
        "is_free_provider": da.is_free_provider, "domain_age_days": da.domain_age_days, "age_source": da.age_source,
        "registration_date": as_aware(da.registration_date), "reputation_status": da.reputation_status,
        "reputation_detail": da.reputation_detail or {}, "suspicious_indicators": da.suspicious_indicators or [],
        "threat_matches": da.threat_matches or [], "resolver_used": da.resolver_used,
        "analyzed_at": as_aware(da.analyzed_at), "expires_at": as_aware(da.expires_at),
        "dns": _auth_dict(_latest(da, "dns")), "mx": _auth_dict(_latest(da, "mx")),
        "spf": _auth_dict(_latest(da, "spf")), "dmarc": _auth_dict(_latest(da, "dmarc")),
        "dkim": _auth_dict(_latest(da, "dkim", summary_only=True)),
        "dkim_selectors": [_auth_dict(r) for r in sel],
        "dkim_signature_checks": [_auth_dict(r) | {"id": r.id} for r in sorted(sigs, key=lambda r: as_aware(r.checked_at), reverse=True)[:10]],
    }
