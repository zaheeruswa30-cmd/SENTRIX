"""Sentrix AI — Email Identity analysis (RAG-grounded).

Answers are composed deterministically from stored evidence (email record, domain analysis,
risk findings, audit history) plus tenant knowledge-base chunks, so every statement links to
evidence. If an LLM is configured it may only *rephrase* the grounded summary; its output is
rejected if it makes identity/fraud claims (see ``FORBIDDEN``).
"""
from __future__ import annotations

import re

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.base import as_aware
from ...models import EmailVerificationRecord, Tenant, User, VerificationAuditLog
from ..audit import audit
from ..email_identity import service as svc
from ..email_identity.risk_engine import DISCLAIMER
from ..email_identity.syntax import validate_email_syntax
from ..knowledge import rag

ASSISTANT_NAME = "Sentrix AI"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
FORBIDDEN = re.compile(r"\b(is|are|seems|appears)\s+(a\s+)?(fraud\w*|scammer|criminal|untrustworthy|fake person|"
                       r"genuine person|real person|authentic person|trustworthy person)\b", re.I)

INTENTS = {
    "validity": r"technically valid|\bvalid\b|syntax|well[- ]formed",
    "infrastructure": r"infrastructure|mail server|\bmx\b|legitimate mail|receive mail|deliver",
    "ownership": r"owner|ownership|verified|verify the mailbox|mailbox",
    "failure": r"\bwhy\b|fail|failed|rejected|invalid",
    "suspicious": r"suspicious|phish|lookalike|impersonat|spoof|risk|threat|malicious|abuse",
    "missing_auth": r"missing|spf|dkim|dmarc|authentication|auth record",
    "steps": r"steps|fix|resolve|remediat|what should|how do i|next",
    "identity": r"who is|real person|authentic|identity|trust(worthy)?|legit(imate)? person|fraud|scam",
    "difference": r"difference|explain (the )?layers|what does .* mean|distinguish",
}


def detect_intents(q: str) -> list[str]:
    ql = q.lower()
    found = [k for k, pat in INTENTS.items() if re.search(pat, ql)]
    return found or ["overview"]


def _issue_text(i) -> str:
    return i.get("message", str(i)) if isinstance(i, dict) else str(i)


def _issue_sev(i) -> str:
    return i.get("severity", "info") if isinstance(i, dict) else "info"


def _cite(kind: str, label: str, ref: str | None = None) -> dict:
    return {"type": kind, "label": label, "ref": ref}


def _resolve_record(db: Session, tenant: Tenant, user: User, question: str, record_id: str | None,
                    email: str | None, run_if_missing: bool) -> tuple[EmailVerificationRecord | None, str | None]:
    if record_id:
        rec = db.get(EmailVerificationRecord, record_id)
        return (rec if rec and rec.tenant_id == tenant.id else None), None
    target = email or (EMAIL_RE.search(question).group(0) if EMAIL_RE.search(question) else None)
    if not target:
        return None, None
    norm = validate_email_syntax(target).normalized or target.lower()
    rec = db.scalar(select(EmailVerificationRecord).where(EmailVerificationRecord.tenant_id == tenant.id,
                                                          EmailVerificationRecord.email == norm))
    if rec is None and run_if_missing and user.role in ("admin", "analyst"):
        rec = svc.run_check(db, tenant=tenant, user=user, email=target, purpose="Sentrix AI analysis request")
        return rec, "A new technical check was run for this question (recorded in the audit trail)."
    return rec, None


def _ladder(rec: EmailVerificationRecord) -> dict:
    items = []
    for l in svc.layers(rec):
        items.append(f"{l['label']}: {l['state'].upper()} — {l['detail']}. {l['meaning']}")
    return {"kind": "telemetry", "title": "Validity layers (each layer is a separate claim)", "bullets": items,
            "citations": [_cite("email_record", f"Email record {rec.email}", rec.id)]}


def _findings(rec: EmailVerificationRecord, layer_filter: set[str] | None = None, positive_only=True) -> list[dict]:
    ra = rec.risk_assessments[0] if rec.risk_assessments else None
    if not ra:
        return []
    out = [f for f in ra.findings if (not positive_only or f["impact"] > 0)
           and (layer_filter is None or f["layer"] in layer_filter)]
    return sorted(out, key=lambda f: -f["impact"])


def _fmt_finding(f: dict) -> str:
    return f"{f['title']} — evidence: {f['evidence']} (confidence {f['confidence']}%, {f['severity']})."


def answer(db: Session, *, tenant: Tenant, user: User, question: str, record_id: str | None = None,
           email: str | None = None, run_if_missing: bool = True, ip=None, user_agent=None) -> dict:
    question = (question or "").strip()[:1000]
    intents = detect_intents(question)
    rec, note = _resolve_record(db, tenant, user, question, record_id, email, run_if_missing)
    sections: list[dict] = []
    summary_parts: list[str] = []

    if rec is None:
        summary_parts.append("No email record matched this question. Mention an address (for example "
                             "“Is jane@example.com technically valid?”) or open an email record and ask from there.")
    else:
        d = svc.serialize_record(rec, detail=True)
        da = d.get("domain_analysis") or {}
        risk = d.get("risk") or {}
        cite_rec = _cite("email_record", f"Email record {rec.email}", rec.id)
        if note:
            sections.append({"kind": "history", "title": "Check performed", "text": note, "citations": [cite_rec]})

        if "validity" in intents or "overview" in intents or "failure" in intents:
            ok = rec.syntax_status == "valid"
            summary_parts.append(
                f"{rec.email} is {'syntactically valid' if ok else 'not syntactically valid'}"
                + (f"; its domain {'exists' if rec.dns_status == 'resolves' else 'does not resolve (' + rec.dns_status + ')'}"
                   f" and mail infrastructure is '{rec.mx_status}'." if ok else ".")
                + " Technical validity means mail can be routed to the domain; it does not confirm the mailbox exists "
                  "or who uses it.")
        if "infrastructure" in intents:
            mx = da.get("mx_records") or []
            summary_parts.append(
                f"Mail infrastructure for {rec.domain}: {rec.mx_status}"
                + (f" with {len(mx)} MX host(s) ({', '.join(m['host'] for m in mx[:4])})." if mx else ".")
                + f" Sender authentication: SPF {rec.spf_status}, DKIM {rec.dkim_status}, DMARC {rec.dmarc_status}.")
            sections.append({"kind": "telemetry", "title": "DNS evidence", "bullets":
                             [f"MX {m['preference']} {m['host']} → {', '.join(m.get('addresses', [])) or 'no address'}" for m in mx]
                             or [(da.get('mx') or {}).get('explanation') or "No MX records published."],
                             "citations": [_cite("domain_analysis", f"Domain analysis {rec.domain}", da.get("id"))]})
        if "ownership" in intents:
            if rec.ownership_status == "verified":
                summary_parts.append(f"Mailbox ownership is VERIFIED ({rec.ownership_method}, "
                                     f"{as_aware(rec.ownership_verified_at).isoformat() if rec.ownership_verified_at else ''}). "
                                     "This proves someone could read mail sent to this inbox at that time — "
                                     "not who that person is.")
            else:
                summary_parts.append(f"Mailbox ownership is NOT verified (status: {rec.ownership_status}). Technical "
                                     "validity and domain reputation do not substitute for an ownership challenge.")
            hist = db.scalars(select(VerificationAuditLog).where(
                VerificationAuditLog.tenant_id == tenant.id, VerificationAuditLog.email_record_id == rec.id,
                VerificationAuditLog.action.like("ownership.%")).order_by(VerificationAuditLog.at.desc()).limit(8)).all()
            if hist:
                sections.append({"kind": "history", "title": "Ownership verification history",
                                 "bullets": [f"{as_aware(h.at).strftime('%Y-%m-%d %H:%M UTC')} · {h.action} · {h.outcome}" for h in hist],
                                 "citations": [_cite("audit", "Verification audit log", rec.id)]})
        if "failure" in intents:
            fails = _findings(rec, {"syntax", "domain", "mail_infrastructure", "ownership"})
            sections.append({"kind": "risk", "title": "Why checks failed",
                             "bullets": [_fmt_finding(f) for f in fails] or ["No validity or ownership failures are recorded."],
                             "citations": [cite_rec]})
        if "missing_auth" in intents:
            miss = []
            for mech in ("spf", "dkim", "dmarc"):
                a = da.get(mech) or {}
                st = a.get("status", "not_checked")
                if st not in ("valid", "enforced", "selector_found", "signature_pass"):
                    miss.append(f"{mech.upper()}: {st}. {a.get('explanation') or ''}")
                for issue in (a.get("issues") or [])[:3]:
                    miss.append(f"{mech.upper()} issue ({_issue_sev(issue)}): {_issue_text(issue)}")
            gaps = [f"{m.upper()} {(da.get(m) or {}).get('status', 'not_checked')}" for m in ("spf", "dkim", "dmarc")
                    if (da.get(m) or {}).get("status") not in ("valid", "enforced", "selector_found", "signature_pass")]
            for m in ("spf", "dkim", "dmarc"):
                serious = [i for i in ((da.get(m) or {}).get("issues") or []) if _issue_sev(i) in ("medium", "high")]
                if serious and not any(g.startswith(m.upper()) for g in gaps):
                    gaps.append(f"{m.upper()} has {len(serious)} configuration issue(s)")
            summary_parts.append("Authentication gaps: " + (", ".join(gaps) if gaps else "none detected")
                                 + ". These describe the domain owner's anti-spoofing setup, not the user. "
                                   "A DKIM key in DNS does not mean a given message passed DKIM.")
            sections.append({"kind": "telemetry", "title": "Authentication records", "bullets": miss or
                             ["SPF, DKIM key discovery and DMARC all present."],
                             "citations": [_cite("domain_analysis", f"SPF/DKIM/DMARC lookups for {rec.domain}", da.get("id"))]})
        if "suspicious" in intents or "overview" in intents:
            sus = [f for f in _findings(rec) if f["category"] in
                   ("reputation", "suspicious_domain", "threat_intel", "abuse", "disposable")]
            summary_parts.append(
                f"Risk score {rec.risk_score} ({rec.risk_band}, confidence {risk.get('confidence')}%). "
                + (f"{len(sus)} reputation/impersonation indicator(s) found." if sus else
                   "No suspicious domain indicators were found."))
            sections.append({"kind": "risk", "title": "Risk findings with evidence",
                             "bullets": [_fmt_finding(f) for f in _findings(rec)] or ["No risk-increasing findings."],
                             "citations": [_cite("risk_assessment", f"Risk assessment {risk.get('engine_version')}", rec.id)]})
        if "steps" in intents or "failure" in intents or "missing_auth" in intents:
            recs = []
            for f in _findings(rec):
                if f.get("recommendation") and f["recommendation"] not in recs:
                    recs.append(f["recommendation"])
            if rec.ownership_status != "verified" and rec.mx_status in ("present", "implicit"):
                recs.append("If control of the mailbox matters for this purpose, start an ownership verification challenge.")
            if rec.is_suspicious and not rec.incident_id:
                recs.append("Indicators are present: review the evidence and, if corroborated, open an investigation case.")
            sections.append({"kind": "steps", "title": "Recommended steps", "bullets": recs or ["No action required."],
                             "citations": [cite_rec]})

    if "identity" in intents or "difference" in intents:
        sections.append({"kind": "ai", "title": "What email checks can and cannot prove", "bullets": [
            "Valid syntax — the text is a well-formed address.",
            "Existing domain — the domain resolves in DNS.",
            "Configured mail infrastructure — MX hosts exist so the domain can receive mail.",
            "SPF/DKIM/DMARC — the domain owner's anti-spoofing configuration; a DKIM key in DNS is not proof that a message passed DKIM.",
            "Verified mailbox ownership — someone completed a one-time challenge sent to the inbox.",
            "Real-world identity — never established by Sentrix email checks; use a dedicated identity-proofing process.",
        ], "citations": [_cite("kb", "Email validity layers")]})
        if "identity" in intents:
            summary_parts.append("Sentrix cannot tell you whether a person is authentic or trustworthy from an email "
                                 "address. At most it can show technical validity, domain configuration/reputation and "
                                 "verified control of the mailbox.")

    # RAG knowledge
    kq = question + " " + " ".join(intents) + (f" {rec.domain}" if rec else "")
    hits = rag.search(db, tenant.id, kq, k=4, ref_id=rec.id if rec else None)
    if hits:
        sections.append({"kind": "rag", "title": "Knowledge base", "bullets":
                         [f"{h['citation']}: {h['text'][:260]}{'…' if len(h['text']) > 260 else ''}" for h in hits],
                         "citations": [_cite("kb_chunk", h["citation"], h["chunk_id"]) for h in hits]})

    summary = " ".join(summary_parts) or "See the evidence below."
    summary, llm_used = _maybe_rephrase(summary)
    audit(db, tenant_id=tenant.id, actor_id=user.id, action="ai.email.ask", object_type="email_record",
          object_id=rec.id if rec else None, detail={"intents": intents, "kb_hits": len(hits), "llm": llm_used},
          ip=ip, user_agent=user_agent)
    db.commit()
    return {"assistant": ASSISTANT_NAME, "question": question, "intents": intents,
            "record": svc.serialize_record(rec) if rec else None, "summary": summary, "sections": sections,
            "disclaimer": DISCLAIMER, "grounded": True, "llm_used": llm_used}


def _maybe_rephrase(summary: str) -> tuple[str, bool]:
    s = get_settings()
    if s.LLM_PROVIDER == "none":
        return summary, False
    prompt = ("Rewrite the following security analysis in clear plain English for an analyst. Do not add facts. "
              "Never state or imply that a person is fraudulent, trustworthy, authentic or real.\n\n" + summary)
    try:
        if s.LLM_PROVIDER == "ollama":
            r = httpx.post(f"{s.OLLAMA_BASE_URL.rstrip('/')}/api/generate", timeout=s.LLM_TIMEOUT_SECONDS,
                           json={"model": s.LLM_REPORT_MODEL, "prompt": prompt, "stream": False})
            out = r.json().get("response", "")
        else:
            r = httpx.post("https://api.openai.com/v1/chat/completions", timeout=s.LLM_TIMEOUT_SECONDS,
                           headers={"Authorization": f"Bearer {s.OPENAI_API_KEY}"},
                           json={"model": s.OPENAI_MODEL, "messages": [{"role": "user", "content": prompt}]})
            out = r.json()["choices"][0]["message"]["content"]
    except Exception:  # noqa: BLE001 — fall back to grounded text
        return summary, False
    out = (out or "").strip()
    if not out or FORBIDDEN.search(out) or len(out) > 4 * len(summary) + 200:
        return summary, False
    return out, True
