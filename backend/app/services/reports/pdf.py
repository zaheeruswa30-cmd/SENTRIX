"""Sentrix-branded PDF reports (fpdf2, core fonts → text is sanitised to Latin-1)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...models import EmailVerificationRecord, Report, Tenant, User
from ..email_identity.risk_engine import DISCLAIMER
from ..email_identity.service import layers, serialize_record

INK = (11, 18, 32)
CYAN = (34, 211, 238)
INDIGO = (99, 102, 241)
MUTED = (100, 116, 139)
STATE_COLOR = {"pass": (22, 163, 74), "warn": (217, 119, 6), "fail": (220, 38, 38), "pending": (37, 99, 235)}

_REPL = {"\u2014": "-", "\u2013": "-", "\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"', "\u2026": "...",
         "\u203a": ">", "\u2192": "->", "\u00b7": "-", "\u2022": "-", "\u2265": ">=", "\u2264": "<="}


def latin(text) -> str:
    t = str(text if text is not None else "")
    for a, b in _REPL.items():
        t = t.replace(a, b)
    return t.encode("latin-1", "replace").decode("latin-1")


class SentrixPDF(FPDF):
    def __init__(self, title: str, tenant: str):
        super().__init__(format="A4")
        self.doc_title, self.tenant = title, tenant
        self.set_auto_page_break(True, 18)
        self.set_margins(16, 16, 16)
        s = get_settings()
        self.set_title(latin(title))
        self.set_author(latin(f"{s.APP_NAME} {s.APP_VERSION}"))
        self.set_creator(latin(s.APP_NAME))
        self.set_subject(latin(s.APP_TAGLINE))

    def multi_cell(self, w, h=None, text="", *args, **kwargs):  # always continue at the left margin
        kwargs.setdefault("new_x", "LMARGIN")
        kwargs.setdefault("new_y", "NEXT")
        return super().multi_cell(w, h, text, *args, **kwargs)

    def header(self):
        self.set_fill_color(*INK)
        self.rect(0, 0, 210, 20, "F")
        # shield mark
        self.set_fill_color(*CYAN)
        self.polygon([(16, 5), (23, 5), (23, 11), (19.5, 15), (16, 11)], style="F")
        self.set_xy(26, 5)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 13)
        self.cell(40, 6, "SENTRIX")
        self.set_xy(26, 11)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*CYAN)
        self.cell(120, 4, latin("Intelligent Security Operations, Threat Detection and Digital Identity Intelligence"))
        self.set_xy(130, 7)
        self.set_text_color(200, 210, 225)
        self.set_font("Helvetica", "", 8)
        self.cell(64, 6, latin(self.tenant), align="R")
        self.set_y(26)
        self.set_text_color(*INK)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*MUTED)
        self.cell(0, 5, latin(f"Sentrix - {self.doc_title} - CONFIDENTIAL - page {self.page_no()}/{{nb}}"), align="C")

    def h1(self, t):
        self.set_font("Helvetica", "B", 16)
        self.multi_cell(0, 8, latin(t))
        self.ln(1)

    def h2(self, t):
        self.ln(3)
        self.set_font("Helvetica", "B", 11.5)
        self.set_text_color(*INDIGO)
        self.multi_cell(0, 6, latin(t))
        self.set_draw_color(*CYAN)
        self.line(self.l_margin, self.get_y(), 210 - self.r_margin, self.get_y())
        self.ln(2)
        self.set_text_color(*INK)

    def para(self, t, size=9.5, color=INK):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 5, latin(t))
        self.set_text_color(*INK)

    def kv(self, rows: list[tuple[str, str]]):
        for k, v in rows:
            self.set_font("Helvetica", "B", 9)
            self.cell(48, 5.5, latin(k))
            self.set_font("Helvetica", "", 9)
            self.multi_cell(0, 5.5, latin(v))

    def bullet(self, t, color=None):
        self.set_font("Helvetica", "", 9)
        x = self.get_x()
        if color:
            self.set_fill_color(*color)
            self.rect(x + 1, self.get_y() + 1.7, 2, 2, "F")
        else:
            self.cell(4, 5, "-")
        self.set_x(x + 5)
        self.multi_cell(0, 5, latin(t))


def email_record_pdf(rec: EmailVerificationRecord, tenant: Tenant, user: User) -> bytes:
    d = serialize_record(rec, detail=True)
    da = d.get("domain_analysis") or {}
    risk = d.get("risk") or {}
    pdf = SentrixPDF("Email Identity Investigation Report", tenant.name)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.h1(f"Email Identity Investigation: {rec.email}")
    pdf.para(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {user.name} ({user.role}). "
             f"Purpose of check: {rec.purpose or 'not stated'}.", 8.5, MUTED)
    pdf.h2("Summary")
    pdf.kv([("Email address", rec.email), ("Domain", rec.domain or "-"),
            ("Risk score", f"{rec.risk_score} / 100 ({rec.risk_band}), confidence {risk.get('confidence', '-')}%"),
            ("Ownership", rec.ownership_status + (f" ({rec.ownership_method}, {d['ownership_verified_at']})"
                                                  if rec.ownership_verified_at else "")),
            ("Classifications", ", ".join(d["classifications"])),
            ("Last checked", str(d["last_checked_at"])), ("Linked case", rec.incident_id or "none")])
    if risk.get("summary"):
        pdf.ln(1)
        pdf.para(risk["summary"])
    pdf.h2("Validity layers (each is a separate claim)")
    for l in layers(rec):
        pdf.bullet(f"{l['label']}: {l['state'].upper()} - {l['detail']}. {l['meaning']}",
                   STATE_COLOR.get(l["state"], MUTED))
    pdf.h2("DNS and authentication evidence")
    pdf.kv([("DNS", f"{rec.dns_status}; A: {', '.join(da.get('a_records') or []) or '-'}"),
            ("MX", f"{rec.mx_status}; " + (", ".join(f"{m['preference']} {m['host']}" for m in da.get("mx_records") or []) or "-"))])
    for mech in ("spf", "dkim", "dmarc"):
        a = da.get(mech) or {}
        pdf.kv([(mech.upper(), f"{a.get('status', 'not_checked')} - {a.get('explanation') or ''}")])
        for r in (a.get("raw_records") or [])[:3]:
            pdf.para(f"    {r[:300]}", 8, MUTED)
        for i in (a.get("issues") or [])[:4]:
            pdf.bullet(i.get("message", str(i)) if isinstance(i, dict) else str(i), STATE_COLOR["warn"])
    pdf.para("Note: discovering a DKIM public key in DNS does not prove that any message passed DKIM. Signatures are "
             "verified only when the raw message is supplied.", 8, MUTED)
    for sc in (da.get("dkim_signature_checks") or [])[:3]:
        pdf.kv([("DKIM message check", f"{sc['status']} ({str(sc['checked_at'])[:19]}) - {sc.get('explanation') or ''}")])
    pdf.h2("Risk findings")
    for f in sorted(risk.get("findings", []), key=lambda f: -f["impact"]):
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(0, 5, latin(f"[{f['severity'].upper()}] {f['title']}  (impact {f['impact']:+d}, confidence {f['confidence']}%)"))
        pdf.para(f"Evidence: {f['evidence']}", 8.5)
        pdf.para(f"Recommendation: {f['recommendation']}", 8.5, MUTED)
        pdf.ln(1)
    if da.get("suspicious_indicators") or da.get("threat_matches"):
        pdf.h2("Domain intelligence")
        for i in da.get("suspicious_indicators") or []:
            pdf.bullet(f"{i.get('title')}: {i.get('evidence')}", STATE_COLOR["warn"])
        for m in da.get("threat_matches") or []:
            pdf.bullet(f"TI match {m['indicator_type']} {m['value']} ({m['source']}, {m['severity']}, "
                       f"confidence {m['confidence']}%) via {m['matched_via']}", STATE_COLOR["fail"])
    pdf.h2("Scope and privacy")
    pdf.para(DISCLAIMER, 8.5)
    pdf.para("Sentrix does not probe mailboxes (no SMTP RCPT checks). Verification tokens are never stored or shown; "
             "only keyed hashes are kept.", 8.5, MUTED)
    return bytes(pdf.output())


def summary_pdf(tenant: Tenant, user: User, stats: dict, records: list[EmailVerificationRecord]) -> bytes:
    pdf = SentrixPDF("Email Identity Intelligence Summary", tenant.name)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.h1("Email Identity Intelligence - Summary")
    pdf.para(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {user.name}.", 8.5, MUTED)
    pdf.h2("Totals")
    pdf.kv([(k.replace("_", " ").title(), str(v)) for k, v in stats.items() if not isinstance(v, dict)])
    pdf.h2("Records (highest risk first)")
    pdf.set_font("Helvetica", "B", 8)
    widths = [62, 14, 18, 18, 18, 22, 26]
    for w, h in zip(widths, ["Email", "Risk", "MX", "SPF", "DMARC", "Ownership", "Checked"]):
        pdf.cell(w, 6, h, border="B")
    pdf.ln()
    pdf.set_font("Helvetica", "", 7.5)
    for r in sorted(records, key=lambda r: -(r.risk_score or 0))[:120]:
        vals = [r.email[:44], f"{r.risk_score}", r.mx_status, r.spf_status, r.dmarc_status, r.ownership_status,
                (r.last_checked_at.strftime("%Y-%m-%d") if r.last_checked_at else "-")]
        for w, v in zip(widths, vals):
            pdf.cell(w, 5, latin(v)[:40])
        pdf.ln()
    pdf.h2("Scope")
    pdf.para(DISCLAIMER, 8.5)
    return bytes(pdf.output())


def store_report(db: Session, *, tenant: Tenant, user: User, kind: str, title: str, data: bytes,
                 ref_type: str | None = None, ref_id: str | None = None, params: dict | None = None) -> Report:
    s = get_settings()
    folder = Path(s.REPORTS_DIR) / tenant.id
    folder.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256(data).hexdigest()
    path = folder / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{kind}-{sha[:8]}.pdf"
    path.write_bytes(data)
    rep = Report(tenant_id=tenant.id, kind=kind, format="pdf", title=title[:300], path=str(path), sha256=sha,
                 size_bytes=len(data), ref_type=ref_type, ref_id=ref_id, generated_by=user.id, params=params or {})
    db.add(rep)
    db.flush()
    return rep
