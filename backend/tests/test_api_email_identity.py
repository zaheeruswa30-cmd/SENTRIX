"""End-to-end API tests for Email Identity Intelligence."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from backend.app.db.session import SessionLocal
from backend.app.models import AuditLog, EmailVerificationRecord, OwnershipVerificationToken, VerificationAuditLog

from .conftest import latest_message_secrets, login

API = "/api/v1/email-identity"


def _check(client, h, email, purpose="unit test"):
    r = client.post(f"{API}/records", json={"email": email, "purpose": purpose}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_healthz_and_frontend(client):
    assert client.get("/api/healthz").json()["service"] == "Sentrix"
    r = client.get("/")
    assert r.status_code == 200 and "Sentrix" in r.text


def test_requires_auth(client):
    assert client.get(f"{API}/records").status_code == 401


def test_legacy_demo_login_alias(client):
    login(client, "analyst@securewatch.local", "Demo1234!")


def test_full_check_well_configured(client, analyst):
    d = _check(client, analyst, "Jane@ACME.example")
    assert d["email"] == "jane@acme.example"
    assert (d["syntax_status"], d["dns_status"], d["mx_status"]) == ("valid", "resolves", "present")
    assert d["spf_status"] == "valid" and d["dmarc_status"] == "enforced" and d["dkim_status"] == "selector_found"
    assert d["ownership_status"] == "unverified" and d["risk_band"] == "low"
    keys = [l["key"] for l in d["layers"]]
    assert keys == ["syntax", "domain", "mail_infrastructure", "authentication", "ownership", "real_world_identity"]
    assert d["layers"][-1]["state"] == "not_assessed"
    assert "not" in d["risk"]["disclaimer"].lower()


def test_invalid_and_suspicious_filters(client, analyst):
    _check(client, analyst, "ghost@does-not-exist.example")
    _check(client, analyst, "not-an-email")
    _check(client, analyst, "temp@mailinator.com")
    inv = client.get(f"{API}/records", params={"filter": "invalid"}, headers=analyst).json()
    emails = {i["email"] for i in inv["items"]}
    assert "ghost@does-not-exist.example" in emails and "not-an-email" in emails
    for f in ("verified", "unverified", "invalid", "suspicious", "pending"):
        assert client.get(f"{API}/records", params={"filter": f}, headers=analyst).status_code == 200
    assert client.get(f"{API}/records", params={"filter": "bogus"}, headers=analyst).status_code == 422


def test_viewer_is_read_only(client, viewer):
    r = client.post(f"{API}/records", json={"email": "a@acme.example", "purpose": "x-test"}, headers=viewer)
    assert r.status_code == 403
    assert client.get(f"{API}/records", headers=viewer).status_code == 200


def test_threat_intel_match_and_incident(client, analyst):
    r = client.post("/api/v1/threat-intel/indicators", headers=analyst, json={
        "indicator_type": "domain", "value": "paypa1-secure.example", "severity": "high", "confidence": 90,
        "description": "Phishing kit observed"})
    assert r.status_code in (201, 409)
    d = _check(client, analyst, "support@paypa1-secure.example")
    assert d["risk_band"] == "high" and "suspicious" in d["classifications"]
    codes = {f["code"] for f in d["risk"]["findings"]}
    assert "threat_intel_match" in codes and "brand_homoglyph" in codes
    inc = client.post(f"{API}/records/{d['id']}/incident", json={"kind": "investigation"}, headers=analyst)
    assert inc.status_code == 201 and inc.json()["incident_key"].startswith("INV-")
    again = client.post(f"{API}/records/{d['id']}/incident", json={"kind": "incident"}, headers=analyst)
    assert again.status_code == 409
    incs = client.get("/api/v1/incidents", params={"source": "email_identity"}, headers=analyst).json()["items"]
    assert any(i["source_ref"] == d["id"] for i in incs)


def test_ownership_flow_hash_only_and_code(client, analyst):
    d = _check(client, analyst, "owner@acme.example")
    rid = d["id"]
    r = client.post(f"{API}/records/{rid}/ownership/start", json={"consent": False}, headers=analyst)
    assert r.status_code == 400
    r = client.post(f"{API}/records/{rid}/ownership/start", json={"consent": True}, headers=analyst)
    assert r.status_code == 200 and r.json()["status"] == "pending"
    code, token = latest_message_secrets("owner@acme.example")
    assert code not in r.text and token not in r.text  # never exposed by the API
    with SessionLocal() as db:
        tok = db.scalar(select(OwnershipVerificationToken).where(OwnershipVerificationToken.email_record_id == rid))
        assert tok.link_token_hash != token and len(tok.link_token_hash) == 64 and code not in tok.code_hash
        audit_text = " ".join(str(a.detail) for a in db.scalars(select(AuditLog)))
        assert token not in audit_text and code not in audit_text
    # immediate resend is rate limited (cooldown)
    assert client.post(f"{API}/records/{rid}/ownership/resend", json={"consent": True}, headers=analyst).status_code == 429
    bad = client.post(f"{API}/records/{rid}/ownership/verify", json={"code": "000000" if code != "000000" else "111111"},
                      headers=analyst)
    assert bad.status_code == 400 and "remaining" in bad.json()["detail"]
    ok = client.post(f"{API}/records/{rid}/ownership/verify", json={"code": code}, headers=analyst)
    assert ok.status_code == 200 and ok.json()["status"] == "verified"
    rec = client.get(f"{API}/records/{rid}", headers=analyst).json()
    assert rec["ownership_status"] == "verified" and rec["ownership_verified_at"]
    assert rec["layers"][4]["state"] == "pass" and rec["layers"][5]["state"] == "not_assessed"
    # used link can't be replayed
    assert client.post(f"{API}/ownership/confirm", json={"token": token}).status_code == 410
    actions = [a["action"] for a in client.get(f"{API}/records/{rid}/audit", headers=analyst).json()["items"]]
    assert "ownership.start" in actions and "ownership.verify" in actions


def test_ownership_link_confirmation_public(client, analyst):
    d = _check(client, analyst, "linkuser@acme.example")
    client.post(f"{API}/records/{d['id']}/ownership/start", json={"consent": True}, headers=analyst)
    _, token = latest_message_secrets("linkuser@acme.example")
    r = client.post(f"{API}/ownership/confirm", json={"token": token})
    assert r.status_code == 200 and r.json()["status"] == "verified"
    assert "linkuser" not in r.json()["email_masked"]
    assert client.post(f"{API}/ownership/confirm", json={"token": "x" * 43}).status_code == 400


def test_ownership_lockout_and_expiry(client, analyst):
    d = _check(client, analyst, "lock@acme.example")
    rid = d["id"]
    client.post(f"{API}/records/{rid}/ownership/start", json={"consent": True}, headers=analyst)
    code, _ = latest_message_secrets("lock@acme.example")
    wrong = "123456" if code != "123456" else "654321"
    codes = [client.post(f"{API}/records/{rid}/ownership/verify", json={"code": wrong}, headers=analyst).status_code
             for _ in range(5)]
    assert codes[-1] == 423
    assert client.get(f"{API}/records/{rid}", headers=analyst).json()["ownership_status"] == "locked"
    # correct code after lock is rejected
    assert client.post(f"{API}/records/{rid}/ownership/verify", json={"code": code}, headers=analyst).status_code == 409

    d2 = _check(client, analyst, "expire@acme.example")
    client.post(f"{API}/records/{d2['id']}/ownership/start", json={"consent": True}, headers=analyst)
    code2, token2 = latest_message_secrets("expire@acme.example")
    with SessionLocal() as db:
        tok = db.scalar(select(OwnershipVerificationToken).where(OwnershipVerificationToken.email_record_id == d2["id"]))
        tok.expires_at = tok.expires_at - timedelta(hours=1)
        db.commit()
    assert client.post(f"{API}/ownership/confirm", json={"token": token2}).status_code == 410
    assert client.get(f"{API}/records/{d2['id']}", headers=analyst).json()["ownership_status"] == "expired"


def test_undeliverable_address_cannot_start_ownership(client, analyst):
    d = _check(client, analyst, "nobody@nullmx.example")
    assert d["mx_status"] == "null_mx"
    r = client.post(f"{API}/records/{d['id']}/ownership/start", json={"consent": True}, headers=analyst)
    assert r.status_code == 409


def test_tenant_isolation(client, analyst):
    d = _check(client, analyst, "isolated@acme.example")
    r = client.post("/api/v1/auth/register", json={"name": "Other", "email": "owner@other-org.example",
                                                   "password": "Sup3r-secret-pass", "organisation": "Other Org"})
    assert r.status_code == 201, r.text
    other = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get(f"{API}/records/{d['id']}", headers=other).status_code == 404
    assert client.get(f"{API}/records", headers=other).json()["total"] == 0
    client.post(f"{API}/records/{d['id']}/knowledge", headers=analyst)
    hits = client.get("/api/v1/knowledge/search", params={"q": "isolated acme investigation"}, headers=other).json()["hits"]
    assert all("isolated@acme.example" not in h["text"] for h in hits)
    ans = client.post("/api/v1/ai/email/ask", json={"question": "Is isolated@acme.example verified?",
                                                    "run_if_missing": False}, headers=other).json()
    assert ans["record"] is None


def test_ai_assistant_distinguishes_layers_and_refuses_identity_claims(client, analyst):
    _check(client, analyst, "ceo@weak.example")
    q = "Is ceo@weak.example a real person and which authentication records are missing? What steps should be taken?"
    r = client.post("/api/v1/ai/email/ask", json={"question": q}, headers=analyst)
    assert r.status_code == 200
    a = r.json()
    assert {"identity", "missing_auth", "steps"} <= set(a["intents"])
    assert "cannot tell you whether a person is authentic" in a["summary"]
    titles = [s["title"] for s in a["sections"]]
    assert "What email checks can and cannot prove" in titles and "Knowledge base" in titles
    assert all(s["citations"] for s in a["sections"])
    import re
    assert not re.search(r"\b(is|are)\s+(a\s+)?(fraud\w*|real person|genuine person)\b", a["summary"], re.I)


def test_dkim_message_upload_and_pdf_and_history(client, analyst):
    d = _check(client, analyst, "sender@acme.example")
    raw = "From: sender@acme.example\r\nTo: x@acme.example\r\nSubject: hi\r\n\r\nbody\r\n"
    r = client.post(f"{API}/dkim/verify", data={"raw": raw, "record_id": d["id"]}, headers=analyst)
    assert r.status_code == 200 and r.json()["status"] == "no_signature"
    pdf = client.get(f"{API}/records/{d['id']}/report.pdf", headers=analyst)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    reports = client.get("/api/v1/reports", headers=analyst).json()["items"]
    assert reports and client.get(f"/api/v1/reports/{reports[0]['id']}/download", headers=analyst).status_code == 200
    hist = client.get(f"{API}/history", headers=analyst).json()
    assert any(x["record_id"] == d["id"] for x in hist["reports"])
    assert client.get(f"{API}/report/summary.pdf", headers=analyst).content[:4] == b"%PDF"
    with SessionLocal() as db:
        assert db.scalar(select(VerificationAuditLog).where(VerificationAuditLog.action == "dkim.verify_message"))
        rec = db.get(EmailVerificationRecord, d["id"])
        assert rec.risk_assessments


def test_domain_endpoints(client, analyst):
    _check(client, analyst, "a@weak.example")
    doms = client.get(f"{API}/domains", headers=analyst).json()["items"]
    weak = next(x for x in doms if x["domain"] == "weak.example")
    assert weak["spf_status"] == "multiple" and weak["dmarc_status"] == "monitoring"
    det = client.get(f"{API}/domains/weak.example", headers=analyst).json()
    assert det["addresses"] and det["spf"]["issues"]
    r = client.post(f"{API}/domains/analyze", json={"domain": "acme.example"}, headers=analyst)
    assert r.status_code == 200 and r.json()["dmarc"]["status"] == "enforced"
    assert client.get(f"{API}/auth-results", params={"mechanism": "spf"}, headers=analyst).status_code == 200
    st = client.get(f"{API}/stats", headers=analyst).json()
    assert st["total"] >= 1 and "status_breakdown" in st
