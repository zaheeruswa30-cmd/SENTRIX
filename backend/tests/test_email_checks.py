"""Unit tests: syntax, mail infrastructure, SPF/DKIM/DMARC parsing, risk engine wording."""
from __future__ import annotations

import re

from backend.app.services.email_identity import auth_records, mail_infra
from backend.app.services.email_identity.dns_client import StaticDnsClient
from backend.app.services.email_identity.reputation import check_disposable
from backend.app.services.email_identity.risk_engine import assess
from backend.app.services.email_identity.syntax import validate_email_syntax
from backend.app.services.email_identity.suspicious import find_indicators

from .conftest import ZONE

DNS = StaticDnsClient(ZONE)


def test_syntax_valid_and_normalised():
    r = validate_email_syntax("  Jane.Doe+news@ACME.Example ")
    assert r.valid and r.normalized == "jane.doe+news@acme.example"
    assert r.ascii_domain == "acme.example"


def test_syntax_invalid_cases():
    for bad in ["", "plainaddress", "a@@b.com", "a@b", "a..b@acme.example", ".a@acme.example", "a@-acme.example",
                "a" * 65 + "@acme.example"]:
        assert not validate_email_syntax(bad).valid, bad


def test_idn_and_role_account():
    r = validate_email_syntax("info@bücher.example")
    assert r.valid and r.is_idn and r.ascii_domain.startswith("xn--")
    assert r.is_role_account


def test_mail_infrastructure_states():
    assert mail_infra.analyze_mail_infrastructure(DNS, "acme.example").mx_status == "present"
    assert mail_infra.analyze_mail_infrastructure(DNS, "nomail.example").mx_status == "implicit"
    assert mail_infra.analyze_mail_infrastructure(DNS, "nullmx.example").mx_status == "null_mx"
    nx = mail_infra.analyze_mail_infrastructure(DNS, "does-not-exist.example")
    assert nx.dns_status == "nxdomain" and nx.mx_status == "absent"
    assert mail_infra.analyze_mail_infrastructure(DNS, "broken.example").dns_status == "error"


def test_spf_parsing():
    assert auth_records.check_spf(DNS, "acme.example").status == "valid"
    assert auth_records.check_spf(DNS, "weak.example").status == "multiple"
    assert auth_records.check_spf(DNS, "nomail.example").status == "missing"
    plus_all = StaticDnsClient({("x.example", "TXT"): ["v=spf1 +all"], ("x.example", "A"): ["192.0.2.1"]})
    assert auth_records.check_spf(plus_all, "x.example").status == "permissive"


def test_spf_lookup_limit():
    zone = {("loop.example", "TXT"): ["v=spf1 " + " ".join(f"include:i{i}.example" for i in range(11)) + " -all"]}
    zone |= {(f"i{i}.example", "TXT"): ["v=spf1 ip4:192.0.2.1 -all"] for i in range(11)}
    r = auth_records.check_spf(StaticDnsClient(zone), "loop.example")
    assert r.status == "invalid"
    assert any("10" in (i["message"] if isinstance(i, dict) else i) for i in r.issues)


def test_dmarc_policies_and_org_fallback():
    assert auth_records.check_dmarc(DNS, "acme.example").status == "enforced"
    assert auth_records.check_dmarc(DNS, "weak.example").status == "monitoring"
    assert auth_records.check_dmarc(DNS, "nomail.example").status == "missing"
    sub = auth_records.check_dmarc(DNS, "mail.acme.example")
    assert sub.status == "enforced"  # inherited from organisational domain


def test_dkim_discovery_is_not_verification():
    summary, found = auth_records.check_dkim(DNS, "acme.example", ["selector1", "google"])
    assert summary.status == "selector_found" and found[0].selector == "selector1"
    assert "configuration evidence only" in summary.explanation.lower()
    none, _ = auth_records.check_dkim(DNS, "weak.example", ["selector1"])
    assert none.status == "not_found"


def test_disposable_and_lookalike():
    assert check_disposable("mailinator.com")[0]
    assert not check_disposable("acme.example")[0]
    codes = {i["code"] for i in find_indicators("paypa1-secure.example", ["paypal.com"], None)}
    assert codes & {"brand_homoglyph", "brand_typosquat", "brand_embedded"}


FORBIDDEN = re.compile(r"\b(fraud\w*|scam\w*|criminal|untrustworthy|liar)\b", re.I)


def _ev(**kw):
    base = {"syntax": {"valid": True}, "infra": {"domain": "x.example", "dns_status": "resolves", "mx_status": "present",
                                                 "mx_records": [{"host": "mx.x.example", "addresses": ["192.0.2.1"]}]},
            "spf": {"status": "missing"}, "dmarc": {"status": "missing"}, "dkim": {"status": "not_found"},
            "disposable": False, "free_provider": False, "role_account": False, "suspicious": [],
            "threat_matches": [], "ownership_status": "unverified"}
    return base | kw


def test_risk_engine_never_judges_people():
    for ev in [_ev(), _ev(disposable=True), _ev(syntax={"valid": False, "errors": ["bad"]}),
               _ev(threat_matches=[{"indicator_id": "1", "indicator_type": "domain", "value": "x.example",
                                    "source": "analyst", "severity": "critical", "confidence": 95}])]:
        a = assess(ev)
        text = " ".join([a.summary] + [f["title"] + " " + f["evidence"] + " " + f["recommendation"] for f in a.findings])
        assert not FORBIDDEN.search(text), text
        for f in a.findings:
            assert f["evidence"] and 0 <= f["confidence"] <= 100


def test_technical_failures_alone_cannot_reach_high():
    a = assess(_ev(infra={"domain": "x.example", "dns_status": "resolves", "mx_status": "absent", "mx_records": []},
                   disposable=True))
    assert a.band != "high" and a.score <= 69


def test_threat_intel_corroboration_can_reach_high():
    a = assess(_ev(disposable=True, suspicious=[{"code": "brand_lookalike", "title": "Lookalike", "evidence": "e",
                                                 "weight": 25, "confidence": 80}],
                   threat_matches=[{"indicator_id": "1", "indicator_type": "domain", "value": "x.example",
                                    "source": "analyst", "severity": "high", "confidence": 90}]))
    assert a.band == "high" and a.is_suspicious
