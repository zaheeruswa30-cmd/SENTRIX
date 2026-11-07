"""Test configuration: isolated SQLite DB, dev outbox and a deterministic DNS zone (no network)."""
from __future__ import annotations

import email
import email.policy
import os
import re
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="sentrix-tests-"))
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_TMP / 'test.db'}",
    "DEV_OUTBOX_DIR": str(_TMP / "outbox"),
    "REPORTS_DIR": str(_TMP / "reports"),
    "EMAIL_PROVIDER": "dev_outbox",
    "ENVIRONMENT": "test",
    "SEED_DEMO_DATA": "true",
    "AUTO_CREATE_SCHEMA": "true",
    "ENRICHMENT_RDAP_ENABLED": "false",
    "ENRICHMENT_DNSBL_ENABLED": "false",
    "LLM_PROVIDER": "none",
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
    "PROTECTED_BRAND_DOMAINS": "paypal.com,microsoft.com,sentrix.example",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app.api.deps import limiter  # noqa: E402
from backend.app.services.email_identity import service as svc  # noqa: E402
from backend.app.services.email_identity.dns_client import StaticDnsClient  # noqa: E402

ZONE: dict = {
    # well-configured organisation
    ("acme.example", "A"): ["192.0.2.10"],
    ("acme.example", "MX"): ["10 mx1.acme.example.", "20 mx2.acme.example."],
    ("mx1.acme.example", "A"): ["192.0.2.25"],
    ("mx2.acme.example", "A"): ["192.0.2.26"],
    ("acme.example", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:_spf.mailhost.example -all"],
    ("_spf.mailhost.example", "TXT"): ["v=spf1 ip4:198.51.100.0/24 ~all"],
    ("_dmarc.acme.example", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.example; adkim=s"],
    ("selector1._domainkey.acme.example", "TXT"): [
        "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB"],
    # domain exists but publishes no mail records
    ("nomail.example", "A"): ["192.0.2.50"],
    # null MX
    ("nullmx.example", "MX"): ["0 ."],
    ("nullmx.example", "A"): ["192.0.2.60"],
    # weak authentication
    ("weak.example", "A"): ["192.0.2.70"],
    ("weak.example", "MX"): ["10 mail.weak.example."],
    ("mail.weak.example", "A"): ["192.0.2.71"],
    ("weak.example", "TXT"): ["v=spf1 +all", "v=spf1 -all"],
    ("_dmarc.weak.example", "TXT"): ["v=DMARC1; p=none"],
    # lookalike of protected brand, seeded as TI indicator in tests
    ("paypa1-secure.example", "A"): ["203.0.113.5"],
    ("paypa1-secure.example", "MX"): ["10 mx.paypa1-secure.example."],
    ("mx.paypa1-secure.example", "A"): ["203.0.113.6"],
    # disposable provider
    ("mailinator.com", "A"): ["198.51.100.20"],
    ("mailinator.com", "MX"): ["10 mail.mailinator.com."],
    ("mail.mailinator.com", "A"): ["198.51.100.21"],
    ("broken.example", "A"): "ERROR",
    ("broken.example", "MX"): "ERROR",
}


@pytest.fixture(autouse=True)
def static_dns(monkeypatch):
    monkeypatch.setattr(svc, "DNS_FACTORY", lambda: StaticDnsClient(ZONE))
    limiter.reset()
    yield


@pytest.fixture(scope="session")
def client():
    from backend.app.main import app
    with TestClient(app) as c:
        yield c


def login(client, email="analyst@sentrix.local", password="Demo1234!") -> dict:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def analyst(client):
    return login(client)


@pytest.fixture
def viewer(client):
    return login(client, "viewer@sentrix.local", "Viewer1234!")


def outbox_dir() -> Path:
    return Path(os.environ["DEV_OUTBOX_DIR"])


def latest_message_secrets(to: str) -> tuple[str, str]:
    """Parse the newest dev-outbox message for ``to`` and return (code, link_token)."""
    files = sorted(outbox_dir().glob("*.eml"), key=lambda p: p.stat().st_mtime, reverse=True)
    for f in files:
        msg = email.message_from_bytes(f.read_bytes(), policy=email.policy.default)
        if msg["To"] != to:
            continue
        text = msg.get_body(preferencelist=("plain",)).get_content()
        code = re.search(r"(?<!\d)(\d{6})(?!\d)", text).group(1)
        token = re.search(r"token=([A-Za-z0-9_\-]+)", text).group(1)
        return code, token
    raise AssertionError(f"no message for {to}")
