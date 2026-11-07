"""Idempotent demo seed: demo organisation, users, knowledge base and *demo-labelled* threat
intelligence. Demo indicators use reserved ``.example`` names so they never flag real domains."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .core.security import hash_password
from .models import Tenant, ThreatIndicator, User
from .services.knowledge.rag import seed_tenant_knowledge

DEMO_USERS = [
    ("admin@sentrix.local", "Avery Admin", "Admin1234!", "admin"),
    ("analyst@sentrix.local", "Riley Analyst", "Demo1234!", "analyst"),
    ("viewer@sentrix.local", "Morgan Viewer", "Viewer1234!", "viewer"),
]
DEMO_TI = [
    ("domain", "login-verify-account.example", "high", 85, "Demo indicator: credential-phishing kit hosting domain."),
    ("domain", "invoice-payments-portal.example", "medium", 70, "Demo indicator: business-email-compromise lure domain."),
    ("email", "billing@invoice-payments-portal.example", "high", 80, "Demo indicator: sender seen in BEC campaign."),
]


def seed_demo(db: Session) -> Tenant:
    t = db.scalar(select(Tenant).where(Tenant.slug == "sentrix-demo"))
    if not t:
        t = Tenant(name="Sentrix Demo SOC", slug="sentrix-demo")
        db.add(t)
        db.flush()
    for email, name, pw, role in DEMO_USERS:
        if not db.scalar(select(User.id).where(User.email == email)):
            db.add(User(tenant_id=t.id, email=email, name=name, password_hash=hash_password(pw), role=role))
    for typ, value, sev, conf, desc in DEMO_TI:
        if not db.scalar(select(ThreatIndicator.id).where(ThreatIndicator.tenant_id == t.id,
                                                          ThreatIndicator.indicator_type == typ,
                                                          ThreatIndicator.value == value)):
            db.add(ThreatIndicator(tenant_id=t.id, indicator_type=typ, value=value, source="demo", severity=sev,
                                   confidence=conf, description=desc))
    db.flush()
    seed_tenant_knowledge(db, t.id)
    db.commit()
    return t
