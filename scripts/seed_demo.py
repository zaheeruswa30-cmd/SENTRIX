"""Seed the Sentrix demo organisation (idempotent).

    python -m scripts.seed_demo                 # users, knowledge base, demo threat intel
    python -m scripts.seed_demo --with-checks   # also run live email checks for a few public examples
"""
from __future__ import annotations

import argparse

from backend.app import models  # noqa: F401
from backend.app.db.base import Base
from backend.app.db.session import SessionLocal, engine
from backend.app.models import User
from backend.app.seed import DEMO_USERS, seed_demo
from sqlalchemy import select

SAMPLE = ["postmaster@gmail.com", "someone@mailinator.com", "billing@invoice-payments-portal.example",
          "not-an-address", "contact@example.com"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-checks", action="store_true", help="run live DNS checks for sample addresses")
    args = ap.parse_args()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        tenant = seed_demo(db)
        print(f"Seeded organisation '{tenant.name}'. Demo logins:")
        for email, _, pw, role in DEMO_USERS:
            print(f"  {role:8s} {email} / {pw}")
        if args.with_checks:
            from backend.app.services.email_identity.service import run_check
            user = db.scalar(select(User).where(User.email == "analyst@sentrix.local"))
            for addr in SAMPLE:
                rec = run_check(db, tenant=tenant, user=user, email=addr, purpose="Demo data seed")
                print(f"  checked {addr:45s} syntax={rec.syntax_status} mx={rec.mx_status} risk={rec.risk_score}")


if __name__ == "__main__":
    main()
