"""Authentication: login, self-service organisation registration, current user."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...core.security import create_access_token, hash_password, verify_password
from ...db.base import utcnow
from ...db.session import get_db
from ...models import Tenant, User
from ...services.audit import audit
from ...services.knowledge.rag import seed_tenant_knowledge
from ..deps import Ctx, client_meta, current, limiter

router = APIRouter(prefix="/auth", tags=["auth"])
LEGACY_DOMAIN = "@securewatch.local"  # pre-rebrand demo accounts keep working


class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=200)


class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    email: str = Field(max_length=320)
    password: str = Field(min_length=8, max_length=200)
    organisation: str = Field(min_length=1, max_length=160)


def user_out(u: User, t: Tenant) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role,
            "tenant": {"id": t.id, "name": t.name, "slug": t.slug}}


def _token(u: User, t: Tenant) -> dict:
    s = get_settings()
    return {"access_token": create_access_token(u.id, t.id, u.role), "token_type": "bearer",
            "expires_in": s.ACCESS_TOKEN_EXPIRE_MINUTES * 60, "user": user_out(u, t)}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip, ua = client_meta(request)
    limiter.hit(f"login:{ip}", 20, 300)
    email = body.email.strip().lower()
    if email.endswith(LEGACY_DOMAIN):
        email = email[: -len(LEGACY_DOMAIN)] + "@sentrix.local"
    u = db.scalar(select(User).where(User.email == email))
    if not u or not u.is_active or not verify_password(body.password, u.password_hash):
        audit(db, tenant_id=u.tenant_id if u else None, actor_id=u.id if u else None, action="auth.login",
              detail={"outcome": "failure"}, ip=ip, user_agent=ua)
        db.commit()
        raise HTTPException(401, "Email or password is incorrect.")
    t = db.get(Tenant, u.tenant_id)
    u.last_login_at = utcnow()
    audit(db, tenant_id=t.id, actor_id=u.id, action="auth.login", detail={"outcome": "success"}, ip=ip, user_agent=ua)
    db.commit()
    return _token(u, t)


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    if not s.ALLOW_SELF_REGISTRATION:
        raise HTTPException(403, "Self-registration is disabled. Ask an administrator for an account.")
    if len(body.password) < s.PASSWORD_MIN_LENGTH:
        raise HTTPException(422, f"Password must be at least {s.PASSWORD_MIN_LENGTH} characters.")
    ip, ua = client_meta(request)
    limiter.hit(f"register:{ip}", 5, 3600)
    email = body.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(422, "Enter a valid email address.")
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "An account with this email already exists.")
    slug_base = re.sub(r"[^a-z0-9]+", "-", body.organisation.lower()).strip("-")[:60] or "org"
    slug, n = slug_base, 1
    while db.scalar(select(Tenant.id).where(Tenant.slug == slug)):
        n += 1
        slug = f"{slug_base}-{n}"
    t = Tenant(name=body.organisation.strip(), slug=slug)
    db.add(t)
    db.flush()
    u = User(tenant_id=t.id, email=email, name=body.name.strip(), password_hash=hash_password(body.password),
             role="admin")
    db.add(u)
    db.flush()
    seed_tenant_knowledge(db, t.id)
    audit(db, tenant_id=t.id, actor_id=u.id, action="auth.register", detail={"organisation": t.name}, ip=ip,
          user_agent=ua)
    db.commit()
    return _token(u, t)


@router.get("/me")
def me(ctx: Ctx = Depends(current)):
    return user_out(ctx.user, ctx.tenant)
