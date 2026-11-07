"""Shared API dependencies: authentication, role checks, client metadata and rate limiting."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.security import decode_access_token
from ..db.session import get_db
from ..models import Tenant, User


@dataclass
class Ctx:
    user: User
    tenant: Tenant
    ip: str | None
    user_agent: str | None


def client_meta(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None), request.headers.get("user-agent")


def current(request: Request, authorization: str | None = Header(default=None),
            db: Session = Depends(get_db)) -> Ctx:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in required.")
    try:
        claims = decode_access_token(authorization.split(" ", 1)[1].strip())
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired or invalid. Sign in again.") from None
    user = db.get(User, claims.get("sub"))
    if not user or not user.is_active or user.tenant_id != claims.get("tid"):
        raise HTTPException(401, "Account not available.")
    tenant = db.get(Tenant, user.tenant_id)
    if not tenant or not tenant.is_active:
        raise HTTPException(403, "Organisation is disabled.")
    ip, ua = client_meta(request)
    return Ctx(user, tenant, ip, ua)


def require(*roles: str):
    def dep(ctx: Ctx = Depends(current)) -> Ctx:
        if ctx.user.role not in roles:
            raise HTTPException(403, f"This action requires one of the roles: {', '.join(roles)}.")
        return ctx
    return dep


analyst = require("admin", "analyst")
admin = require("admin")


class RateLimiter:
    """Simple in-process sliding-window limiter (use Redis for multi-instance deployments)."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                retry = int(window_seconds - (now - q[0])) + 1
                raise HTTPException(429, f"Rate limit reached. Try again in {retry} s.",
                                    headers={"Retry-After": str(retry)})
            q.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
