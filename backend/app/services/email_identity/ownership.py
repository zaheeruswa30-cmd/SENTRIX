"""Email ownership verification workflow.

1. ``start``   – generate a 256-bit link token + 6-digit code with ``secrets``; persist only their
                 HMAC-SHA256 digests; e-mail both to the address; status → pending.
2. ``verify_code`` / ``confirm_link`` – constant-time digest comparison, expiry check, attempt
                 counting (lock after OWNERSHIP_MAX_ATTEMPTS), single use.
3. Every step writes the verification audit trail. Secrets are never returned by the API, written
   to the database, or logged.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...core.security import (
    constant_time_equals, generate_link_token, generate_numeric_code, hash_secret,
)
from ...db.base import as_aware, utcnow
from ...models import EmailVerificationRecord, OwnershipVerificationToken, Tenant, User
from ..audit import verification_audit
from ..errors import ServiceError
from ..notifications import mailer


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _expire_stale(db: Session, record: EmailVerificationRecord) -> None:
    for t in record.tokens:
        if t.status == "active" and as_aware(t.expires_at) <= _now():
            t.status = "expired"
    if record.ownership_status == "pending" and not any(t.status == "active" for t in record.tokens):
        record.ownership_status = "expired"


def status_view(db: Session, record: EmailVerificationRecord) -> dict:
    """Public, secret-free view of the ownership state for the UI."""
    s = get_settings()
    _expire_stale(db, record)
    active = next((t for t in sorted(record.tokens, key=lambda t: t.created_at, reverse=True)
                   if t.status == "active"), None)
    day_ago = _now() - timedelta(days=1)
    sends_24h = sum(1 for t in record.tokens if as_aware(t.created_at) >= day_ago)
    last = max((as_aware(t.created_at) for t in record.tokens), default=None)
    cooldown = 0
    if last:
        cooldown = max(0, int(s.OWNERSHIP_RESEND_COOLDOWN_SECONDS - (_now() - last).total_seconds()))
    return {
        "status": record.ownership_status,
        "verified_at": record.ownership_verified_at,
        "method": record.ownership_method,
        "active_challenge": None if not active else {
            "id": active.id, "expires_at": as_aware(active.expires_at),
            "attempts_used": active.attempts, "attempts_remaining": max(0, active.max_attempts - active.attempts),
            "delivery_status": active.delivery_status, "delivery_provider": active.delivery_provider,
        },
        "sends_last_24h": sends_24h,
        "sends_remaining_24h": max(0, s.OWNERSHIP_MAX_SENDS_PER_DAY - sends_24h),
        "resend_available_in_seconds": cooldown,
        "meaning": "Verified ownership proves the submitter could read mail delivered to this address. "
                   "It does not verify the person's real-world identity.",
    }


def start(db: Session, *, record: EmailVerificationRecord, actor: User, tenant: Tenant, consent: bool,
          ip: str | None, user_agent: str | None, resend: bool = False) -> dict:
    s = get_settings()
    action = "ownership.resend" if resend else "ownership.start"
    if not consent:
        raise ServiceError(400, "Confirm that you are authorised to send a verification message to this address.")
    if record.syntax_status != "valid" or record.mx_status not in ("present", "implicit"):
        verification_audit(db, tenant_id=tenant.id, record_id=record.id, actor_id=actor.id, action=action,
                           outcome="rejected", detail={"reason": "undeliverable"}, ip=ip, user_agent=user_agent)
        db.commit()
        raise ServiceError(409, "This address is not technically deliverable (syntax/DNS/MX), so a verification "
                                "message cannot be sent. Resolve the validity issues first.")
    if record.ownership_status == "verified" and not resend:
        raise ServiceError(409, "Ownership is already verified for this address.")
    view = status_view(db, record)
    if view["sends_remaining_24h"] <= 0:
        verification_audit(db, tenant_id=tenant.id, record_id=record.id, actor_id=actor.id, action=action,
                           outcome="rate_limited", detail={"limit": s.OWNERSHIP_MAX_SENDS_PER_DAY}, ip=ip,
                           user_agent=user_agent)
        db.commit()
        raise ServiceError(429, f"Send limit reached ({s.OWNERSHIP_MAX_SENDS_PER_DAY} per 24 hours). Try again later.")
    if view["resend_available_in_seconds"] > 0:
        raise ServiceError(429, f"Please wait {view['resend_available_in_seconds']} s before requesting another message.")

    for t in record.tokens:  # only one live challenge at a time
        if t.status == "active":
            t.status = "revoked"
    link_token, code = generate_link_token(), generate_numeric_code(6)
    tok = OwnershipVerificationToken(
        tenant_id=tenant.id, email_record_id=record.id,
        link_token_hash=hash_secret(link_token, "ownership-link"),
        code_hash=hash_secret(f"{record.id}:{code}", "ownership-code"),
        status="active", attempts=0, max_attempts=s.OWNERSHIP_MAX_ATTEMPTS,
        expires_at=_now() + timedelta(minutes=s.OWNERSHIP_TOKEN_TTL_MINUTES),
        delivery_provider=s.EMAIL_PROVIDER, requested_by=actor.id, requester_ip=ip,
    )
    record.tokens.append(tok)
    db.flush()
    # The link carries the token in the URL *fragment*, which browsers never send to servers,
    # so it cannot appear in access logs; the SPA posts it in a request body.
    link = f"{s.PUBLIC_BASE_URL.rstrip('/')}/#/verify-email?token={link_token}"
    result = mailer.send(
        record.email, f"{s.APP_NAME}: confirm your email address", "ownership_verification",
        {"email": record.email, "code": code, "link": link, "ttl": str(s.OWNERSHIP_TOKEN_TTL_MINUTES),
         "max_attempts": str(s.OWNERSHIP_MAX_ATTEMPTS), "organisation": tenant.name,
         "purpose": record.purpose or "account verification"},
    )
    del link_token, code, link  # secrets leave scope; never persisted or returned
    tok.delivery_status, tok.delivery_message_id, tok.delivery_error = result.status, result.message_id, result.error
    if result.status != "sent":
        tok.status = "revoked"
        verification_audit(db, tenant_id=tenant.id, record_id=record.id, actor_id=actor.id, action=action,
                           outcome="delivery_failed", detail={"provider": result.provider, "error": result.error},
                           ip=ip, user_agent=user_agent)
        db.commit()
        raise ServiceError(502, f"The verification email could not be sent: {result.error}. Check the email "
                                "provider configuration (EMAIL_PROVIDER and related settings).")
    record.ownership_status = "pending"
    verification_audit(db, tenant_id=tenant.id, record_id=record.id, actor_id=actor.id, action=action,
                       detail={"provider": result.provider, "challenge_id": tok.id,
                               "expires_at": tok.expires_at.isoformat()}, ip=ip, user_agent=user_agent)
    db.commit()
    db.refresh(record)
    return status_view(db, record)


def _mark_verified(db: Session, record: EmailVerificationRecord, tok: OwnershipVerificationToken, method: str) -> None:
    tok.status, tok.consumed_at = "consumed", utcnow()
    record.ownership_status, record.ownership_verified_at, record.ownership_method = "verified", utcnow(), method
    for t in record.tokens:
        if t.status == "active" and t.id != tok.id:
            t.status = "revoked"
    db.flush()
    from .service import recompute_risk  # ownership changes the explainable risk picture
    recompute_risk(db, record)


def verify_code(db: Session, *, record: EmailVerificationRecord, actor: User, code: str,
                ip: str | None, user_agent: str | None) -> dict:
    _expire_stale(db, record)
    tok = next((t for t in record.tokens if t.status == "active"), None)
    if not tok:
        verification_audit(db, tenant_id=record.tenant_id, record_id=record.id, actor_id=actor.id,
                           action="ownership.verify", outcome="no_active_challenge", ip=ip, user_agent=user_agent)
        db.commit()
        raise ServiceError(409, "There is no active verification challenge (it may have expired). Send a new code.")
    code = (code or "").strip()
    tok.attempts += 1
    ok = code.isdigit() and len(code) == 6 and constant_time_equals(
        hash_secret(f"{record.id}:{code}", "ownership-code"), tok.code_hash)
    if ok:
        _mark_verified(db, record, tok, "code")
        verification_audit(db, tenant_id=record.tenant_id, record_id=record.id, actor_id=actor.id,
                           action="ownership.verify", detail={"method": "code", "attempt": tok.attempts},
                           ip=ip, user_agent=user_agent)
    else:
        remaining = tok.max_attempts - tok.attempts
        if remaining <= 0:
            tok.status = "locked"
            record.ownership_status = "locked"
            db.flush()
            from .service import recompute_risk
            recompute_risk(db, record)
        verification_audit(db, tenant_id=record.tenant_id, record_id=record.id, actor_id=actor.id,
                           action="ownership.verify", outcome="locked" if remaining <= 0 else "mismatch",
                           detail={"method": "code", "attempt": tok.attempts, "remaining": max(0, remaining)},
                           ip=ip, user_agent=user_agent)
        db.commit()
        if remaining <= 0:
            raise ServiceError(423, "Too many incorrect codes. The challenge is locked — request a new code.")
        raise ServiceError(400, f"Incorrect code. {remaining} attempt(s) remaining.")
    db.commit()
    db.refresh(record)
    return status_view(db, record)


def confirm_link(db: Session, *, token: str, ip: str | None, user_agent: str | None) -> dict:
    """Unauthenticated: called by the recipient who clicked the e-mailed link."""
    if not token or len(token) > 200:
        raise ServiceError(400, "Invalid verification link.")
    digest = hash_secret(token, "ownership-link")
    tok = db.scalar(select(OwnershipVerificationToken).where(OwnershipVerificationToken.link_token_hash == digest))
    if not tok:
        raise ServiceError(400, "This verification link is invalid or has already been replaced by a newer one.")
    record = tok.email_record
    if tok.status != "active":
        verification_audit(db, tenant_id=tok.tenant_id, record_id=record.id, actor_id=None, actor_type="recipient",
                           action="ownership.link", outcome=f"token_{tok.status}", ip=ip, user_agent=user_agent)
        db.commit()
        msg = {"consumed": "This link has already been used.", "locked": "This challenge was locked after too many attempts.",
               "revoked": "This link was replaced by a newer message.", "expired": "This link has expired."}
        raise ServiceError(410, msg.get(tok.status, "This link is no longer valid."))
    if as_aware(tok.expires_at) <= _now():
        tok.status = "expired"
        if record.ownership_status == "pending":
            record.ownership_status = "expired"
        verification_audit(db, tenant_id=tok.tenant_id, record_id=record.id, actor_id=None, actor_type="recipient",
                           action="ownership.link", outcome="expired", ip=ip, user_agent=user_agent)
        db.commit()
        raise ServiceError(410, "This link has expired. Ask for a new verification message.")
    tok.attempts += 1
    _mark_verified(db, record, tok, "link")
    verification_audit(db, tenant_id=tok.tenant_id, record_id=record.id, actor_id=None, actor_type="recipient",
                       action="ownership.link", detail={"method": "link"}, ip=ip, user_agent=user_agent)
    db.commit()
    local, _, dom = record.email.partition("@")
    return {"status": "verified", "email_masked": f"{local[:1]}***@{dom}",
            "message": "Thank you — you have confirmed you can receive mail at this address. You can close this page."}


def expire_all(db: Session) -> int:
    """Housekeeping: mark expired challenges (call from a scheduler or at startup)."""
    n = 0
    for t in db.scalars(select(OwnershipVerificationToken).where(
            OwnershipVerificationToken.status == "active", OwnershipVerificationToken.expires_at <= _now())):
        t.status = "expired"
        n += 1
        rec = t.email_record
        if rec.ownership_status == "pending" and not any(x.status == "active" and x.id != t.id for x in rec.tokens):
            rec.ownership_status = "expired"
    db.commit()
    return n


def count_recent_sends(db: Session, tenant_id: str) -> int:
    return db.scalar(select(func.count(OwnershipVerificationToken.id)).where(
        OwnershipVerificationToken.tenant_id == tenant_id,
        OwnershipVerificationToken.created_at >= _now() - timedelta(days=1))) or 0
