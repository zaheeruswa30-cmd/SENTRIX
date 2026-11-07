"""Sentrix email delivery.

Providers (``EMAIL_PROVIDER``):
  * ``smtp``       — any SMTP relay (credentials from env: SMTP_HOST/PORT/USERNAME/PASSWORD)
  * ``sendgrid``   — SendGrid v3 HTTP API (SENDGRID_API_KEY)
  * ``dev_outbox`` — development only: writes .eml files to DEV_OUTBOX_DIR (refused in production)
  * ``disabled``   — sending is refused with a clear configuration error

Message bodies may contain one-time codes, so bodies are NEVER logged. Log lines show only the
provider, a masked recipient and the outcome.
"""
from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path
from string import Template

import httpx

from ...core.config import get_settings

log = logging.getLogger("sentrix.mailer")
TEMPLATES = Path(__file__).resolve().parents[2] / "templates" / "email"


class EmailDeliveryError(RuntimeError):
    pass


@dataclass
class DeliveryResult:
    provider: str
    status: str  # sent | failed
    message_id: str | None = None
    error: str | None = None


def mask_email(addr: str) -> str:
    local, _, dom = addr.partition("@")
    return (local[:1] + "***" if local else "***") + "@" + dom


def render(template: str, context: dict[str, str], subject: str) -> tuple[str, str]:
    """Returns (text, html). HTML values are escaped; the layout wraps the body."""
    s = get_settings()
    text = Template((TEMPLATES / f"{template}.txt").read_text(encoding="utf-8")).safe_substitute(context)
    esc = {k: html.escape(str(v), quote=True) for k, v in context.items()}
    body = Template((TEMPLATES / f"{template}.html").read_text(encoding="utf-8")).safe_substitute(esc)
    layout = Template((TEMPLATES / "_layout.html").read_text(encoding="utf-8")).safe_substitute(
        subject=html.escape(subject), body=body, product_line="Digital Identity Intelligence",
        footer=html.escape(f"Sent by {s.APP_NAME} on behalf of {context.get('organisation', 'your organisation')}."),
    )
    return text, layout


def build_message(to: str, subject: str, text: str, html_body: str) -> EmailMessage:
    s = get_settings()
    msg = EmailMessage()
    msg["From"] = formataddr((s.EMAIL_FROM_NAME, s.EMAIL_FROM_ADDRESS))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=s.EMAIL_FROM_ADDRESS.split("@")[-1])
    msg["X-Sentrix-Category"] = "identity-verification"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg


def send(to: str, subject: str, template: str, context: dict[str, str]) -> DeliveryResult:
    s = get_settings()
    provider = s.EMAIL_PROVIDER
    text, html_body = render(template, context, subject)
    msg = build_message(to, subject, text, html_body)
    mid = msg["Message-ID"]
    try:
        if provider == "disabled":
            raise EmailDeliveryError("Email delivery is disabled (EMAIL_PROVIDER=disabled).")
        if provider == "dev_outbox":
            if s.is_production:
                raise EmailDeliveryError("dev_outbox is not permitted in production.")
            out = Path(s.DEV_OUTBOX_DIR)
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"{uuid.uuid4().hex}.eml"
            path.write_bytes(bytes(msg))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        elif provider == "smtp":
            ctx = ssl.create_default_context()
            if s.SMTP_SSL:
                server: smtplib.SMTP = smtplib.SMTP_SSL(s.SMTP_HOST, s.SMTP_PORT, timeout=15, context=ctx)
            else:
                server = smtplib.SMTP(s.SMTP_HOST, s.SMTP_PORT, timeout=15)
            with server:
                if s.SMTP_STARTTLS and not s.SMTP_SSL:
                    server.starttls(context=ctx)
                if s.SMTP_USERNAME:
                    server.login(s.SMTP_USERNAME, s.SMTP_PASSWORD)
                server.send_message(msg)
        elif provider == "sendgrid":
            if not s.SENDGRID_API_KEY:
                raise EmailDeliveryError("SENDGRID_API_KEY is not configured.")
            r = httpx.post(
                "https://api.sendgrid.com/v3/mail/send", timeout=15,
                headers={"Authorization": f"Bearer {s.SENDGRID_API_KEY}"},
                json={"personalizations": [{"to": [{"email": to}]}],
                      "from": {"email": s.EMAIL_FROM_ADDRESS, "name": s.EMAIL_FROM_NAME},
                      "subject": subject,
                      "content": [{"type": "text/plain", "value": text}, {"type": "text/html", "value": html_body}],
                      "tracking_settings": {"click_tracking": {"enable": False}, "open_tracking": {"enable": False}}},
            )
            if r.status_code >= 300:
                raise EmailDeliveryError(f"SendGrid returned HTTP {r.status_code}")
            mid = r.headers.get("X-Message-Id", mid)
        else:  # pragma: no cover
            raise EmailDeliveryError(f"Unknown EMAIL_PROVIDER {provider}")
        log.info("email delivered provider=%s to=%s template=%s", provider, mask_email(to), template)
        return DeliveryResult(provider, "sent", mid)
    except (EmailDeliveryError, smtplib.SMTPException, OSError, httpx.HTTPError) as exc:
        err = str(exc) if isinstance(exc, EmailDeliveryError) else type(exc).__name__
        log.warning("email delivery failed provider=%s to=%s error=%s", provider, mask_email(to), err)
        return DeliveryResult(provider, "failed", None, err[:300])
