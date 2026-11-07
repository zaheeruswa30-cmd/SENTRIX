"""Sentrix — logging setup with secret redaction.

Verification tokens, codes, JWTs and passwords must never reach log output. Besides never
logging them explicitly, this filter scrubs anything that looks like one as a defence in depth.
"""
from __future__ import annotations

import logging
import re

_PATTERNS = [
    (re.compile(r"(token=)[A-Za-z0-9_\-\.]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(\"?(?:token|code|password|secret|authorization)\"?\s*[:=]\s*\"?)[^\s\",}]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[REDACTED-JWT]"),
]


def redact(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - malformed record
            return True
        record.msg = redact(msg)
        record.args = ()
        return True


def configure_logging(debug: bool = False) -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in root.filters):
        logging.basicConfig(
            level=logging.DEBUG if debug else logging.INFO,
            format="%(asctime)s %(levelname)s [sentrix] %(name)s: %(message)s",
        )
    for noisy in ("fpdf", "fontTools", "httpx", "httpcore", "multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    flt = RedactingFilter()
    for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error", "sentrix"):
        lg = logging.getLogger(name)
        lg.addFilter(flt)
        for h in lg.handlers:
            h.addFilter(flt)
