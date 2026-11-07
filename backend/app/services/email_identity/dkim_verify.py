"""Cryptographic DKIM signature verification for an analyst-supplied message.

This is the ONLY place Sentrix reports DKIM pass/fail. It requires the full original message
(headers + body exactly as received, e.g. an exported .eml). The message is processed in memory
and discarded — only a SHA-256 fingerprint and a header summary are persisted.

``Authentication-Results`` headers are reported separately as *claims made by a receiving
server*; they are never treated as Sentrix's own verification.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from email.utils import parseaddr

import dkim

from .dns_client import DnsClient

MAX_MESSAGE_BYTES = 2 * 1024 * 1024


@dataclass
class SignatureResult:
    index: int
    domain: str
    selector: str
    algorithm: str
    signed_headers: list[str]
    verified: bool
    aligned_with_from: bool
    error: str | None = None


@dataclass
class DkimVerification:
    status: str  # signature_pass | signature_fail | no_signature | error
    message_sha256: str
    from_address: str = ""
    from_domain: str = ""
    subject_present: bool = False
    signatures: list[SignatureResult] = field(default_factory=list)
    receiver_claims: list[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["signatures"] = [s.__dict__ for s in self.signatures]
        return d


def _aligned(sig_domain: str, from_domain: str) -> bool:
    s, f = sig_domain.lower().rstrip("."), from_domain.lower().rstrip(".")
    return bool(s and f) and (f == s or f.endswith("." + s) or s.endswith("." + f))


def verify_message(raw: bytes, dns_client: DnsClient) -> DkimVerification:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("Message exceeds the 2 MB limit.")
    raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")  # canonical CRLF line endings
    digest = hashlib.sha256(raw).hexdigest()
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    from_addr = parseaddr(msg.get("From", ""))[1]
    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    out = DkimVerification(status="no_signature", message_sha256=digest, from_address=from_addr,
                           from_domain=from_domain, subject_present=bool(msg.get("Subject")))
    out.receiver_claims = [re.sub(r"\s+", " ", str(h))[:400] for h in (msg.get_all("Authentication-Results") or [])][:5]

    def dnsfunc(name, timeout=5):  # dkimpy callback → our resolver (system or DoH)
        n = name.decode() if isinstance(name, bytes) else name
        ans = dns_client.txt(n.rstrip("."))
        return ans.records[0].encode() if ans.ok and ans.records else b""

    sig_headers = msg.get_all("DKIM-Signature") or []
    if not sig_headers:
        out.explanation = ("The message carries no DKIM-Signature header, so there is nothing to verify. Receiver "
                           "claims (Authentication-Results), if any, are listed separately and were not re-verified.")
        return out
    d = dkim.DKIM(raw)
    any_pass = False
    for idx, hv in enumerate(sig_headers):
        tags = {}
        for part in re.sub(r"\s+", "", str(hv)).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.lower()] = v
        sr = SignatureResult(index=idx, domain=tags.get("d", ""), selector=tags.get("s", ""),
                             algorithm=tags.get("a", ""), signed_headers=tags.get("h", "").split(":")[:20],
                             verified=False, aligned_with_from=_aligned(tags.get("d", ""), from_domain))
        try:
            sr.verified = bool(d.verify(idx=idx, dnsfunc=dnsfunc))
            if not sr.verified:
                sr.error = "Signature did not verify (body or signed headers altered, or key mismatch)."
        except dkim.DKIMException as exc:
            sr.error = str(exc)[:200]
        any_pass = any_pass or sr.verified
        out.signatures.append(sr)
    out.status = "signature_pass" if any_pass else "signature_fail"
    aligned_pass = any(s.verified and s.aligned_with_from for s in out.signatures)
    if any_pass:
        out.explanation = ("At least one DKIM signature verified cryptographically against the public key in DNS" +
                           (" and its d= domain aligns with the From domain." if aligned_pass else
                            ", but no passing signature aligns with the From domain (DMARC alignment would fail).") +
                           " This proves the signed content was not altered since signing by a holder of that "
                           "domain's key — it does not identify the human sender.")
    else:
        out.explanation = ("No DKIM signature verified. Common benign causes: the message was modified in transit "
                           "(mailing lists, footers), it was re-saved with altered line endings, or the key was rotated.")
    return out
