"""DNS lookups for Email Identity Intelligence.

Two transports:
  * ``system`` — the host resolver via dnspython (default)
  * ``doh``    — DNS-over-HTTPS, RFC 8484 wire format, to ``DNS_DOH_URL``

If the system resolver is unusable (common in locked-down networks/containers) and
``DNS_DOH_FALLBACK`` is true, the query is retried over DoH. Only public DNS data is queried; no
SMTP connection is ever opened to the target mail server (no mailbox probing).
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import httpx

from ...core.config import get_settings

log = logging.getLogger("sentrix.dns")


@dataclass
class DnsAnswer:
    name: str
    rdtype: str
    status: str  # ok | nxdomain | nodata | error
    records: list[str] = field(default_factory=list)
    error: str | None = None
    resolver: str = "system"

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.rdtype, "status": self.status, "records": self.records,
                "error": self.error, "resolver": self.resolver}


def _rdata_text(rdtype: str, rdata) -> str:
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rdtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True) or '.'}"
    if rdtype in ("NS", "CNAME", "PTR"):
        return rdata.target.to_text(omit_final_dot=True)
    return rdata.to_text()


class DnsClient:
    """Thread-safe resolver with a per-instance memo (one instance per analysis run)."""

    def __init__(self, mode: str | None = None, timeout: float | None = None):
        s = get_settings()
        self.mode = mode or s.DNS_RESOLVER
        self.timeout = timeout or s.DNS_TIMEOUT_SECONDS
        self.doh_url = s.DNS_DOH_URL
        self.doh_fallback = s.DNS_DOH_FALLBACK
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._lock = threading.Lock()
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = self.timeout
        self._resolver.timeout = min(self.timeout, 2.0)
        self._system_broken = False

    # public API ------------------------------------------------------------
    def resolve(self, name: str, rdtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rdtype.upper())
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        ans = self._resolve(*key)
        with self._lock:
            self._cache[key] = ans
        return ans

    def txt(self, name: str) -> DnsAnswer:
        return self.resolve(name, "TXT")

    # transports ------------------------------------------------------------
    def _resolve(self, name: str, rdtype: str) -> DnsAnswer:
        if self.mode == "doh" or self._system_broken:
            return self._doh(name, rdtype)
        ans = self._system(name, rdtype)
        if ans.status == "error" and self.doh_fallback:
            doh = self._doh(name, rdtype)
            if doh.status != "error":
                self._system_broken = True  # stop paying the timeout on every query
            return doh
        return ans

    def _system(self, name: str, rdtype: str) -> DnsAnswer:
        try:
            rrset = self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
            if rrset.rrset is None:
                return DnsAnswer(name, rdtype, "nodata", resolver="system")
            return DnsAnswer(name, rdtype, "ok", [_rdata_text(rdtype, r) for r in rrset], resolver="system")
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rdtype, "nxdomain", resolver="system")
        except dns.resolver.NoAnswer:
            return DnsAnswer(name, rdtype, "nodata", resolver="system")
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            return DnsAnswer(name, rdtype, "error", error=type(exc).__name__, resolver="system")
        except dns.exception.DNSException as exc:
            return DnsAnswer(name, rdtype, "error", error=type(exc).__name__, resolver="system")

    def _doh(self, name: str, rdtype: str) -> DnsAnswer:
        try:
            q = dns.message.make_query(name, rdtype)
            q.id = 0  # RFC 8484 §4.1 cache friendliness
            r = httpx.post(
                self.doh_url, content=q.to_wire(), timeout=self.timeout,
                headers={"content-type": "application/dns-message", "accept": "application/dns-message"},
            )
            r.raise_for_status()
            msg = dns.message.from_wire(r.content)
            rc = msg.rcode()
            if rc == dns.rcode.NXDOMAIN:
                return DnsAnswer(name, rdtype, "nxdomain", resolver="doh")
            if rc != dns.rcode.NOERROR:
                return DnsAnswer(name, rdtype, "error", error=dns.rcode.to_text(rc), resolver="doh")
            want = dns.rdatatype.from_text(rdtype)
            out: list[str] = []
            for rrset in msg.answer:
                if rrset.rdtype == want:
                    out.extend(_rdata_text(rdtype, rd) for rd in rrset)
            return DnsAnswer(name, rdtype, "ok" if out else "nodata", out, resolver="doh")
        except (httpx.HTTPError, dns.exception.DNSException, ValueError) as exc:
            log.warning("DoH lookup failed for %s %s: %s", name, rdtype, type(exc).__name__)
            return DnsAnswer(name, rdtype, "error", error=type(exc).__name__, resolver="doh")


class StaticDnsClient(DnsClient):
    """Deterministic resolver for tests and offline demos.

    ``zone`` maps ``(name, TYPE)`` → list of records, or the strings ``"NXDOMAIN"`` / ``"ERROR"``.
    Names absent from the zone return NODATA if any record exists for the name, else NXDOMAIN.
    """

    def __init__(self, zone: dict[tuple[str, str], object]):
        self.zone = {(k[0].lower(), k[1].upper()): v for k, v in zone.items()}
        self._cache = {}
        self._lock = threading.Lock()
        self.mode = "static"

    def _resolve(self, name: str, rdtype: str) -> DnsAnswer:
        v = self.zone.get((name, rdtype))
        if v == "NXDOMAIN":
            return DnsAnswer(name, rdtype, "nxdomain", resolver="static")
        if v == "ERROR":
            return DnsAnswer(name, rdtype, "error", error="Timeout", resolver="static")
        if isinstance(v, list):
            return DnsAnswer(name, rdtype, "ok" if v else "nodata", list(v), resolver="static")
        exists = any(k[0] == name or k[0].endswith("." + name) for k in self.zone)
        return DnsAnswer(name, rdtype, "nodata" if exists else "nxdomain", resolver="static")
