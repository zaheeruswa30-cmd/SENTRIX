"""Domain existence and mail-exchanger (MX) analysis.

* ``dns_status``: does the domain exist in DNS at all?
* ``mx_status``:  is the domain set up to *receive* mail?
    - ``present``  – one or more MX hosts (and at least one of them resolves)
    - ``implicit`` – no MX, but an A/AAAA record exists; RFC 5321 §5.1 "implicit MX" fallback
    - ``null_mx``  – the domain explicitly declares it accepts no mail (RFC 7505: "MX 0 .")
    - ``absent``   – neither MX nor address records → mail cannot be delivered
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .dns_client import DnsAnswer, DnsClient


@dataclass
class MailInfra:
    domain: str
    dns_status: str = "not_checked"
    mx_status: str = "not_checked"
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    mx_records: list[dict] = field(default_factory=list)  # {preference, host, resolves, addresses}
    lookups: list[dict] = field(default_factory=list)
    explanation: str = ""
    resolver: str = "system"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def analyze_mail_infrastructure(dns: DnsClient, ascii_domain: str) -> MailInfra:
    info = MailInfra(domain=ascii_domain)
    with ThreadPoolExecutor(max_workers=4) as pool:
        fa, faaaa, fmx, fns = (pool.submit(dns.resolve, ascii_domain, t) for t in ("A", "AAAA", "MX", "NS"))
        a, aaaa, mx, ns = fa.result(), faaaa.result(), fmx.result(), fns.result()
    answers: list[DnsAnswer] = [a, aaaa, mx, ns]
    info.lookups = [x.to_dict() for x in answers]
    info.resolver = mx.resolver
    info.a_records, info.aaaa_records, info.ns_records = a.records, aaaa.records, ns.records

    if all(x.status == "error" for x in answers) or (
            not any(x.ok for x in answers) and "error" in (a.status, mx.status)
            and not any(x.status == "nxdomain" for x in answers)):
        info.dns_status = info.mx_status = "error"
        info.explanation = ("DNS lookups failed (resolver timeout or refusal), so domain existence could not be "
                            "determined. This is a lookup problem, not evidence about the domain.")
        return info
    if any(x.status == "nxdomain" for x in (a, mx, ns)) and not any(x.ok for x in answers):
        info.dns_status, info.mx_status = "nxdomain", "absent"
        info.explanation = (f"{ascii_domain} does not exist in DNS (NXDOMAIN). No mail can be delivered to "
                            "addresses at this domain.")
        return info
    info.dns_status = "resolves" if any(x.ok for x in answers) else "no_address"

    if mx.ok:
        parsed = []
        for rec in mx.records:
            pref, _, host = rec.partition(" ")
            parsed.append({"preference": int(pref) if pref.isdigit() else 0, "host": host.strip().rstrip(".")})
        parsed.sort(key=lambda r: r["preference"])
        if len(parsed) == 1 and parsed[0]["host"] in ("", "."):
            info.mx_status = "null_mx"
            info.mx_records = [{"preference": parsed[0]["preference"], "host": ".", "resolves": False, "addresses": []}]
            info.explanation = (f"{ascii_domain} publishes a Null MX record (RFC 7505), explicitly declaring that it "
                                "does not accept email.")
            return info

        def _resolve_host(rec: dict) -> dict:
            ha = dns.resolve(rec["host"], "A")
            h6 = dns.resolve(rec["host"], "AAAA") if not ha.ok else None
            addrs = ha.records + (h6.records if h6 else [])
            return {**rec, "resolves": bool(addrs), "addresses": addrs[:4]}

        with ThreadPoolExecutor(max_workers=5) as pool:
            info.mx_records = list(pool.map(_resolve_host, parsed[:6]))
        if any(r["resolves"] for r in info.mx_records):
            info.mx_status = "present"
            info.explanation = (f"{ascii_domain} has {len(parsed)} MX host(s); the primary is "
                                f"{info.mx_records[0]['host']} (preference {info.mx_records[0]['preference']}). "
                                "This shows mail infrastructure is configured — not that any particular mailbox exists.")
        else:
            info.mx_status = "absent"
            info.explanation = (f"{ascii_domain} lists MX hosts but none of them resolve to an IP address, so mail "
                                "delivery would fail.")
        return info

    if mx.status == "error":
        info.mx_status = "error"
        info.explanation = "The MX lookup failed (resolver error); mail infrastructure is undetermined."
        return info
    if a.ok or aaaa.ok:
        info.mx_status = "implicit"
        info.explanation = (f"{ascii_domain} has no MX record, but it has an address record. Under RFC 5321 §5.1 "
                            "senders may fall back to that host (implicit MX). This is unusual for real mail domains.")
    else:
        info.mx_status = "absent"
        info.explanation = f"{ascii_domain} exists but has neither MX nor address records; it cannot receive mail."
    return info
