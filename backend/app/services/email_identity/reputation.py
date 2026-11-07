"""Disposable-domain detection, free-provider detection and opt-in reputation enrichment.

Privacy note: RDAP and DNSBL lookups disclose the *domain* (never the full address) to a third
party, so both are disabled by default and must be enabled explicitly in configuration.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import httpx

from ...core.config import get_settings
from .dns_client import DnsClient

log = logging.getLogger("sentrix.reputation")
DATA = Path(__file__).resolve().parents[2] / "data"

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
    "gmx.de", "web.de", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com",
    "126.com", "fastmail.com", "tutanota.com", "hey.com",
}


@lru_cache
def disposable_domains() -> frozenset[str]:
    path = DATA / "disposable_domains.txt"
    items = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                items.add(line)
    return frozenset(items)


def check_disposable(ascii_domain: str) -> tuple[bool, str | None]:
    """Exact or parent-domain match against the bundled community list (CC0)."""
    dset = disposable_domains()
    labels = ascii_domain.lower().split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in dset:
            return True, f"disposable-email-domains list (match: {cand})"
    return False, None


def is_free_provider(ascii_domain: str) -> bool:
    return ascii_domain.lower() in FREE_PROVIDERS


def rdap_domain_age(ascii_domain: str) -> dict:
    s = get_settings()
    if not s.ENRICHMENT_RDAP_ENABLED:
        return {"status": "not_checked", "reason": "RDAP enrichment disabled (ENRICHMENT_RDAP_ENABLED=false)"}
    try:
        r = httpx.get(s.RDAP_BASE_URL + ascii_domain, timeout=6, follow_redirects=True,
                      headers={"accept": "application/rdap+json"})
        if r.status_code == 404:
            return {"status": "not_found", "reason": "Registry RDAP has no record for this domain"}
        r.raise_for_status()
        data = r.json()
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return {"status": "ok", "registration_date": dt.isoformat(),
                        "age_days": (datetime.now(timezone.utc) - dt).days, "source": "RDAP"}
        return {"status": "unknown", "reason": "RDAP response has no registration event"}
    except (httpx.HTTPError, ValueError) as exc:
        log.info("RDAP lookup failed for domain: %s", type(exc).__name__)
        return {"status": "error", "reason": type(exc).__name__}


def dnsbl_reputation(dns: DnsClient, ascii_domain: str) -> dict:
    s = get_settings()
    if not s.ENRICHMENT_DNSBL_ENABLED:
        return {"status": "not_checked", "reason": "DNSBL enrichment disabled (ENRICHMENT_DNSBL_ENABLED=false)"}
    results = []
    listed = False
    errored = False
    for zone in s.dnsbl_zones:
        ans = dns.resolve(f"{ascii_domain}.{zone}", "A")
        if ans.ok:
            codes = ans.records
            # Spamhaus returns 127.255.255.x when the query is refused (e.g. via a public resolver)
            if any(c.startswith("127.255.255.") for c in codes):
                errored = True
                results.append({"zone": zone, "status": "query_refused", "codes": codes})
            else:
                listed = True
                results.append({"zone": zone, "status": "listed", "codes": codes})
        elif ans.status == "error":
            errored = True
            results.append({"zone": zone, "status": "error"})
        else:
            results.append({"zone": zone, "status": "not_listed"})
    status = "listed" if listed else ("error" if errored and not any(r["status"] == "not_listed" for r in results)
                                      else "not_listed")
    return {"status": status, "zones": results}
