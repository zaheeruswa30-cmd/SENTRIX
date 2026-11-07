"""SPF, DMARC and DKIM *configuration* analysis from public DNS.

IMPORTANT: these functions describe how a domain has configured sender authentication. They do
not — and cannot — say whether a particular message passed authentication. A DKIM public key in
DNS only proves a key is published; DKIM *verification* requires the signed message itself
(see ``dkim_verify.py``).
"""
from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .dns_client import DnsClient

SPF_LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}
SPF_ALL_MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}


@dataclass
class AuthResult:
    mechanism: str
    status: str
    query_name: str
    raw_records: list[str] = field(default_factory=list)
    parsed: dict = field(default_factory=dict)
    issues: list[dict] = field(default_factory=list)  # {severity, code, message}
    explanation: str = ""
    selector: str | None = None

    def issue(self, severity: str, code: str, message: str) -> None:
        self.issues.append({"severity": severity, "code": code, "message": message})

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ── SPF ──────────────────────────────────────────────────────────────────────

def _spf_records(dns: DnsClient, name: str) -> tuple[str, list[str]]:
    ans = dns.txt(name)
    if ans.status == "error":
        return "error", []
    return ans.status, [r for r in ans.records if r.lower().startswith("v=spf1 ") or r.lower() == "v=spf1"]


def _count_lookups(dns: DnsClient, record: str, depth: int, seen: set[str]) -> int:
    count = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech = re.split(r"[:/=]", t, maxsplit=1)[0]
        if mech in SPF_LOOKUP_MECHS:
            count += 1
        if mech == "redirect":
            count += 1
        target = None
        if mech == "include" and ":" in t:
            target = t.split(":", 1)[1]
        elif mech == "redirect" and "=" in t:
            target = t.split("=", 1)[1]
        if target and depth < 4 and target not in seen:
            seen.add(target)
            _, recs = _spf_records(dns, target)
            if len(recs) == 1:
                count += _count_lookups(dns, recs[0], depth + 1, seen)
    return count


def check_spf(dns: DnsClient, domain: str) -> AuthResult:
    r = AuthResult("spf", "not_checked", domain)
    status, recs = _spf_records(dns, domain)
    ans = dns.txt(domain)
    r.raw_records = recs
    if status == "error":
        r.status = "error"
        r.explanation = "The TXT lookup for SPF failed; SPF configuration is undetermined."
        return r
    if not recs:
        r.status = "missing"
        r.issue("medium", "spf_missing", "No SPF record (TXT starting with v=spf1) is published.")
        r.explanation = (f"{domain} publishes no SPF policy, so receivers cannot check which servers may send mail "
                         "using this domain in the envelope sender. This matters when the domain is used to *send* mail; "
                         "it says nothing about the person using an address here.")
        r.parsed = {"other_txt_records": len(ans.records)}
        return r
    if len(recs) > 1:
        r.status = "multiple"
        r.issue("high", "spf_multiple", f"{len(recs)} SPF records found; RFC 7208 §4.5 makes this a permanent error.")
        r.explanation = "More than one SPF record exists, which causes SPF evaluation to fail (permerror) everywhere."
        return r

    record = recs[0]
    terms = record.split()[1:]
    mechanisms, modifiers, unknown = [], {}, []
    all_q = None
    for term in terms:
        q = term[0] if term[0] in "+-~?" else "+"
        body = term[1:] if term[0] in "+-~?" else term
        low = body.lower()
        if "=" in low and not low.startswith(("ip4", "ip6")) and re.match(r"^[a-z][a-z0-9_.-]*=", low):
            k, v = body.split("=", 1)
            modifiers[k.lower()] = v
            continue
        mech = re.split(r"[:/]", low, maxsplit=1)[0]
        if mech not in SPF_ALL_MECHS:
            unknown.append(term)
            continue
        mechanisms.append({"qualifier": q, "mechanism": mech, "value": body[len(mech):].lstrip(":") or None})
        if mech == "all":
            all_q = q
    lookups = _count_lookups(dns, record, 0, {domain})
    r.parsed = {"record": record, "mechanisms": mechanisms, "modifiers": modifiers, "all_qualifier": all_q,
                "dns_lookup_count": lookups}
    if unknown:
        r.status = "invalid"
        r.issue("high", "spf_syntax", f"Unrecognised SPF term(s): {', '.join(unknown[:5])}.")
    if lookups > 10:
        r.status = "invalid"
        r.issue("high", "spf_too_many_lookups",
                f"SPF needs {lookups} DNS lookups; RFC 7208 §4.6.4 allows at most 10 (permerror).")
    if any(m["mechanism"] == "ptr" for m in mechanisms):
        r.issue("low", "spf_ptr", "The 'ptr' mechanism is deprecated (RFC 7208 §5.5) and slow.")
    if all_q == "+":
        r.status = r.status if r.status == "invalid" else "permissive"
        r.issue("high", "spf_pass_all", "'+all' authorises every server on the internet to send as this domain.")
    elif all_q == "?":
        r.issue("medium", "spf_neutral_all", "'?all' (neutral) gives receivers no guidance for unlisted servers.")
    elif all_q == "~all":
        pass
    elif all_q is None and "redirect" not in modifiers:
        r.issue("low", "spf_no_all", "No 'all' mechanism or redirect; unlisted senders default to neutral.")
    if r.status == "not_checked":
        r.status = "valid"
    strictness = {"-": "hard fail (-all)", "~": "soft fail (~all)", "?": "neutral (?all)", "+": "pass (+all)"}.get(
        all_q or "", "no explicit default")
    r.explanation = (f"SPF record found with {len(mechanisms)} mechanism(s), default policy {strictness}, "
                     f"{lookups} DNS lookup(s). SPF authorises sending servers for the envelope domain; "
                     "it is a sender-side control, not proof of who owns a mailbox.")
    return r


# ── DMARC ────────────────────────────────────────────────────────────────────

def _org_domain(domain: str) -> str:
    """Approximate organisational domain (last two labels). A Public Suffix List lookup would be
    more accurate for multi-label suffixes such as co.uk; documented limitation."""
    labels = domain.split(".")
    return ".".join(labels[-3:]) if len(labels) >= 3 and len(labels[-2]) <= 3 and len(labels[-1]) == 2 \
        else ".".join(labels[-2:])


def check_dmarc(dns: DnsClient, domain: str) -> AuthResult:
    name = f"_dmarc.{domain}"
    r = AuthResult("dmarc", "not_checked", name)
    ans = dns.txt(name)
    inherited = False
    if ans.status in ("nxdomain", "nodata") or (ans.ok and not any(x.lower().startswith("v=dmarc1") for x in ans.records)):
        org = _org_domain(domain)
        if org != domain:
            alt = dns.txt(f"_dmarc.{org}")
            if alt.ok and any(x.lower().startswith("v=dmarc1") for x in alt.records):
                ans, inherited, r.query_name = alt, True, f"_dmarc.{org}"
    if ans.status == "error":
        r.status = "error"
        r.explanation = "The DMARC TXT lookup failed; DMARC policy is undetermined."
        return r
    recs = [x for x in ans.records if x.lower().startswith("v=dmarc1")]
    r.raw_records = recs
    if not recs:
        r.status = "missing"
        r.issue("medium", "dmarc_missing", "No DMARC record is published at _dmarc." + domain + ".")
        r.explanation = (f"{domain} has no DMARC policy, so receivers have no instruction for mail that fails "
                         "SPF/DKIM alignment and the owner receives no aggregate reports.")
        return r
    if len(recs) > 1:
        r.status = "invalid"
        r.issue("high", "dmarc_multiple", "Multiple DMARC records; receivers must ignore all of them (RFC 7489 §6.6.3).")
        r.explanation = "Multiple DMARC records were found, which invalidates the policy."
        return r
    tags: dict[str, str] = {}
    for part in recs[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    r.parsed = {"record": recs[0], "tags": tags, "inherited_from_org_domain": inherited}
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        r.status = "invalid"
        r.issue("high", "dmarc_bad_policy", "The required 'p=' tag is missing or not none/quarantine/reject.")
        r.explanation = "The DMARC record is malformed (invalid or missing p= policy)."
        return r
    pct = tags.get("pct", "100")
    if not tags.get("rua"):
        r.issue("low", "dmarc_no_rua", "No rua= aggregate-report address; the owner gets no visibility of abuse.")
    if pct.isdigit() and int(pct) < 100:
        r.issue("low", "dmarc_partial", f"pct={pct}: the policy applies to only {pct}% of failing mail.")
    if p == "none":
        r.status = "monitoring"
        r.issue("low", "dmarc_p_none", "p=none only monitors; spoofed mail is not quarantined or rejected.")
    else:
        r.status = "enforced"
    r.explanation = (f"DMARC policy p={p}" + (f", subdomain policy sp={tags['sp']}" if "sp" in tags else "") +
                     (" (inherited from the organisational domain)" if inherited else "") +
                     ". DMARC tells receivers what to do with mail that fails SPF/DKIM alignment for this domain.")
    return r


# ── DKIM (selector discovery) ────────────────────────────────────────────────

def _rsa_bits(p_b64: str) -> int | None:
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        key = load_der_public_key(base64.b64decode(p_b64 + "=" * (-len(p_b64) % 4)))
        return getattr(key, "key_size", None)
    except Exception:
        return None


def check_dkim(dns: DnsClient, domain: str, selectors: list[str]) -> tuple[AuthResult, list[AuthResult]]:
    summary = AuthResult("dkim", "not_checked", f"<selector>._domainkey.{domain}")
    ordered = list(dict.fromkeys(s.strip() for s in selectors if s and re.match(r"^[A-Za-z0-9._-]{1,63}$", s.strip())))

    def probe(sel: str) -> AuthResult | None:
        name = f"{sel}._domainkey.{domain}"
        ans = dns.txt(name)
        if not ans.ok:
            return None
        recs = [x for x in ans.records if "p=" in x.replace(" ", "") or x.lower().startswith("v=dkim1")]
        if not recs:
            return None
        res = AuthResult("dkim", "selector_found", name, raw_records=[x[:600] for x in recs], selector=sel)
        tags = {}
        for part in recs[0].split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip().replace(" ", "")
        k = tags.get("k", "rsa").lower()
        p = tags.get("p", "")
        bits = _rsa_bits(p) if k == "rsa" and p else None
        res.parsed = {"key_type": k, "key_bits": bits, "revoked": p == "", "testing": "y" in tags.get("t", "").split(":")}
        if p == "":
            res.issue("medium", "dkim_revoked", f"Selector '{sel}' has an empty p= (key revoked).")
        if bits and bits < 1024:
            res.issue("high", "dkim_weak_key", f"Selector '{sel}' uses a {bits}-bit RSA key (minimum 1024, 2048 recommended).")
        elif bits and bits < 2048:
            res.issue("low", "dkim_1024", f"Selector '{sel}' uses a 1024-bit RSA key; 2048-bit is recommended.")
        res.explanation = (f"A DKIM public key is published at {name} ({k}{', ' + str(bits) + '-bit' if bits else ''}). "
                           "This shows the domain can sign mail with this selector; it does not show that any "
                           "given message passed DKIM verification.")
        return res

    with ThreadPoolExecutor(max_workers=8) as pool:
        found = [x for x in pool.map(probe, ordered) if x]
    summary.parsed = {"selectors_tried": ordered, "selectors_found": [f.selector for f in found]}
    if found:
        summary.status = "selector_found"
        for f in found:
            summary.issues.extend(f.issues)
        summary.raw_records = [f"{f.selector}: {f.raw_records[0][:120]}…" for f in found]
        summary.explanation = (f"Found DKIM key(s) for selector(s) {', '.join(f.selector or '' for f in found)}. "
                               "Key discovery is configuration evidence only — DKIM pass/fail can only be determined "
                               "by verifying the signature on an actual message (use 'Verify a message').")
    else:
        summary.status = "not_found"
        summary.issue("info", "dkim_not_discovered",
                      f"No DKIM key found for {len(ordered)} common selector(s).")
        summary.explanation = ("No DKIM key was found under the common selector names tried. DKIM selectors are "
                               "arbitrary, so this does NOT prove DKIM is absent — provide a message's DKIM-Signature "
                               "(s= tag) or a known selector to check precisely.")
    return summary, found
