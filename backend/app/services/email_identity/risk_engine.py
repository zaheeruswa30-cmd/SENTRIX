"""Explainable email risk engine.

Design rules (enforced in code and wording):
  1. Every point added to the score is a ``finding`` with evidence, confidence and a
     recommendation. There are no hidden factors.
  2. The score describes the *address and its domain* — never the person. Output never uses
     words like "fraudulent" or "untrustworthy" about an individual.
  3. A failed technical check alone cannot push the band to "high"; that requires corroborating
     reputation, threat-intelligence or impersonation evidence.
  4. Missing data lowers *confidence*, not the score.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ENGINE_VERSION = "sentrix-eri-1.2"
DISCLAIMER = ("This assessment describes technical, configuration and reputation indicators for an email address "
              "and its domain. It is not a judgement about the trustworthiness or identity of any person. Mailbox "
              "ownership verification proves control of the inbox only; it does not verify real-world identity.")
SEV_WEIGHT = {"critical": 45, "high": 35, "medium": 22, "low": 10, "info": 4}


@dataclass
class Assessment:
    score: int
    band: str
    confidence: int
    findings: list[dict] = field(default_factory=list)
    summary: str = ""
    is_suspicious: bool = False
    is_technically_invalid: bool = False
    engine_version: str = ENGINE_VERSION
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _f(code, category, layer, title, evidence, impact, confidence, severity, recommendation) -> dict:
    return {"code": code, "category": category, "layer": layer, "title": title, "evidence": evidence,
            "impact": impact, "confidence": confidence, "severity": severity, "recommendation": recommendation}


def assess(ev: dict) -> Assessment:
    """``ev`` keys: syntax, infra, spf, dkim, dmarc, disposable, disposable_source, free_provider,
    role_account, reputation, age, suspicious, threat_matches, ownership_status."""
    F: list[dict] = []
    unknowns = 0
    syntax = ev.get("syntax") or {}
    infra = ev.get("infra") or {}

    # ── Layer 1: syntax ────────────────────────────────────────────────────
    if not syntax.get("valid"):
        F.append(_f("syntax_invalid", "validity", "syntax", "Address is not syntactically valid",
                    "; ".join(syntax.get("errors") or ["Failed RFC 5322 syntax rules"]), 40, 98, "high",
                    "Ask the user to re-enter the address; check for typos or copy-paste artefacts."))
        return _finish(F, unknowns=0, invalid=True)

    # ── Layer 2/3: domain existence + mail infrastructure ─────────────────────
    dns_status, mx_status = infra.get("dns_status"), infra.get("mx_status")
    invalid = False
    if dns_status == "nxdomain":
        invalid = True
        F.append(_f("domain_nxdomain", "validity", "domain", "Domain does not exist",
                    f"DNS returned NXDOMAIN for {infra.get('domain')}.", 35, 95, "high",
                    "The address cannot receive mail. Check for a misspelt domain (e.g. gmial.com)."))
    elif dns_status == "error":
        unknowns += 2
        F.append(_f("dns_error", "validity", "domain", "DNS lookup failed", "Resolver error or timeout; existence "
                    "undetermined.", 0, 40, "info", "Re-run the check later; this is not evidence about the domain."))
    if mx_status == "null_mx":
        invalid = True
        F.append(_f("null_mx", "infrastructure", "mail_infrastructure", "Domain declares it accepts no mail",
                    "Null MX record (RFC 7505: 'MX 0 .').", 30, 95, "high",
                    "Addresses at this domain cannot receive mail; request a different address."))
    elif mx_status == "absent" and dns_status != "nxdomain":
        invalid = True
        F.append(_f("no_mail_infra", "infrastructure", "mail_infrastructure", "No working mail infrastructure",
                    infra.get("explanation", "No MX/A records usable for delivery."), 30, 90, "high",
                    "Mail cannot be delivered; the address is not usable for verification or contact."))
    elif mx_status == "implicit":
        F.append(_f("implicit_mx", "infrastructure", "mail_infrastructure", "No MX record (implicit MX only)",
                    "Delivery would rely on the domain's A/AAAA record (RFC 5321 §5.1).", 8, 70, "low",
                    "Uncommon for real mailbox providers; confirm ownership before relying on the address."))
    elif mx_status == "present":
        F.append(_f("mx_present", "infrastructure", "mail_infrastructure", "Mail infrastructure configured",
                    f"{len(infra.get('mx_records') or [])} MX host(s), primary {((infra.get('mx_records') or [{}])[0]).get('host', '?')}.",
                    0, 95, "info", "None — note this does not prove the individual mailbox exists."))
    elif mx_status == "error":
        unknowns += 1

    # ── Disposable / provider type ──────────────────────────────────────────
    if ev.get("disposable"):
        F.append(_f("disposable", "disposable", "domain", "Disposable / temporary email domain",
                    f"Matched {ev.get('disposable_source') or 'the disposable-domain list'}.", 25, 90, "medium",
                    "Disposable inboxes are often short-lived. If a durable contact is required, ask for another address "
                    "— many people use them for legitimate privacy reasons."))
    if ev.get("free_provider"):
        F.append(_f("free_provider", "infrastructure", "domain", "Consumer mailbox provider",
                    "Domain is a large free mail provider; anyone can register an address.", 0, 95, "info",
                    "Normal for individuals. The provider's good authentication setup says nothing about the account holder."))
    if ev.get("role_account"):
        F.append(_f("role_account", "validity", "syntax", "Shared role mailbox",
                    "Local part looks like a role address (info@, support@ …).", 0, 70, "info",
                    "Role mailboxes may be read by several people; ownership verification proves group access only."))

    # ── Layer 4: authentication posture (sender-side controls) ─────────────────
    spf, dmarc, dkim = ev.get("spf") or {}, ev.get("dmarc") or {}, ev.get("dkim") or {}
    sender_note = " Relevant when this domain is used to send mail (spoofing protection), not to the person's identity."
    st = spf.get("status")
    if st == "missing":
        F.append(_f("spf_missing", "authentication", "authentication", "SPF record missing",
                    "No v=spf1 TXT record.", 6, 90, "low", "Domain owner should publish an SPF record ending in ~all or -all." + sender_note))
    elif st == "permissive":
        F.append(_f("spf_pass_all", "authentication", "authentication", "SPF allows every sender (+all)",
                    spf.get("parsed", {}).get("record", ""), 10, 95, "medium", "Replace +all with -all or ~all." + sender_note))
    elif st in ("invalid", "multiple"):
        F.append(_f("spf_broken", "authentication", "authentication", "SPF record is broken",
                    "; ".join(i["message"] for i in spf.get("issues", [])) or st, 6, 90, "low",
                    "Fix the SPF syntax / merge records / reduce lookups below 10." + sender_note))
    elif st == "error":
        unknowns += 1
    dt = dmarc.get("status")
    if dt == "missing":
        F.append(_f("dmarc_missing", "authentication", "authentication", "DMARC policy missing",
                    "No _dmarc TXT record.", 6, 90, "low", "Publish v=DMARC1; p=none with rua= reporting, then move to quarantine/reject." + sender_note))
    elif dt == "monitoring":
        F.append(_f("dmarc_none", "authentication", "authentication", "DMARC in monitoring mode (p=none)",
                    dmarc.get("parsed", {}).get("record", ""), 2, 90, "info", "Progress to p=quarantine then p=reject once reports are clean." + sender_note))
    elif dt == "invalid":
        F.append(_f("dmarc_invalid", "authentication", "authentication", "DMARC record malformed",
                    "; ".join(i["message"] for i in dmarc.get("issues", [])), 5, 90, "low", "Correct the DMARC record syntax." + sender_note))
    elif dt == "error":
        unknowns += 1
    kt = dkim.get("status")
    if kt == "not_found":
        F.append(_f("dkim_unknown", "authentication", "authentication", "No DKIM key at common selectors",
                    "Selector discovery is incomplete by nature; this is not proof DKIM is absent.", 0, 35, "info",
                    "Verify DKIM by analysing a real message from this domain (Email Authentication → Verify message)."))
    elif kt == "signature_fail":
        F.append(_f("dkim_sig_fail", "authentication", "authentication", "Supplied message failed DKIM verification",
                    "Cryptographic verification of the provided message failed.", 8, 80, "low",
                    "Check whether the message was forwarded/modified; failure alone is not proof of spoofing."))
    elif kt == "signature_pass":
        F.append(_f("dkim_sig_pass", "authentication", "authentication", "Supplied message passed DKIM verification",
                    "At least one DKIM signature verified against DNS.", 0, 90, "info",
                    "None — integrity of that message is confirmed; sender identity is not."))

    # ── Reputation / age / suspicious structure ────────────────────────────────
    rep = ev.get("reputation") or {}
    if rep.get("status") == "listed":
        zones = ", ".join(z["zone"] for z in rep.get("zones", []) if z.get("status") == "listed")
        F.append(_f("dnsbl_listed", "reputation", "reputation", "Domain listed on a DNS blocklist",
                    f"Listed on {zones}.", 35, 85, "high", "Treat mail from this domain with caution; review the listing reason."))
    elif rep.get("status") in ("not_checked", "error", None):
        unknowns += 1
    age = ev.get("age") or {}
    if age.get("status") != "ok":
        unknowns += 1
    for ind in ev.get("suspicious") or []:
        sev = "medium" if ind["weight"] >= 15 else "low"
        F.append(_f(ind["code"], "suspicious_domain", "reputation", ind["title"], ind["evidence"], ind["weight"],
                    ind["confidence"], sev, "Compare the domain carefully with the organisation it appears to reference."))

    # ── Threat intelligence + abuse reports ────────────────────────────────────
    for m in ev.get("threat_matches") or []:
        is_abuse = m.get("source") == "abuse_report"
        w = SEV_WEIGHT.get(m.get("severity", "medium"), 22) * (0.8 if is_abuse else 1)
        F.append(_f("abuse_report" if is_abuse else "threat_intel_match", "abuse" if is_abuse else "threat_intel",
                    "reputation", ("Abuse report on file" if is_abuse else "Threat-intelligence match") +
                    f" ({m.get('indicator_type')}: {m.get('value')})", m.get("description") or "Indicator in tenant TI store.",
                    int(round(w * (m.get("confidence", 60) / 100) + 5)), m.get("confidence", 60), m.get("severity", "medium"),
                    "Open the indicator, confirm it is current, and consider an investigation case."))

    # ── Layer 5: ownership ────────────────────────────────────────────────────
    own = ev.get("ownership_status", "unverified")
    if own == "verified":
        F.append(_f("ownership_verified", "ownership", "ownership", "Mailbox ownership verified",
                    "The submitter completed the one-time code / link challenge sent to this address.", -15, 95, "info",
                    "Control of the inbox is demonstrated. Real-world identity is still unverified."))
    elif own in ("failed", "locked"):
        F.append(_f("ownership_failed", "ownership", "ownership", "Ownership challenge not completed",
                    f"Challenge status: {own}. Frequently caused by typos, expired codes or spam filtering.", 4, 40, "low",
                    "Offer a resend; do not treat this alone as evidence of misuse."))
    elif own in ("unverified", "expired", "pending"):
        F.append(_f("ownership_unverified", "ownership", "ownership", "Mailbox ownership not verified",
                    f"Status: {own}.", 0, 90, "info", "Send a verification challenge if control of the inbox matters."))
    return _finish(F, unknowns, invalid)


def _finish(F: list[dict], unknowns: int, invalid: bool) -> Assessment:
    raw = sum(f["impact"] for f in F)
    score = max(0, min(100, int(round(raw))))
    corroborated = any(f["category"] in ("threat_intel", "abuse", "reputation", "suspicious_domain")
                       and f["impact"] >= 15 for f in F)
    if score >= 70 and not corroborated:
        score = 69  # rule 3: technical failures alone cannot reach "high"
    band = "high" if score >= 70 else "elevated" if score >= 45 else "guarded" if score >= 20 else "low"
    weighted = [f for f in F if f["impact"] != 0] or F
    base_conf = sum(f["confidence"] for f in weighted) / max(1, len(weighted)) if weighted else 50
    confidence = int(max(20, min(98, base_conf - unknowns * 6)))
    suspicious = band in ("elevated", "high") or any(
        f["category"] in ("threat_intel", "abuse") or (f["category"] == "suspicious_domain" and f["confidence"] >= 60)
        for f in F)
    drivers = sorted([f for f in F if f["impact"] > 0], key=lambda f: -f["impact"])[:3]
    if drivers:
        summary = (f"Risk {score}/100 ({band}). Main drivers: " + "; ".join(f["title"] for f in drivers) + ".")
    else:
        summary = f"Risk {score}/100 ({band}). No adverse technical or reputation indicators were found."
    if invalid:
        summary += " The address is not technically deliverable."
    return Assessment(score=score, band=band, confidence=confidence, findings=F, summary=summary,
                      is_suspicious=suspicious, is_technically_invalid=invalid)
