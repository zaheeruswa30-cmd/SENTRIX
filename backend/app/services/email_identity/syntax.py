"""Email address syntax validation (RFC 5321 / 5322 / 6531 practical profile).

Each rule is reported as an individual check so the result is explainable. A syntactically valid
address only means the string is well-formed — it says nothing about whether the domain exists,
whether it can receive mail, or who owns the mailbox.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

import idna

ATEXT = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$")
LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
ROLE_LOCAL_PARTS = {
    "abuse", "admin", "administrator", "billing", "contact", "help", "helpdesk", "hostmaster", "info",
    "it", "mail", "marketing", "no-reply", "noreply", "office", "postmaster", "root", "sales",
    "security", "support", "team", "webmaster", "hr", "jobs", "careers", "privacy",
}


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class SyntaxResult:
    input: str
    valid: bool
    normalized: str = ""
    local_part: str = ""
    domain: str = ""            # unicode form, lower-cased
    ascii_domain: str = ""      # A-label (punycode) form used for DNS
    is_idn: bool = False
    smtputf8_local: bool = False
    is_role_account: bool = False
    checks: list[Check] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["checks"] = [asdict(c) for c in self.checks]
        return d


def _split(address: str) -> tuple[str, str] | None:
    """Split on the last unquoted '@'."""
    in_quote = False
    esc = False
    at = -1
    for i, ch in enumerate(address):
        if esc:
            esc = False
            continue
        if ch == "\\" and in_quote:
            esc = True
        elif ch == '"':
            in_quote = not in_quote
        elif ch == "@" and not in_quote:
            at = i
    if at <= 0 or at == len(address) - 1:
        return None
    return address[:at], address[at + 1:]


def validate_email_syntax(raw: str) -> SyntaxResult:
    address = (raw or "").strip()
    res = SyntaxResult(input=raw or "", valid=False)

    def check(name: str, ok: bool, detail: str, error: str | None = None) -> bool:
        res.checks.append(Check(name, ok, detail))
        if not ok and error:
            res.errors.append(error)
        return ok

    if not check("present", bool(address), "An address was supplied.", "No email address was supplied."):
        return res
    check("no_whitespace", not re.search(r"\s", address), "Address contains no whitespace.",
          "Email addresses cannot contain spaces or line breaks.")
    check("total_length", len(address) <= 254, f"Length {len(address)} of max 254 characters (RFC 5321 path limit).",
          "The address is longer than 254 characters.")

    parts = _split(address)
    if not check("single_at", parts is not None, "Exactly one unquoted '@' separates local part and domain.",
                 "The address must contain a local part, one '@' and a domain."):
        return res
    local, domain = parts  # type: ignore[misc]
    res.local_part = local

    # ── local part ──────────────────────────────────────────────────────────
    check("local_length", 1 <= len(local.encode("utf-8")) <= 64,
          f"Local part is {len(local.encode('utf-8'))} octets (max 64).", "The part before '@' exceeds 64 octets.")
    if local.startswith('"') and local.endswith('"') and len(local) >= 2:
        res.warnings.append("Quoted local parts are valid per RFC 5322 but are rejected by many mail systems.")
        check("local_chars", True, "Quoted-string local part.")
    else:
        atoms = local.split(".")
        dot_ok = all(atoms) and not local.startswith(".") and not local.endswith(".")
        check("local_dots", dot_ok, "No leading, trailing or consecutive dots in the local part.",
              "The local part has a leading, trailing or doubled dot.")
        ascii_ok = all(ATEXT.match(a) for a in atoms if a)
        if not ascii_ok:
            utf8_ok = all(a and all(ord(c) > 127 or ATEXT.match(c) for c in a) for a in atoms)
            if utf8_ok:
                res.smtputf8_local = True
                res.warnings.append("Non-ASCII local part requires SMTPUTF8 (RFC 6531) support on every hop.")
                check("local_chars", True, "Internationalised (SMTPUTF8) local part.")
            else:
                check("local_chars", False, "Local part contains only permitted characters.",
                      "The local part contains characters that are not allowed.")
        else:
            check("local_chars", True, "Local part uses only RFC 5322 atext characters.")

    # ── domain ──────────────────────────────────────────────────────────────
    if domain.startswith("[") and domain.endswith("]"):
        check("domain_literal", False, "Address literals ([IP]) are not analysable as mail domains.",
              "IP-address literal domains are not supported for identity analysis.")
        return _finish(res)
    domain = domain.rstrip(".")
    try:
        ascii_domain = idna.encode(domain, uts46=True).decode("ascii").lower()
        unicode_domain = idna.decode(ascii_domain)
        res.is_idn = ascii_domain != domain.lower() or "xn--" in ascii_domain
        check("idna", True, "Domain converts cleanly to IDNA A-labels." if res.is_idn else "ASCII domain.")
    except idna.IDNAError as exc:
        check("idna", False, f"IDNA conversion failed: {exc}", "The domain is not a valid (internationalised) host name.")
        return _finish(res)
    res.domain, res.ascii_domain = unicode_domain.lower(), ascii_domain
    labels = ascii_domain.split(".")
    check("domain_length", len(ascii_domain) <= 253, f"Domain is {len(ascii_domain)} characters (max 253).",
          "The domain is longer than 253 characters.")
    check("domain_labels", len(labels) >= 2, f"Domain has {len(labels)} labels (needs a name and a TLD).",
          "The domain needs at least a name and a top-level domain, e.g. example.com.")
    check("label_syntax", all(LABEL.match(lbl) for lbl in labels),
          "Each label is 1–63 letters, digits or hyphens, not starting or ending with a hyphen.",
          "A domain label is empty, too long or uses invalid characters/hyphen placement.")
    tld = labels[-1]
    check("tld", bool(tld) and not tld.isdigit() and len(tld) >= 2,
          f"Top-level domain '.{tld}' is alphabetic.", "The top-level domain is missing or numeric.")
    res.is_role_account = local.lower().split("+")[0] in ROLE_LOCAL_PARTS
    if res.is_role_account:
        res.warnings.append("This looks like a shared role mailbox (e.g. info@, support@) rather than a personal one.")
    return _finish(res)


def _finish(res: SyntaxResult) -> SyntaxResult:
    res.valid = all(c.passed for c in res.checks) and not res.errors
    if res.valid:
        res.normalized = f"{res.local_part}@{res.ascii_domain}".lower() if not res.smtputf8_local \
            else f"{res.local_part}@{res.ascii_domain}"
    else:
        res.normalized = res.input.strip().lower()[:320]
        if not res.domain and "@" in res.normalized:
            res.domain = res.normalized.rsplit("@", 1)[-1][:253]
            res.ascii_domain = res.domain
    return res
