"""Suspicious-domain heuristics. Every indicator carries evidence and a confidence value.

These are *indicators for analyst review*, not verdicts. Many legitimate domains trip one weak
heuristic (e.g. a hyphenated company name), which is why each carries an honest confidence.
"""
from __future__ import annotations

import math
import unicodedata
from collections import Counter

import re

import idna

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
WEAK_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest",
             "cam", "monster", "quest", "support", "loan", "bid"}
LURE_WORDS = {"secure", "login", "verify", "account", "update", "billing", "support", "signin", "auth",
              "wallet", "payment", "service", "helpdesk", "recovery", "unlock", "confirm"}


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                pass
    return out


def find_indicators(ascii_domain: str, protected: list[str], age_days: int | None = None) -> list[dict]:
    ind: list[dict] = []
    d = ascii_domain.lower()
    labels = d.split(".")
    sld = labels[-2] if len(labels) >= 2 else d
    tld = labels[-1]

    def add(code: str, title: str, evidence: str, confidence: int, weight: int) -> None:
        ind.append({"code": code, "title": title, "evidence": evidence, "confidence": confidence, "weight": weight})

    # Brand impersonation / look-alike
    tokens_all = [t for t in re.split(r"[-.]", d) if t]
    sld_tokens = [t for t in sld.split("-") if t] or [sld]
    for brand in protected:
        if d == brand or d.endswith("." + brand):
            continue
        b_sld = brand.split(".")[0]
        hit = False
        for tok in dict.fromkeys([sld] + sld_tokens):
            norm = tok.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
            dist = _lev(tok, b_sld)
            where = "" if tok == sld else f" (label part '{tok}' of '{sld}')"
            if norm == b_sld and tok != b_sld:
                add("brand_homoglyph", f"Look-alike of {brand}", f"'{tok}' becomes '{b_sld}' after undoing character "
                    f"substitutions (0→o, 1→l, rn→m…){where}.", 85, 30)
                hit = True
            elif 0 < dist <= (1 if len(b_sld) <= 5 else 2) and len(b_sld) >= 4 and len(tok) >= 4:
                add("brand_typosquat", f"Possible typosquat of {brand}", f"'{tok}' is {dist} edit(s) away from "
                    f"'{b_sld}'{where}.", 70, 25)
                hit = True
            if hit:
                break
        if not hit and b_sld in d and len(b_sld) >= 5:
            lure = set(tokens_all) & LURE_WORDS
            add("brand_embedded", f"Contains the brand '{b_sld}'",
                f"'{d}' embeds '{b_sld}' but is not {brand}" + (f"; lure words: {', '.join(sorted(lure))}" if lure else "") + ".",
                75 if lure else 50, 22 if lure else 12)
    # IDN / mixed scripts
    if "xn--" in d:
        try:
            uni = idna.decode(d)
            scripts = _scripts(uni)
            if len(scripts - {"DIGIT"}) > 1:
                add("idn_mixed_script", "Mixed-script internationalised domain",
                    f"'{uni}' mixes scripts {sorted(scripts)} — a common homograph technique.", 80, 22)
            else:
                add("idn", "Internationalised domain name", f"Displayed as '{uni}'. Legitimate for many languages; "
                    "check it is the domain the user expects.", 30, 4)
        except idna.IDNAError:
            add("idn_invalid", "Malformed punycode label", f"'{d}' contains an undecodable xn-- label.", 70, 15)
    # Structure
    if sld.count("-") >= 3:
        add("many_hyphens", "Many hyphens in domain name", f"'{sld}' contains {sld.count('-')} hyphens.", 40, 6)
    digits = sum(ch.isdigit() for ch in sld)
    if len(sld) >= 8 and digits / len(sld) > 0.4:
        add("digit_heavy", "Digit-heavy domain name", f"{digits} of {len(sld)} characters in '{sld}' are digits.", 35, 5)
    if len(sld) >= 12 and _entropy(sld) > 3.6 and not any(w in sld for w in LURE_WORDS):
        add("random_looking", "Random-looking domain label", f"'{sld}' has high character entropy ({_entropy(sld):.2f} bits).", 35, 6)
    if len(labels) >= 5:
        add("deep_subdomain", "Deeply nested subdomain", f"{len(labels)} labels in '{d}'.", 30, 4)
    if tld in WEAK_TLDS:
        add("abused_tld", f"Frequently abused TLD .{tld}", f"'.{tld}' appears disproportionately in abuse reports. Weak "
            "signal on its own — many legitimate sites use it.", 25, 4)
    if age_days is not None:
        if age_days < 30:
            add("new_domain", "Newly registered domain", f"Registered {age_days} day(s) ago (RDAP).", 75, 20)
        elif age_days < 180:
            add("young_domain", "Recently registered domain", f"Registered {age_days} days ago (RDAP).", 45, 8)
    return ind
