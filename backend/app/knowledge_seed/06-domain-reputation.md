# Domain reputation and suspicious domain indicators

## Signals Sentrix uses
- Disposable / temporary email domains (CC0 community blocklist, disposable-email-domains project).
- Newly registered domains, from RDAP registration dates (optional, opt-in enrichment).
- Domain blocklists (DNSBL such as the Spamhaus DBL; optional, opt-in, subject to the provider's usage terms).
- Lookalike indicators: punycode / mixed scripts, edit-distance similarity to protected brands configured by the organisation, brand names embedded in other domains, excessive hyphens or digits, high-entropy labels.
- Tenant threat intelligence: indicators added by analysts, abuse reports and feeds.

## Interpreting signals
Each signal carries evidence and a confidence level. A single weak signal (for example a free mail provider or a role account) is context, not a judgement. Free providers are used by many legitimate people. Sentrix caps scores from technical signals alone and requires corroboration (such as a threat-intelligence match) before rating an address high risk. Risk scores describe technical indicators about an address and domain; they never classify a person as fraudulent or untrustworthy.
