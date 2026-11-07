# DMARC — RFC 7489

DMARC tells receivers what to do with mail whose visible From domain fails authentication, and requires that SPF or DKIM pass with a domain aligned to the From domain.

## Record format
A TXT record at `_dmarc.<domain>`, for example `v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=r`.

## Policies
- `p=none`: monitoring only; spoofed mail is still delivered.
- `p=quarantine`: failing mail goes to spam / quarantine.
- `p=reject`: failing mail is refused. This is the strongest protection.
- `pct` below 100 applies the policy only to a share of failing mail.
- Subdomains inherit the organisational domain policy unless `sp=` overrides it.

## Common problems
- No DMARC record: the domain is easier to impersonate.
- `p=none` left in place indefinitely.
- No `rua` reporting address, so the owner cannot see who sends as the domain.

## Remediation path
Publish `p=none` with `rua` reporting, fix SPF/DKIM coverage for legitimate senders using the reports, then move to `quarantine` and finally `reject`.
