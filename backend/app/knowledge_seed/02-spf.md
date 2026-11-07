# SPF (Sender Policy Framework) — RFC 7208

SPF lets a domain publish which hosts may send mail using the domain in the SMTP envelope sender (MAIL FROM / Return-Path).

## Record format
A single TXT record at the domain beginning with `v=spf1`, for example `v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all`.

## Common problems
- Missing record: receivers cannot evaluate SPF; spoofing of the envelope sender is easier.
- Multiple `v=spf1` records: this is a permanent error (permerror); merge them into one record.
- More than 10 DNS-querying mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`): permerror. Flatten includes or remove unused services.
- `+all` or `?all`: the record authorises or does not judge every host on the internet, which provides no protection.
- `~all` (softfail) is common during rollout; `-all` (fail) is the strict end state.

## Remediation
1. Inventory every service that sends mail for the domain.
2. Publish one record that lists them, ending with `~all`, then move to `-all` once DMARC reports confirm coverage.
3. Keep the lookup count at 10 or below.

SPF passing for a message does not prove the visible From address is authentic; DMARC alignment is required for that.
