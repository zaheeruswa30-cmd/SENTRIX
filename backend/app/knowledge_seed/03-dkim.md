# DKIM (DomainKeys Identified Mail) — RFC 6376

DKIM adds a cryptographic signature to outgoing messages. Receivers fetch the public key from DNS at `<selector>._domainkey.<domain>` and verify the signature over selected headers and the body.

## Discovery versus verification
Finding a DKIM public-key record in DNS only shows that the domain has published a key for a selector. It does NOT prove that any particular message passed DKIM verification. A message passes DKIM only when its actual DKIM-Signature header verifies against the published key. Sentrix verifies DKIM signatures only when an analyst supplies the raw message (.eml) with its headers.

## Selectors
Selectors are chosen by the sender and are not discoverable by enumeration. Sentrix probes a list of common selectors (for example `google`, `selector1`, `selector2`, `k1`, `s1`, `default`); "no selector found" means only that none of the probed names exist, not that DKIM is absent.

## Common problems
- Revoked key (`p=` empty).
- Short RSA keys (under 1024 bits are insecure; 2048 bits recommended).
- Signing domain (`d=`) not aligned with the From domain, so DMARC cannot use the DKIM result.

## Remediation
Enable DKIM signing in every sending platform, publish the selector records the platform provides, use 2048-bit keys and rotate them periodically.
