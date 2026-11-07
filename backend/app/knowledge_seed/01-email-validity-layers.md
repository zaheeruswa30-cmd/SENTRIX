# Email validity layers — what each check proves

Sentrix evaluates an email address in separate layers. Each layer answers a different question, and passing one layer never implies the next.

## Valid email syntax
The address is well-formed according to RFC 5321/5322 (local part, a single @, a domain with valid labels, length limits). Syntax validity says nothing about whether the domain exists or whether mail can be delivered.

## Existing email domain
The domain resolves in public DNS (it is not NXDOMAIN). A domain can exist and still be unable to receive mail.

## Configured email infrastructure
The domain publishes MX records (or, if none, an A/AAAA record used as an implicit MX per RFC 5321 section 5.1). A "null MX" (`0 .`, RFC 7505) explicitly declares that the domain accepts no mail. Sentrix never connects to mail servers to probe whether an individual mailbox exists (no SMTP RCPT probing), because such probing is unreliable and can be abusive.

## SPF / DKIM / DMARC authentication
These are anti-spoofing controls published by the domain owner. They protect recipients against forged mail that claims to come from the domain. They describe the domain's configuration, not the person using an address.

## Verified mailbox ownership
The submitter proved they can read mail delivered to the address by completing a one-time challenge (link or code). This is the only layer that relates to control of the specific mailbox.

## Real-world identity
No email check — including ownership verification — establishes who a person is. Real-world identity requires a separate identity-proofing process (for example document verification or in-person checks). Sentrix never claims a person is authentic, fraudulent or untrustworthy based on an email address.
