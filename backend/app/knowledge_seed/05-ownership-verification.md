# Mailbox ownership verification

Ownership verification confirms that the person who submitted an address can read mail delivered to it.

## How Sentrix performs it
1. An authorised analyst confirms that sending a message to the address is permitted for the stated purpose.
2. The backend generates a cryptographically secure link token and a 6-digit code. Only HMAC-SHA256 hashes are stored; the raw values exist only in the outgoing message.
3. The challenge expires (default 15 minutes) and allows a limited number of attempts (default 5). Resends are rate-limited (cooldown and a daily cap).
4. The recipient clicks the link or the analyst enters the code the recipient reads back. Success records the method and timestamp.
5. Every step is written to the verification audit log and the security audit log, without tokens or codes.

## What it proves and what it does not
Verified ownership proves control of the mailbox at that moment. It does not prove the person's real-world identity, does not prove the domain is reputable, and can become stale if the mailbox changes hands.

## Why verification can fail
- The address is not deliverable (invalid syntax, non-existent domain, no mail infrastructure).
- The challenge expired before use.
- Too many incorrect codes locked the challenge.
- The message was filtered as spam or not delivered by the provider.
- The email delivery provider is not configured.
