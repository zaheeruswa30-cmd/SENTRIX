# Sentrix — Email Identity Intelligence

Sentrix 2.0 module for assessing an email address and its domain: technical validity, mail infrastructure, sender-authentication configuration, abuse and reputation indicators, and **consent-based** mailbox ownership verification.

> **Validity is not identity.** Sentrix reports six separate layers and never treats a pass in one layer as a pass in the next. It never labels a person as fraudulent, untrustworthy or authentic from an email check.

| # | Layer | What a "pass" means | What it does **not** mean |
|---|---|---|---|
| 1 | Valid email syntax | The text is a well-formed address (RFC 5321/5322, IDN via `idna`) | That anything exists |
| 2 | Existing email domain | The domain resolves in public DNS | That it accepts mail |
| 3 | Configured mail infrastructure | MX (or implicit A/AAAA) exists; no null MX (RFC 7505) | That this mailbox exists. Sentrix never probes mailboxes (no SMTP `RCPT TO`) |
| 4 | SPF / DKIM / DMARC configuration | The domain owner published sender-authentication records | That a given message passed authentication |
| 5 | Verified mailbox ownership | Someone completed a one-time challenge sent to that inbox | Who that person is |
| 6 | Real-world identity | **Never assessed** by Sentrix | — |

**DKIM:** finding a DKIM public key at `<selector>._domainkey.<domain>` (`selector_found`) shows only that a key is published. A message passed DKIM only when an analyst pastes the **raw message with headers** into *Verify a message (DKIM)*, and Sentrix verifies the signature with `dkimpy` (`POST /email-identity/dkim/verify`).

---

## Navigation

**Email Identity Intelligence** in the sidebar:

| Section | Route | Purpose |
|---|---|---|
| Email Verification | `#/email-verification` | Dashboard: email, domain, syntax, DNS, MX, SPF, DKIM, DMARC, disposable, ownership, risk, findings, last checked. Filters: all / verified / unverified / invalid / suspicious / pending. Single and bulk checks |
| Domain Intelligence | `#/email-domain`, `#/email-domain/<domain>` | Per-domain DNS, MX, auth, disposable/free-provider, look-alike indicators, optional RDAP/DNSBL enrichment; organisation threat-intel indicators |
| Email Authentication | `#/email-auth` | SPF/DKIM/DMARC lookup results with raw records, parsed tags, issues and explanations; DKIM message verification |
| Ownership Verification | `#/email-ownership` | Challenge status, attempts, sends, verification timestamps |
| Email Risk Analysis | `#/email-risk` | Band distribution, highest-risk records, most common findings, scoring method |
| Investigation History | `#/email-history` | Cases, reports and knowledge entries, checks, verification audit trail |

The record page (`#/email-record/<id>`) shows the validity ladder, the risk assessment, findings with evidence and confidence, DNS and auth detail, the ownership state and the audit trail. Its actions are: re-run checks, start ownership verification, verify a message (DKIM), ask Sentrix AI, add to the knowledge base, download a PDF report, and create an incident or investigation case.

The public page `#/verify-email?token=…` is where recipients confirm ownership. The token is removed from the address bar immediately and sent to the backend in a POST body.

---

## Checks (backend `services/email_identity/`)

| Module | Responsibility |
|---|---|
| `syntax.py` | Syntax validation, normalisation, IDN handling, role-address detection, domain extraction |
| `dns_client.py` | `dnspython` resolver with timeouts; optional DNS-over-HTTPS (`DNS_RESOLVER=doh`) and automatic DoH fallback when the system resolver is blocked |
| `mail_infra.py` | A/AAAA/NS resolution, NXDOMAIN detection, MX lookup, null-MX, implicit MX |
| `auth_records.py` | SPF (single record, `all` qualifier, lookup-count estimate, `+all`/`?all`), DMARC (`p`, `sp`, `pct`, `rua`), DKIM selector discovery over `DKIM_COMMON_SELECTORS` plus user-supplied selectors |
| `dkim_verify.py` | Real DKIM signature verification of a supplied raw message |
| `reputation.py` | Disposable list (`backend/app/data/disposable_domains.txt`, CC0), free-provider list, optional RDAP domain age, optional DNSBL |
| `suspicious.py` | Look-alike / homoglyph / punycode / brand-in-subdomain checks against `PROTECTED_BRAND_DOMAINS`, risky TLDs |
| `risk_engine.py` | Explainable scoring (below) |
| `ownership.py` | Token lifecycle |
| `investigation.py` | Cases → incidents, knowledge-base entries, reports |
| `service.py` | Orchestration, domain-analysis cache (`DOMAIN_CACHE_HOURS`), audit logging |

Domain results are cached per tenant in `email_domain_analyses` with `expires_at`. Re-running a check refreshes them.

---

## Risk engine (`sentrix-eri-1.2`)

- Every point is a **finding**: code, category, layer, title, evidence, impact, confidence, severity and recommendation. There are no hidden factors.
- Score 0–100 → band: **low** 0–19 · **guarded** 20–44 · **elevated** 45–69 · **high** 70–100.
- **Technical failures alone cannot reach "high".** Reaching it requires corroborating threat-intelligence, abuse, reputation or impersonation evidence; otherwise the score is capped at 69.
- Missing data (lookups disabled or timed out) lowers **confidence**, not the score.
- Verified ownership lowers the score. A failed check never labels a person.
- Inputs: syntax, DNS/MX, SPF/DKIM/DMARC posture, disposable and free-provider status, look-alike indicators, organisation threat-intel matches (`threat_indicators`), analyst abuse reports, RDAP age and DNSBL (when enabled), and ownership status.

"Suspicious" means band elevated/high, or any threat-intel/impersonation finding. In that case analysts can **Create incident / case**: an `incidents` row (source `email_identity`) linked to the record and its evidence. Optionally, a notification goes to `INCIDENT_NOTIFY_EMAIL`.

---

## Ownership verification

1. An analyst confirms they are authorised to contact the address (`consent: true` is required and recorded).
2. The backend generates a 256-bit link token (`secrets.token_urlsafe(32)`) and a 6-digit code (`secrets.randbelow`).
3. Only **HMAC-SHA256 digests** (keyed with `SECRET_KEY`) are stored in `email_ownership_tokens`. Plain values exist only in the outgoing email and are never returned by the API or written to logs.
4. The email is sent through `EMAIL_PROVIDER` (`dev_outbox` → `outbox/*.eml`, `smtp`, `sendgrid`), using Sentrix-branded HTML and text templates.
5. The recipient opens `{PUBLIC_BASE_URL}/#/verify-email?token=…` or gives the code to the analyst.
6. Limits:
   - `OWNERSHIP_TOKEN_TTL_MINUTES` expiry (default 15)
   - `OWNERSHIP_MAX_ATTEMPTS` wrong codes per challenge (default 5) → locked
   - `OWNERSHIP_MAX_SENDS_PER_DAY` per address (default 5)
   - `OWNERSHIP_RESEND_COOLDOWN_SECONDS` (default 60)
   - starting a new challenge revokes the previous one
   - comparisons are constant-time
7. On success the record becomes `ownership_status=verified`, with `ownership_method` (link/code) and `ownership_verified_at`. Every step is written to `email_verification_audit_logs` and the platform `audit_log`, and the risk score is recomputed.

---

## Data model (migration `0002_email_identity`)

| Table | Model | Notes |
|---|---|---|
| `email_verification_records` | `EmailVerificationRecord` | Unique `(tenant_id, email)`; CHECK constraints on every status column; `risk_score` 0–100; indexes on checked time, domain, ownership, risk |
| `email_domain_analyses` | `DomainAnalysis` | Unique `(tenant_id, domain)`; `analyzed_at`, `expires_at` (cache) |
| `email_dns_auth_results` | `DnsAuthenticationResult` | One row per SPF/DKIM/DMARC lookup; raw records, parsed tags, issues |
| `email_ownership_tokens` | `OwnershipVerificationToken` | Hashes only; unique link hash; `attempts >= 0`; `expires_at`, `status` (active/consumed/expired/revoked/locked) |
| `email_risk_assessments` | `EmailRiskAssessment` | Score/confidence 0–100, band, findings JSON, engine version — history kept per check |
| `email_investigation_reports` | `EmailInvestigationReport` | Cases, PDF reports (SHA-256 recorded), knowledge entries |
| `email_verification_audit_logs` | `VerificationAuditLog` | Who / what / when / IP / user agent per record |

Every table carries `tenant_id` with a foreign key to `tenants`, and all queries are tenant-scoped. Expired tokens are swept on access and by `ownership.expire_all()`.

---

## API (`/api/v1`, JWT bearer, roles: viewer < analyst < admin)

| Method | Path | Role |
|---|---|---|
| GET | `/email-identity/stats` | viewer |
| GET / POST | `/email-identity/records` (`filter`, `q`, `domain`) | viewer / analyst |
| POST | `/email-identity/records/bulk` | analyst |
| GET / DELETE | `/email-identity/records/{id}` | viewer / admin |
| POST | `/email-identity/records/{id}/recheck` | analyst |
| GET | `/email-identity/domains`, `/email-identity/domains/{domain}` | viewer |
| POST | `/email-identity/domains/analyze` | analyst |
| GET | `/email-identity/auth-results` | viewer |
| POST | `/email-identity/dkim/verify` | analyst |
| GET | `/email-identity/ownership`, `/email-identity/records/{id}/ownership` | viewer |
| POST | `/email-identity/records/{id}/ownership/start` · `/resend` · `/verify` | analyst |
| POST | `/email-identity/ownership/confirm` (public, token in body) | — |
| GET | `/email-identity/records/{id}/audit`, `/email-identity/history` | viewer |
| GET | `/email-identity/audit` | analyst |
| POST | `/email-identity/records/{id}/incident`, `/email-identity/records/{id}/knowledge` | analyst |
| GET | `/email-identity/records/{id}/report.pdf`, `/email-identity/report/summary.pdf` | viewer |
| GET / PATCH | `/incidents`, `/incidents/{id}` | viewer / analyst |
| GET / POST / DELETE | `/threat-intel/indicators` | viewer / analyst |
| GET | `/audit-logs` | analyst |
| GET / POST | `/knowledge/search`, `/knowledge/documents` | viewer / analyst |
| POST | `/ai/email/ask` | viewer |
| GET | `/reports`, `/reports/{id}/download` | viewer |

Full schemas are in the OpenAPI UI at `/api/docs`.

---

## Sentrix AI and RAG

`POST /ai/email/ask` (`services/ai/email_assistant.py`) answers questions such as "Is this email address technically valid?", "Which authentication records are missing?" or "Why did this email fail verification?".

1. It loads the referenced record (tenant-scoped).
2. It retrieves passages from the tenant knowledge base (`services/knowledge/rag.py`, BM25-style lexical ranking over `document_chunks`). The base is seeded with SPF, DKIM, DMARC, disposable-domain, ownership and "validity vs identity" guides, plus investigation history and saved findings.
3. It builds a deterministic, evidence-linked answer with sections for: what is established, what is not, auth gaps, recommended steps, citations (record fields, DNS lookups, KB chunks) and the six-layer distinction.

If `LLM_PROVIDER=ollama|openai` is configured, an LLM may rephrase the answer using only the retrieved evidence. The guardrails and citations are kept either way. The assistant never claims a person is authentic.

The Assistant page sends email-related questions to this endpoint; endpoint questions stay on the client-side demo engine. Use **Ask Sentrix AI** on a record to open the assistant with that record as context.

---

## Privacy and authorised use

- Only DNS lookups and opt-in public enrichment are used. No mailbox probing, no SMTP enumeration, no scraping of personal data.
- Ownership challenges require recorded analyst consent and are rate-limited per address and per tenant.
- `EMAIL_CHECKS_PER_HOUR` caps checks per tenant.
- Records can be deleted by admins; the deletion is audited.
