# Sentrix

**Sentrix — Intelligent Security Operations, Threat Detection and Digital Identity Intelligence Platform.**

Sentrix 2.0 is the rebranded successor of SecureWatch AI. It keeps the endpoint-security console (monitoring, deterministic detection, RAG intelligence, AI agents, incident correlation) and adds a full-stack **Email Identity Intelligence** module.

**Scope: authorized, defensive security work only.** Sentrix recommends investigation steps and never acts on an endpoint, mailbox or person.

---

## Quick start (VS Code)

```bash
# 1. unzip, then open the folder
code sentrix

# 2. create a virtual environment (VS Code detects .venv automatically; if asked, pick ".venv" as the interpreter)
python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1     Windows (cmd):  .venv\Scripts\activate
# macOS / Linux:         source .venv/bin/activate

# 3. install dependencies
pip install -r requirements.txt

# 4. configuration
cp .env.example .env          # Windows: copy .env.example .env

# 5. run (SQLite by default — no Docker needed)
uvicorn backend.app.main:app --reload --port 8000
```

Open **http://localhost:8000** for the app and **http://localhost:8000/api/docs** for the interactive API docs.

On first start the schema is created automatically and demo data is seeded (`SEED_DEMO_DATA=true`). The same commands exist as VS Code tasks (Terminal › Run Task…) and launch configurations (Run and Debug › "Sentrix API").

### Demo accounts (organisation "Sentrix Demo SOC")

| Role | Email | Password |
|---|---|---|
| Admin | `admin@sentrix.local` | `Admin1234!` |
| Analyst | `analyst@sentrix.local` | `Demo1234!` |
| Viewer | `viewer@sentrix.local` | `Viewer1234!` |

The old `@securewatch.local` addresses still work and are mapped to the new ones. Use **Create account** on the sign-in page to register your own organisation; you become its Admin.

### Other useful commands

```bash
pytest                                            # backend test suite
alembic -c backend/alembic.ini upgrade head       # apply migrations (staging/production; set AUTO_CREATE_SCHEMA=false)
python -m scripts.seed_demo --with-checks         # re-seed demo tenant + run sample email checks
docker compose up -d                              # Postgres + Mailpit + API in containers
```

### Sending real verification emails

By default `EMAIL_PROVIDER=dev_outbox`: ownership-verification messages are written as `.eml` files to `outbox/` and **not** sent. To deliver them:

- **SMTP** — set `EMAIL_PROVIDER=smtp` and the `SMTP_*` variables. `docker compose up -d mailpit` gives you a local catcher at http://localhost:8025 (SMTP on port 1025).
- **SendGrid** — set `EMAIL_PROVIDER=sendgrid` and `SENDGRID_API_KEY`.

Secrets belong in `.env` only (it is git-ignored).

---

## What is real and what is demo

| Area | Implementation |
|---|---|
| Sign-in, registration, organisations, roles | FastAPI backend (JWT, Argon2 password hashes, tenant isolation) |
| **Email Identity Intelligence** (all six sections) | FastAPI backend — live DNS/MX/SPF/DKIM/DMARC lookups, disposable-domain list, risk engine, ownership tokens, audit trail |
| Incidents created from email records, threat-intel indicators, audit log | Backend |
| Email PDF reports, email-security knowledge base, Sentrix AI email answers | Backend |
| Endpoint telemetry, detection rules, endpoint agent pipeline, endpoint RAG documents | Client-side demo on synthetic data (clearly labelled **DEMO DATA**) |

Optional enrichment is off by default: `ENRICHMENT_RDAP_ENABLED` (domain registration age via RDAP) and `ENRICHMENT_DNSBL_ENABLED` (domain blocklist lookup). Enable them only where your usage terms allow.

---

## Repository layout

| Path | Contents |
|---|---|
| `backend/app/` | FastAPI app: `core/` (config, security), `db/`, `models/`, `api/v1/`, `services/` (email identity, knowledge/RAG, AI assistant, reports, mail delivery) |
| `backend/alembic/` | Database migrations (`0001` foundation, `0002` email identity) |
| `backend/tests/` | Pytest suite |
| `backend/app/data/disposable_domains.txt` | Disposable email domain list (see licence note below) |
| `scripts/seed_demo.py` | Demo tenant, users, threat-intel indicators, knowledge base |
| `ui-prototype/` | The Sentrix web app (vanilla JS SPA, served by the API at `/`) |
| `docs/` | Architecture, implementation phases, UI design system, **04 Email Identity Intelligence** |
| `design-tokens.md` | Colour, type, spacing and motion tokens (v2 Sentrix palette) |
| `deploy/`, `docker-compose.yml` | Container setup |
| `.vscode/` | Recommended extensions, tasks, debug configs |

Internal identifiers such as the `SW` JavaScript namespace, `SW-R###` rule IDs, the Postgres database/user `securewatch` and the compose project name `securewatch-ai` are kept on purpose so existing data, volumes and integrations keep working.

---

## Read next

1. `docs/04-EMAIL-IDENTITY-INTELLIGENCE.md` — the new module: checks, risk engine, ownership flow, data model, API.
2. `docs/01-ARCHITECTURE.md` — overall system architecture.
3. `docs/03-UI-DESIGN-SYSTEM.md` and `design-tokens.md` — the Sentrix visual language.

---

## Non-negotiables

- **Provenance separation.** Raw telemetry, retrieved documents, historical Sentrix data and AI-generated conclusions are stored, returned and displayed as distinct, labelled types.
- **Deterministic detection.** Rules create alerts and set a severity floor; the LLM explains and recommends, and can never lower that floor.
- **Validity is not identity.** Valid syntax, an existing domain, configured mail infrastructure, SPF/DKIM/DMARC authentication, verified mailbox ownership and real-world identity are separate claims. Sentrix never labels a person as fraudulent or authentic from an email check.
- **Secrets never leave the backend.** Verification tokens are stored only as HMAC-SHA256 digests and never appear in API responses or logs.
- **Demo data is always labelled.** Synthetic metrics are never presented as real.

## Third-party data

`backend/app/data/disposable_domains.txt` comes from the [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) project ([source list](https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf)), released under CC0 1.0 (public domain).
