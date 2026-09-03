# SecureWatch AI — Intelligent Endpoint Security & Investigation Platform

Endpoint monitoring + deterministic detection + RAG-grounded intelligence + orchestrated AI agents + historical incident correlation + explainable AI + SOC dashboard.

**Scope: authorized, defensive security monitoring only.** Detection and analysis only — the platform recommends investigation steps and never acts on an endpoint.

---

## What's in this repository

| Path | Contents |
|---|---|
| `docs/01-ARCHITECTURE.md` | Full system architecture, data flow, component diagram, database design, RAG pipeline, agent workflow, monitoring workflow, API design, tech-stack rationale, security mapping |
| `docs/02-IMPLEMENTATION-PHASES.md` | Phases 1–10: files to create, dependencies, APIs, DB changes, behavior, how to test, expected output |
| `docs/03-UI-DESIGN-SYSTEM.md` | UI design system, wireframes for every page, component inventory, animation strategy, responsive + a11y rules |
| `design-tokens.md` | Color palette, typography, spacing, radii, motion and breakpoint tokens (source of truth for `frontend/src/styles/tokens.css`) |
| `ui-prototype/` | **Working static HTML/CSS/JS visual prototype** of the whole UI with clearly-labelled demo data — open `ui-prototype/index.html` in a browser |
| `backend/` | FastAPI application skeleton (Phase 1 scaffold) |
| `agent/` | Endpoint monitoring agent skeleton |
| `frontend/` | React + TS + Vite + Tailwind app skeleton (Phase 9) |
| `deploy/`, `docker-compose.yml` | Container setup |

---

## Read this first

1. `docs/01-ARCHITECTURE.md` — understand the whole system before writing code.
2. `docs/02-IMPLEMENTATION-PHASES.md` — then build **Phase 1** only.
3. `ui-prototype/index.html` — the visual target for Phase 9.

---

## Quick start (VS Code)

```bash
# 1. open the folder
code securewatch-ai

# 2. install the recommended extensions when VS Code prompts
#    (Python, Ruff, Pylance, Tailwind CSS IntelliSense, ESLint, Prettier, Docker, REST Client)

# 3. backend env
python -m venv .venv
# Windows:  .venv\Scripts\activate      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill in the values

# 4. infrastructure (Postgres + Redis + Qdrant)
docker compose up -d postgres redis qdrant

# 5. migrations + seed, then run
alembic -c backend/alembic.ini upgrade head
python -m scripts.seed_demo
uvicorn backend.app.main:app --reload --port 8000     # http://localhost:8000/docs

# 6. UI prototype (no build step needed)
python -m http.server 5500 --directory ui-prototype   # http://localhost:5500

# 7. real frontend (from Phase 9 onward)
cd frontend && npm install && npm run dev             # http://localhost:5173
```

---

## Build order

| Phase | Deliverable |
|---|---|
| 1 | Foundation: app skeleton, DB models, migrations, auth + RBAC, audit log |
| 2 | Endpoint monitoring agent + ingest API |
| 3 | Deterministic detection engine (YAML rules, MITRE mapping) |
| 4 | Secure file upload + document processing pipeline |
| 5 | RAG: chunking, embeddings, Qdrant, hybrid search, rerank, citations |
| 6 | AI agents: LangGraph orchestration + guardrails + run traces |
| 7 | Historical incident intelligence (event embeddings, similarity, correlation) |
| 8 | AI security assistant (sourced RAG chat) |
| 9 | SOC dashboard in React, implementing the design system |
| 10 | Testing, security hardening, deployment |

---

## Non-negotiables

- **Provenance separation.** Raw telemetry, retrieved documents, historical SecureWatch data and AI-generated conclusions are stored, returned and displayed as distinct, labelled types.
- **Deterministic detection.** Rules create alerts and set a severity floor; the LLM explains and recommends, and can never lower that floor.
- **Authorization before monitoring.** No endpoint produces data until an admin has authorized it and an enrollment token has been accepted. The consent record is auditable.
- **Uploaded documents are untrusted input.** Sanitized, injection-screened, wrapped in an untrusted-content envelope, never executed, never granted tool access.
- **No response actions in v1.** `response/` exists as a permission-gated, unimplemented interface so the system cannot act on a host.
- **Demo data is always labelled.** Never present synthetic metrics as real.
