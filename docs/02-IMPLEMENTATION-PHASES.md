# SecureWatch AI — Implementation Phases

Each phase is independently runnable and demoable. Do not start a phase before its predecessor's tests pass.
Conventions: backend package root is `backend/app/`, migrations via `alembic revision --autogenerate -m "..."`, every phase ends with `pytest -q` green and a manual smoke check.

---

## Phase 1 — Foundation, database, auth

**Files**
```
backend/app/main.py                 FastAPI app, routers, middleware, CORS, security headers
backend/app/core/config.py          pydantic-settings Settings (env-driven)
backend/app/core/security.py        argon2 hashing, JWT encode/decode, token scopes
backend/app/core/deps.py            get_db, get_current_user, require_role(...)
backend/app/core/logging.py         structlog JSON config + secret redaction
backend/app/core/audit.py           write_audit(actor, action, object, before, after)
backend/app/db/base.py, session.py  SQLAlchemy 2.0 engine/session
backend/app/models/{user,endpoint,event,incident,document,audit,token}.py
backend/app/schemas/{user,auth,common}.py
backend/app/api/v1/{router.py,auth.py,users.py,health.py}
backend/alembic/…                   migration env + 0001_initial
backend/tests/{conftest.py,test_auth.py,test_rbac.py,test_audit.py}
docker-compose.yml                  api, worker, postgres, redis, qdrant
.env.example, requirements.txt, Makefile, README.md
```
**Dependencies** `fastapi uvicorn[standard] pydantic pydantic-settings sqlalchemy alembic psycopg[binary] passlib[argon2] python-jose[cryptography] python-multipart structlog pyotp pytest pytest-asyncio httpx factory-boy`
**APIs** `POST /auth/login|refresh|logout`, `GET /auth/me`, `POST /auth/mfa/verify`, `GET|POST /users` (admin), `GET /healthz|/readyz`
**DB** all core tables created (see architecture §5); `users`, `api_tokens`, `audit_log` fully wired.
**Behavior** A user can log in, receive a JWT, hit a role-protected route; unauthorized roles get 403; every mutation appears in `audit_log`.
**How to test** `pytest backend/tests -q`; then `curl -X POST :8000/api/v1/auth/login -d 'username=admin@local&password=...'` → token; call `/users` as `viewer` → 403. Check `docker compose logs api` shows JSON logs with no secrets.
**Expected output** `docker compose up` yields healthy api/postgres/redis/qdrant, Swagger at `/docs`, seeded admin user, `audit_log` populating.

---

## Phase 2 — Endpoint monitoring & ingest

**Files**
```
agent/securewatch_agent/{__main__.py,config.py,transport.py,spool.py,normalizer.py,redaction.py,enroll.py}
agent/securewatch_agent/collectors/{base.py,inventory.py,process.py,filewatch.py,auth_windows.py,auth_linux.py,network.py}
agent/agent.example.yaml, agent/requirements.txt, agent/install/{systemd,windows-service}/…
backend/app/api/v1/{ingest.py,endpoints.py}
backend/app/services/{endpoint_service.py,ingest_service.py,liveness.py}
backend/app/schemas/{event.py,endpoint.py,ingest.py}
backend/app/workers/liveness_job.py   (RQ scheduled: mark degraded/offline)
backend/tests/{test_ingest.py,test_endpoint_auth.py}; agent/tests/test_collectors.py
```
**Dependencies** agent: `psutil watchdog httpx pyyaml keyring` (+ `pywin32` on Windows); backend: `redis rq`
**APIs** `POST /ingest/enroll`, `POST /ingest/events` (batch + `Idempotency-Key`), `POST /ingest/heartbeat`, `GET|POST /endpoints`, `GET /endpoints/{id}`, `POST /endpoints/{id}/rotate-token`, `DELETE /endpoints/{id}`
**DB** `endpoints` (authorization + enrollment + liveness columns), `events` (+ `dedupe_key` unique, indexes), `api_tokens` scope `agent_ingest`.
**Behavior** Admin authorizes an endpoint → enrollment token → agent enrolls, then streams normalized process/file/auth/network/inventory events; offline agents spool locally and backfill; revoking the token immediately stops ingest (401).
**How to test** unit-test each collector against fixtures; run the agent on your own machine, `touch` a watched path and open a process → events appear in `GET /events`; kill the network for 60 s → spool grows → reconnect → backfill with no duplicates (same `dedupe_key`); stop the agent → status flips `degraded` → `offline`.
**Expected output** Live event stream from at least one real endpoint, visible via API, with a durable offline path and an auditable authorization record.

---

## Phase 3 — Security event detection

**Files**
```
backend/app/detection/{engine.py,loader.py,operators.py,correlation.py,scoring.py}
backend/app/detection/rules/{process.yaml,auth.yaml,file.yaml,network.yaml,persistence.yaml}
backend/app/models/detection.py; backend/app/schemas/detection.py
backend/app/api/v1/rules.py
backend/app/workers/detect_job.py
backend/tests/{test_detection_rules.py,test_correlation.py}; backend/tests/fixtures/golden_events.jsonl
```
**Dependencies** `pyyaml jsonschema` (no new heavy deps)
**APIs** `GET|POST /rules`, `PATCH /rules/{id}`, `POST /rules/{id}/test` (dry-run over historical events), `GET /events?rule=`, `POST /events/{id}/suppress`
**DB** `detection_rules`, `detections`; `events.status` transitions to `detected`.
**Behavior** Deterministic evaluation on ingest: field matches, regex, allow/deny lists, thresholds and time-window correlation (e.g. ≥5 failed logins in 5 min from one source; encoded PowerShell command line; unsigned binary written to a system temp path then executed). Each hit writes a `detection` with `severity_floor`, `matched_fields` and MITRE technique ids.
**How to test** replay `golden_events.jsonl` → assert expected `rule_id`/severity per event; assert benign fixtures produce zero detections (false-positive guard); `POST /rules/{id}/test` returns counts without writing.
**Expected output** Reproducible, explainable alerts with rule provenance, tunable via YAML without code changes.

---

## Phase 4 — File upload & document processing

**Files**
```
backend/app/api/v1/documents.py
backend/app/documents/{validator.py,extractors/{pdf.py,docx.py,text.py,markdown.py},sanitizer.py,injection_screen.py,pipeline.py,storage.py}
backend/app/models/document.py (documents, document_chunks); backend/app/schemas/document.py
backend/app/workers/document_job.py
backend/tests/{test_upload_validation.py,test_extraction.py,test_sanitizer.py,test_injection_screen.py}
backend/tests/fixtures/docs/{policy.pdf,report.docx,notes.md,injected.pdf,encrypted.pdf,huge.pdf,fake.pdf.exe}
```
**Dependencies** `pymupdf python-docx markdown-it-py chardet python-magic tiktoken` (optional `clamd`)
**APIs** `POST /documents` (multipart), `GET /documents`, `GET /documents/{id}` (lifecycle status), `DELETE /documents/{id}`, `POST /documents/{id}/reindex`
**DB** `documents` (status enum, sha256 unique, classification, injection_flags), `document_chunks`.
**Behavior** Upload → validate (magic bytes, size/page caps, allowlist, dedupe) → store outside web root under a UUID name → async extract per page → sanitize (unicode NFKC, zero-width/invisible/off-page text removed) → injection screening writes `injection_flags` → chunk with breadcrumbs → status advances `uploaded → extracting → chunking → ready`. Malicious/undecodable files land in `quarantined` or `failed` with a reason.
**How to test** upload each fixture: `fake.pdf.exe` → 400; `encrypted.pdf` → failed with reason; `injected.pdf` → indexed but `injection_flags` non-empty and chunks marked suspicious; `policy.pdf` → correct `page_count`/`chunk_count`, and chunk text carries `[doc · §section · p.N]`. Re-upload the same file → 409 dedupe.
**Expected output** A real, observable document lifecycle with page-accurate text ready for embedding — and hostile files rejected.

---

## Phase 5 — RAG pipeline & vector database

**Files**
```
backend/app/rag/{embeddings.py,vectorstore.py,chunker.py,retriever.py,reranker.py,hybrid.py,query_builder.py,citations.py}
backend/app/api/v1/rag.py
backend/app/workers/embed_job.py
scripts/{reindex.py,eval_retrieval.py}
backend/tests/{test_chunker.py,test_retriever.py,test_rag_eval.py}; backend/tests/fixtures/rag_golden.yaml
```
**Dependencies** `sentence-transformers qdrant-client FlagEmbedding torch --index-url cpu` (optional `openai`)
**APIs** `POST /rag/search`, `GET /rag/stats`, `POST /documents/{id}/reindex`
**DB** `document_chunks.vector_id` populated; Qdrant `kb_chunks` collection (dense 1024 + sparse, payload-indexed on `document_id`, `classification`, `doc_type`).
**Behavior** Batch-embed chunks with `bge-m3` → upsert with payload → hybrid dense+sparse retrieval with RRF → cross-encoder rerank top-25 → top-5 above a score floor, max 2 chunks per document, RBAC/classification filtered. Document delete cascades to Qdrant. Retrieval returns citable chunks (doc name, page, section, similarity).
**How to test** `pytest test_chunker` for boundary/overlap correctness; `scripts/eval_retrieval.py` against `rag_golden.yaml` (20 security questions → expected doc/page) asserting recall@5 ≥ 0.8 and MRR thresholds; delete a document → `GET /rag/stats` chunk count drops and its chunks vanish from results; confirm a `viewer` cannot retrieve `confidential` chunks.
**Expected output** A measurable, filtered, citation-producing retrieval layer — with a repeatable eval score you can quote in your report.

---

## Phase 6 — AI agents

**Files**
```
backend/app/agents/{orchestrator.py,state.py,context_assembler.py,llm_client.py,guardrails.py,validators.py}
backend/app/agents/nodes/{detection.py,analysis.py,risk.py,investigation.py,report.py}
backend/app/agents/prompts/{analysis.v1.md,risk.v1.md,investigation.v1.md,report.v1.md,untrusted_envelope.md}
backend/app/models/{agent_run.py,analysis.py}; backend/app/schemas/analysis.py
backend/app/api/v1/{agents.py,analyses.py}
backend/app/workers/analyze_job.py
backend/tests/{test_orchestrator.py,test_guardrails.py,test_output_validation.py}
```
**Dependencies** `langgraph langchain-core openai anthropic ollama tenacity`
**APIs** `POST /events/{id}/analyze`, `GET /analyses/{id}`, `GET /analyses/{id}/evidence`, `GET /agents/status`, `GET /agent-runs`, `GET /agent-runs/{id}`, `POST /agent-runs/{id}/retry`
**DB** `agent_runs`, `agent_steps`, `analyses`, `analysis_citations`.
**Behavior** On a detection above threshold, the worker assembles the `ContextBundle` (telemetry + RAG + history placeholder) and runs the LangGraph pipeline. Each node returns strict JSON validated by Pydantic (one repair retry, then `partial`). Guardrails: `risk_level = max(model_risk, severity_floor)`; investigation steps validated against a read-only verb allowlist; unknown citation ids stripped; per-node timeout and token cap. Full step trace persisted.
**How to test** mock `LLMClient` to return fixed/broken JSON → assert repair-retry and `partial` handling; assert a model attempt to downgrade a `critical` floor is overridden; assert a containment-style step ("isolate the host", "kill the process") is rejected by the validator; run end-to-end with Ollama offline and confirm `agent_steps` has 5 rows with latencies.
**Expected output** Every high-severity event yields an explainable, cited, guardrailed analysis plus a visible per-agent execution trace.

---

## Phase 7 — Historical incident intelligence

**Files**
```
backend/app/history/{event_embedder.py,similarity.py,correlator.py,dedupe.py}
backend/app/services/incident_service.py
backend/app/models/incident.py (incidents, incident_events)
backend/app/api/v1/incidents.py
backend/app/workers/history_job.py
backend/tests/{test_similarity.py,test_incident_dedupe.py,test_correlation_window.py}
```
**Dependencies** none new (reuses embeddings + Qdrant)
**APIs** `GET /incidents`, `GET /incidents/{id}`, `PATCH /incidents/{id}`, `POST /incidents/{id}/notes`, `GET /incidents/{id}/similar`, `GET /endpoints/{id}/risk-timeline`
**DB** `event_vectors` Qdrant collection; `incidents.stage/status/risk_score`; `incident_events.relation`.
**Behavior** Each detected event is embedded into a canonical string and kNN-searched against past incidents (filtered by rule or MITRE technique, excluding itself); top matches with their outcomes (`resolved` / `false_positive`) form the `HISTORY` block. Incident service groups events by `(endpoint, rule, time window)` to avoid alert storms and advances lifecycle stages.
**How to test** seed 200 synthetic historical incidents → new PowerShell event returns the prior PowerShell incidents ranked first; assert 20 identical events in 2 minutes create 1 incident with 20 linked events; assert a prior `false_positive` match visibly lowers the AI confidence in the resulting analysis.
**Expected output** "Similar activity was previously observed on WKS-042 and closed as a false positive" — sourced, linked and clearly labeled as historical, not AI-invented.

---

## Phase 8 — AI security assistant

**Files**
```
backend/app/assistant/{service.py,context.py,prompts/assistant.v1.md,stream.py,safety.py}
backend/app/models/assistant.py; backend/app/schemas/assistant.py
backend/app/api/v1/assistant.py
backend/tests/{test_assistant_citations.py,test_assistant_scope.py,test_prompt_injection_e2e.py}
```
**Dependencies** `sse-starlette`
**APIs** `POST /assistant/sessions`, `GET /assistant/sessions`, `POST /assistant/sessions/{id}/messages` (SSE), `GET /assistant/suggested-prompts`
**DB** `assistant_sessions`, `assistant_messages` (citations JSONB, feedback).
**Behavior** Session can be pinned to an incident/endpoint so "why is this high risk?" resolves without the user restating context. Router decides per question whether to use RAG, history, live telemetry or all three; answers stream and always return structured `citations[]`. Refuses offensive-tooling requests and anything outside authorized-defensive scope; a `viewer` cannot pull confidential chunks.
**How to test** ask the five reference questions from the brief and assert each answer contains ≥1 valid citation resolving to a real chunk/page; ask about an unseeded topic → assistant states no supporting documentation instead of guessing; e2e injection test: upload `injected.pdf` telling the model to ignore instructions and leak the system prompt → assert refusal + `injection_flags` surfaced.
**Expected output** A grounded copilot whose every substantive claim is traceable to telemetry, a document page, or an incident id.

---

## Phase 9 — SOC dashboard (frontend)

**Files**
```
frontend/{index.html,vite.config.ts,tailwind.config.ts,tsconfig.json,package.json}
frontend/src/{main.tsx,App.tsx,router.tsx,styles/tokens.css}
frontend/src/lib/{api.ts,ws.ts,queryClient.ts,format.ts}
frontend/src/components/layout/{AppShell,Sidebar,TopBar}.tsx
frontend/src/components/ui/{KpiCard,SeverityBadge,StatusDot,RiskGauge,Skeleton,EmptyState,Drawer,Toast,DemoDataBanner}.tsx
frontend/src/components/security/{EndpointCard,EventTable,TimelineRail,EvidencePanel,SourceChip,ProvenanceTag,ConfidenceMeter}.tsx
frontend/src/components/ai/{AgentPipeline,AgentNode,AnswerCard,ChatThread}.tsx
frontend/src/components/rag/{Dropzone,DocumentCard,PipelineStepper,KbSearch}.tsx
frontend/src/components/charts/{SeverityDonut,EventTrend,EndpointHealthBar,RiskDistribution}.tsx
frontend/src/pages/{Dashboard,Endpoints,EndpointDetail,Events,Incidents,IncidentDetail,AiCenter,RagCenter,KnowledgeBase,Reports,Settings,Login}.tsx
frontend/e2e/{dashboard.spec.ts,rag-upload.spec.ts,assistant.spec.ts,a11y.spec.ts}
```
**Dependencies** `react react-dom react-router-dom typescript vite tailwindcss @tanstack/react-query zustand recharts framer-motion lucide-react @tanstack/react-virtual d3 date-fns @playwright/test axe-core`
**APIs** all `/dashboard/*`, plus events/endpoints/incidents/agents/rag/assistant/reports and `WS /ws/stream`.
**DB** none (read-only consumer).
**Behavior** Implement `docs/03-UI-DESIGN-SYSTEM.md` and `design-tokens.md` exactly, component-by-component in this order: tokens → AppShell/Sidebar/TopBar → primitives → charts → Dashboard → Endpoints/Detail → Events → AI Center → RAG Center → Assistant → Incident Investigation → Settings. Live updates via WS topic invalidation; skeletons on every async panel; the four provenance colors used consistently; demo data always labeled.
**How to test** Playwright flows (login → dashboard KPIs render → upload doc → status reaches ready → ask assistant → citations clickable → open incident → all four evidence tabs populated); axe-core zero critical violations; visual check at 1440/1280/1024 px for overflow and contrast; Lighthouse performance ≥ 85 with a 5k-row event table virtualized.
**Expected output** A SOC console that a reviewer can operate end-to-end, where every AI claim is one click from its evidence.

---

## Phase 10 — Testing, hardening, deployment

**Files**
```
backend/tests/security/{test_authz_matrix.py,test_upload_abuse.py,test_injection_suite.py,test_rate_limits.py,test_headers.py}
backend/tests/load/locustfile.py
backend/app/core/{rate_limit.py,headers.py,retention.py}
backend/app/workers/retention_job.py
deploy/{Dockerfile.api,Dockerfile.worker,Dockerfile.frontend,docker-compose.prod.yml,nginx.conf}
deploy/k8s/*.yaml (optional)
.github/workflows/ci.yml
docs/{DEPLOYMENT.md,THREAT-MODEL.md,PRIVACY.md,AUTHORIZATION-POLICY.md,DEMO-SCRIPT.md,API.md}
```
**Dependencies** `slowapi bandit pip-audit locust ruff mypy semgrep`
**APIs** `GET /metrics`; all others frozen and documented.
**DB** retention/purge jobs, monthly partitioning for `events`, index review, least-privilege DB roles (`audit_log` INSERT-only).
**Behavior** Full authz matrix test (every route × every role), upload abuse suite (zip bomb, 1 GB stream, polyglot file, path traversal), injection suite of 25+ payloads asserting the model never follows document instructions, rate limits, security headers, TLS termination in nginx, secrets from the environment only, `bandit`/`pip-audit`/`semgrep` clean in CI, retention purge verified, backup/restore runbook.
**How to test** `make ci` (ruff + mypy + pytest + bandit + pip-audit + playwright); locust at 50 endpoints × 20 events/s sustained with p95 ingest < 200 ms and no queue growth; restore from backup into a clean stack and confirm `scripts/reindex.py` rebuilds Qdrant.
**Expected output** A hardened, documented, one-command-deployable platform with a written threat model, privacy statement, authorization policy and a 5-minute demo script — portfolio-ready.

---

## Suggested schedule

| Weeks | Phases | Milestone |
|---|---|---|
| 1 | 1 | Auth + DB + Compose up |
| 2 | 2–3 | Real telemetry with real detections |
| 3 | 4–5 | Working, evaluated RAG with citations |
| 4 | 6–7 | Explainable AI analyses + historical correlation |
| 5 | 8–9 | Assistant + full SOC UI |
| 6 | 10 | Hardening, docs, demo |
