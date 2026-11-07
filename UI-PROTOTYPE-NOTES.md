# Sentrix — UI Prototype (build notes)

> Historical build notes from v1. In Sentrix 2.0 the prototype is a single-page app (`index.html` + `views-*.js`) served by the FastAPI backend at `/`; the Email Identity Intelligence pages call the real API through `api.js`.

**Location:** `ui-prototype/`
**Stack:** static multi-page HTML + one `styles.css` + one `app.js` (vanilla), Chart.js 4.4.1 via CDN,
Satoshi (Fontshare) + Inter + JetBrains Mono (Google Fonts). No build step, no backend, no network calls.

## Files
| File | Contents |
|---|---|
| `styles.css` | Full token layer from `design-tokens.md` (colors, severity, provenance, radii, shadows, motion, breakpoints) + every component class |
| `app.js` | Shell injection (sidebar + glass topbar + demo banner), icon set, collapse persistence, skeleton/reveal sequence, Chart.js defaults, `SWbadge`/`SWring`/`SWspark`/`SWtabs`/`SWtoast` helpers |
| `index.html` | Command Center: 5 KPIs incl. 68/100 risk gauge, 7-day multi-severity trend, severity doughnut, endpoint health horizontal bar, risk distribution, live event feed, AI agent mini-panel, RAG status (12 docs / 3,481 chunks), incident timeline strip |
| `endpoints.html` | 9 EndpointCards (OS icon, status dot, risk badge, last activity, alert count, CPU/MEM bars, health ring) + filter/search; links to detail |
| `endpoint-detail.html` | WKS-042 with 7 tabs (Security Events / Processes / File Integrity / Authentication / Network / AI Analysis / Historical Incidents), mono telemetry tables + process tree, 14-day risk timeline chart |
| `ai-center.html` | 5-node AgentPipeline (Detection → Analysis → Risk Assessment → Investigation → Report) with one node pulsing "running", replay animation, agent runs table, latency chart, risk assessments, read-only recommendations |
| `rag-center.html` | Dropzone with simulated ingest lifecycle via PipelineStepper (Uploading → Extracting → Chunking → Embedding → Indexed → Ready), searchable 12-document list with delete, KB search returning 3 chunks with SourceChips (doc, page, similarity %), static pipeline diagram |
| `assistant.html` | Copilot chat: thread rail + AnswerCard sectioned by provenance contract — AI analysis (violet), Evidence/telemetry (cyan), RAG sources (teal + chips), Historical context (slate), Risk assessment (severity + 78% confidence meter), numbered read-only investigation steps, suggested-prompt chips |
| `incident.html` | INC-2291 lifecycle rail (current stage = Risk Assessment), 4 provenance-tagged evidence tabs, incident facts, related events table, export-report button (placeholder) |

## Safety / honesty
- Global "DEMO DATA" topbar badge + full synthetic-data banner on **every** page.
- All interactive buttons that would imply real effects show a toast stating it is a prototype.
- Content is defensive only: detection, evidence, investigation guidance. No offensive tooling, exploit code,
  containment, isolation or remediation actions anywhere.

## QA performed (Playwright, headless Chromium)
- Screenshots of all 7 pages at 1440px (in `../shots/`), plus 1280px and 1024px sweeps.
- Zero console/page errors on all pages at all three widths; no horizontal page overflow.
- Sidebar collapse verified working and persisted to `localStorage` (`sw-nav-collapsed`) across pages;
  auto-collapses below 1280px when no preference is stored.
- `prefers-reduced-motion: reduce` context verified (no shimmer/pulse, transitions ≤1ms, charts render statically).
- Fixed during QA: mid-word wrapping in KV lists and agent-node titles, hostname cell wrapping,
  implicit-column bug that broke the 2-col KPI layout at 1024px, doc-metadata overflow, offline health ring color.

## Outstanding
Deployment could not be completed from this subagent: `pplx-tool deploy_website` returns
`tool_not_allowed`, and no deploy connector is available. The parent agent should run
`deploy_website` with `project_path=<repo>/ui-prototype`.
