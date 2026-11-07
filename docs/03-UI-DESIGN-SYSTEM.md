# Sentrix — UI/UX Design System & Wireframes

Token reference (colors, type, spacing, motion, responsive rules): **`../design-tokens.md`** — that file is the single source of truth and maps 1:1 to `frontend/src/styles/tokens.css`.
This document covers the parts a token file can't express: layout, wireframes, component anatomy and interaction rules.

---

## 1. Design intent

One sentence a viewer should form within three seconds of seeing the dashboard:
**"This is an AI-powered endpoint security monitoring and investigation platform, and it shows me why it thinks what it thinks."**

Four qualities, and how each is expressed visually:

| Quality | Expression |
|---|---|
| Security | dark console surface, severity encoded by color **and** shape **and** text, dense but ordered telemetry |
| Intelligence | violet AI accents used sparingly, confidence meters, uncertainty stated openly |
| Monitoring | live status dots, heartbeat freshness, real-time counters, event trend lines |
| Investigation | timelines, evidence panels, provenance tabs, click-to-source citations |
| Trust | honest empty states, "no supporting documentation found", DEMO DATA labels, visible authorization state |

Anti-goals: Bootstrap default look, rainbow dashboards, glow on everything, 3D, decorative motion, fabricated metrics presented as real.

---

## 2. The provenance contract (most important rule in the UI)

Four data origins, four fixed visual treatments, used identically on every page:

| Origin | Color | Icon | Label | Typeface |
|---|---|---|---|---|
| Raw endpoint telemetry | cyan `#38BDF8` | terminal | `TELEMETRY` | JetBrains Mono |
| Retrieved document | teal `#2DD4BF` | file-text | `DOC · name p.N` | Inter |
| Historical Sentrix data | slate `#94A3B8` | history | `HISTORY · INC-####` | Inter |
| AI-generated | violet `#A78BFA` | sparkles | `AI` | Inter |

Implemented once as `<ProvenanceTag origin=…>` and `<SourceChip>`; no page may improvise its own colors for these. This is what stops the product from feeling like a chatbot with a dark theme.

---

## 3. Layout grid

- App shell: fixed sidebar (264px expanded / 72px collapsed) + fluid content, max content width 1680px, page padding 24–32px.
- 12-column content grid, 20px gutters.
- Standard page rhythm: `PageHeader (title + context + actions)` → `KPI row` → `charts (2 cols)` → `primary table/list` → optional right rail (360px) for evidence/detail.
- Cards: 14px radius, 1px hairline border, 20–24px padding, no drop shadow at rest (shadow appears only on hover/overlay).
- Density: table rows 44px default, 36px compact toggle; mono font for all telemetry columns.

---

## 4. Navigation

```
SENTRIX                        [«]
 ── MONITOR ───────────────
 ◈ Dashboard                     ← accent pill + 2px left bar when active
 ▣ Endpoints                48
 ⚠ Security Events           3 ● ← count badge; dot only when unacknowledged critical
 ⛊ Incidents                  2
 ── INTELLIGENCE ──────────
 ✦ AI Security Center       ▮▮   ← animated only while an agent run is active
 ⌕ RAG Intelligence
 ▤ Knowledge Base           12
 ── OUTPUT ────────────────
 ▦ Reports
 ⚙ Settings
 ─────────────────────────
 ◉ ah  Abid H. · analyst
```
Rules: three labeled groups (Monitor / Intelligence / Output); collapse toggle persisted in localStorage; collapsed mode shows icon + tooltip and keeps badges as dots; active route = accent pill + left bar + icon color, never color alone (also bold label); keyboard `[` toggles collapse, `⌘K` opens global search.

Top bar (glass, 56px): global search (events, endpoints, docs, incidents) · time-range selector · **monitoring-consent indicator** ("48 authorized endpoints") · environment badge · DEMO DATA badge when seeded · notifications · user menu.

---

## 5. Dashboard wireframe (Command Center)

```
┌ Sidebar ┬─────────────────────── Top bar: ⌕ search  ·  24h ▾  ·  ⛨ 48 authorized  ·  DEMO ──┐
│         │ Command Center                                    Last sync 12s ago  [Export ▾]   │
│         │ ┌ Endpoints ─┐┌ Online ────┐┌ Active threats ┐┌ Critical ──┐┌ Risk score ──────┐ │
│         │ │ 48         ││ 41 / 48    ││ 3              ││ 2          ││   ◔ 68 / 100     │ │
│         │ │ ▁▂▃▃▄ +2   ││ 85% ▲      ││ ▲ +1 vs 24h    ││ ⬤ needs IR ││   MEDIUM-HIGH    │ │
│         │ └────────────┘└────────────┘└────────────────┘└────────────┘└──────────────────┘ │
│         │ ┌ Threat severity distribution ───┐ ┌ Security event trend · 7d ───────────────┐ │
│         │ │        ◕ donut                  │ │  stacked area by severity, hover tooltip │ │
│         │ │  C 2 · H 7 · M 19 · L 44        │ │  brush-to-zoom, annotation on spike      │ │
│         │ └─────────────────────────────────┘ └──────────────────────────────────────────┘ │
│         │ ┌ Recent security events ─────────────────────────┐ ┌ AI agent activity ───────┐ │
│         │ │ ⬤C 20:14 WKS-042 Encoded PowerShell   [Analyze]│ │ Detection    ✓ 1.2s      │ │
│         │ │ ▲H 20:09 SRV-DB-01 5× failed SSH      [Analyze]│ │ Analysis     ▮ running   │ │
│         │ │ ◆M 20:02 WKS-017 Unsigned binary temp  [View]  │ │ Risk         · queued    │ │
│         │ │ … virtualized, click → detail drawer            │ │ Investigation· queued    │ │
│         │ └─────────────────────────────────────────────────┘ │ Report       · queued    │ │
│         │ ┌ Endpoint health ──────┐┌ Risk distribution ──┐   │ 3 runs today · p95 8.4s  │ │
│         │ │ horizontal bars       ││ L/M/H/C bar + legend│   └──────────────────────────┘ │
│         │ └───────────────────────┘└─────────────────────┘   ┌ Knowledge base ──────────┐ │
│         │ ┌ Incident timeline · 7d ──────────────────────┐   │ 12 docs · 3,481 chunks   │ │
│         │ │ ●──▲───⬤────●──── stage-colored markers     │   │ Indexed 14m ago  [Upload]│ │
│         │ └──────────────────────────────────────────────┘   └──────────────────────────┘ │
└─────────┴──────────────────────────────────────────────────────────────────────────────────┘
```
Every widget answers a SOC question: *am I covered · what's burning · is it getting worse · which hosts are weak · is the AI working · is my knowledge current.*

---

## 6. Endpoints page

Grid of `EndpointCard` (3–4 per row), filters: status · risk · OS · tag · has-alerts. Card anatomy:

```
┌─────────────────────────────────────────┐
│ ● WKS-042            [HIGH ▲]           │  status dot (pulse only if online), risk badge
│ Windows 11 23H2 · agent 1.4.2           │  mono meta line
│ ── health 62 ──────────────────  ◔62    │  ring + numeric, color from severity scale
│ CPU ▓▓▓▓▓░░░ 54%   MEM ▓▓▓▓▓▓░ 71%      │  thin bars, tabular numbers
│ 3 active alerts · last activity 14s ago │
└─────────────────────────────────────────┘   hover: 1px lift + border brighten + [Investigate]
```
Detail view (`/endpoints/:id`): sticky header (host identity, authorization record, revoke-monitoring action for admin) + risk timeline chart + tabs **Events · Processes · File Integrity · Authentication · Network · AI Analysis · Historical Incidents**. Telemetry tabs are mono, virtualized tables with column-level filters and a raw-JSON drawer per row (`TELEMETRY` tagged).

---

## 7. AI Security Center

```
Detection ──► Analysis ──► Risk ──► Investigation ──► Report
   ✓ 1.2s      ▮ 3.4s      · —          · —            · —
```
Each `AgentNode`: name, state (idle/queued/running/done/failed with distinct icon+color), current task line, last output snippet, latency, model name, token count. Running node: 2s soft pulse on its border only — one node at a time, and nothing pulses when the pipeline is idle. Connectors animate a single traveling dot only while data actually moves.
Below: recent `agent_runs` table (trigger event, duration, status, retries) → click opens the full step trace with each node's structured output; panel of recent risk assessments; AI recommendations list. Guarantee: this page renders real `agent_steps` rows — it is instrumentation, not decoration.

---

## 8. RAG Intelligence Center

Three-zone layout: **Dropzone + lifecycle** (top-left), **document list** (bottom-left, searchable/sortable/deletable with status pills and chunk counts), **retrieval playground** (right).

```
┌ Upload ─────────────────────────────────┐ ┌ Ask the knowledge base ─────────────┐
│  ⤓  Drop PDF · DOCX · TXT · MD          │ │ "PowerShell encoded command detect" │
│     max 25 MB · validated before index  │ │ ── Retrieved chunks ──────────────  │
│ IR-Playbook.pdf                         │ │ ▸ DOC IR-Playbook.pdf p.12  0.91    │
│ Uploading▸Extracting▸Chunking▸Embedding │ │   "Encoded commands (-enc) should…" │
│ ▸Indexed▸Ready      ●●●●●○  step 5/6    │ │ ▸ DOC PS-Policy.docx §3.1   0.84    │
└─────────────────────────────────────────┘ │ ▸ DOC Notes-2025.md         0.77    │
┌ Documents (12) ─────────────────────────┐ │ similarity bars + open-source view  │
│ name · type · size · chunks · status ⋯  │ └─────────────────────────────────────┘
└─────────────────────────────────────────┘ ┌ Pipeline ── Upload→Extract→Chunk→   │
                                            │ Embed→Vector DB→Retrieve→AI answer  │
```
The `PipelineStepper` is bound to the real `documents.status` value (polled/WS), so it is a progress indicator, not an animation. Suspicious documents show an amber `injection screened` chip linking to the findings — a trust feature, not an error.

---

## 9. Incident Investigation view

```
INC-2418 · Encoded PowerShell execution on WKS-042        [CRITICAL]  [Export report ▾]
Detection ──► Analysis ──► Correlation ──► Risk ──► Investigation ──► Resolution
   ✓            ✓             ✓            ✓          ● current          ○
┌ Evidence ────────────────────────────────────────┬ Analysis ─────────────────────┐
│ [ Telemetry ][ RAG Sources ][ History ][ AI ]    │ AI  assessment paragraph      │
│ (each tab keeps its provenance color + icon)     │ Risk CRITICAL · why: factors  │
│ mono process tree / doc chunks / prior incidents │ Confidence ▓▓▓▓▓▓▓░ 78%       │
│                                                  │ Uncertainty: no EDR corroborat│
└──────────────────────────────────────────────────┴───────────────────────────────┘
┌ Recommended defensive investigation (read-only) ─┐ ┌ Related events (7) ─────────┐
│ 1. Review full command line …  → confirms [T2]   │ │ time · host · rule · sev    │
└──────────────────────────────────────────────────┘ └─────────────────────────────┘
```
Stage rail is the page's spine; the evidence tabs are the explainability contract made clickable. Every recommendation states which evidence it would confirm or rule out.

---

## 10. Assistant (security copilot)

Not a bubble chat. User turns are compact right-aligned text; assistant turns are a structured `AnswerCard` with fixed sections in fixed colors:

`AI Analysis` (violet) → `Evidence` (cyan, mono) → `RAG Sources` (teal chips: doc · page · similarity, click to open the chunk) → `Historical Context` (slate, links to incident ids) → `Risk Assessment` (severity color + `ConfidenceMeter`) → `Recommended Defensive Investigation` (numbered).

Sections with no data are omitted, never faked. Context chip at the top shows what the session is pinned to (`INC-2418` / `WKS-042` / knowledge base only). Suggested prompts as chips. Streaming renders section-by-section with a skeleton for pending sections. A footer line always states which sources were searched, including "no supporting documentation found" when retrieval came back empty.

---

## 11. Component system

Primitives: `AppShell · Sidebar · TopBar · PageHeader · Card · KpiCard · Button (primary/ghost/danger) · Input · Select · Tabs · Table (virtualized) · Drawer · Modal · Toast · Tooltip · Skeleton · EmptyState · Pagination`.
Security domain: `SeverityBadge · StatusDot · RiskGauge · EndpointCard · EventRow · TimelineRail · EvidencePanel · SourceChip · ProvenanceTag · ConfidenceMeter · MitreChip · DemoDataBanner`.
AI/RAG: `AgentNode · AgentPipeline · AgentRunTrace · AnswerCard · ChatThread · Dropzone · DocumentCard · PipelineStepper · KbSearchResult`.
Charts: `SeverityDonut · EventTrend · EndpointHealthBar · RiskDistribution · IncidentTimeline · AlertTrend · AiDetectionStats`.

Each component ships with: default / loading (skeleton) / empty / error / dense states, and a keyboard path.

---

## 12. Animation strategy

Purpose classes only: **state change** (status flips, new alert slide-in from top-right + ARIA live announce), **progress** (pipeline stepper, agent run, upload), **orientation** (page transition 320ms fade+4px rise, drawer slide, sidebar width tween), **data reveal** (chart draw-in 700ms once per mount, KPI count-up 600ms).
Limits: one animated focal point per viewport; card fade-in staggered 40ms up to 8 items then instant; no idle glow; no looping animation on data that hasn't changed; all durations from the token scale; `prefers-reduced-motion` disables everything except instant state changes.

---

## 13. Responsive & accessibility

Breakpoint behavior is specified in `design-tokens.md` §Responsive. Additional rules:
- Tablet (768–1023px): sidebar becomes an overlay drawer; KPI row 2×2; charts stack; tables switch to stacked cards below 6 columns, otherwise horizontal scroll with a sticky first column.
- Never hide severity or provenance information at any breakpoint — hide secondary metadata instead.
- WCAG AA contrast for all text and a 3:1 minimum between adjacent chart segments; visible 2px accent focus ring; full keyboard traversal of pipeline nodes and timeline stages; `aria-live="polite"` region for new critical alerts; every chart has an accessible data-table fallback; severity never conveyed by color alone.
- Performance: virtualize any list over 100 rows, lazy-load route chunks, memoize chart data, cap WS re-render frequency (coalesce to 1s), target Lighthouse ≥ 85 with 5k events loaded.

---

## 14. Build order for the frontend

1 tokens.css → 2 AppShell/Sidebar/TopBar → 3 primitives (Card, Button, Badge, Table, Skeleton, EmptyState) → 4 security primitives (SeverityBadge, StatusDot, ProvenanceTag, SourceChip) → 5 charts → 6 Dashboard → 7 Endpoints + detail → 8 Events → 9 AI Center → 10 RAG Center → 11 Assistant → 12 Incident Investigation → 13 Settings/Reports → 14 a11y + performance pass.

Do not move to the next item until the current one renders correctly in all five states (default/loading/empty/error/dense) at 1440, 1280 and 1024 px.


---

## Sentrix 2.0 additions

- **Brand mark:** hexagonal lens (`SW.LOGO_SVG`, `ui-prototype/assets/favicon.svg`) with a cyan → indigo gradient (`#22D3EE` → `#6366F1`). Wordmark "SENTRIX" in Satoshi, letter-spaced; sub-label "Security Operations".
- **Navigation:** new group **Email Identity Intelligence** — Email Verification · Domain Intelligence · Email Authentication · Ownership Verification · Email Risk Analysis · Investigation History. A sub-nav strip repeats the six sections on every page of the module.
- **Validity ladder:** six stacked layers (syntax → domain → mail infrastructure → SPF/DKIM/DMARC → verified ownership → real-world identity). Each layer has its own pass / warn / fail / not-assessed pill so users never read a pass in one layer as a pass in the next. "Real-world identity" is always *not assessed*.
- **Status pills** (`.st-*`): pass/valid (green), warn/monitoring (amber), fail/invalid (red), pending (blue), neutral/not checked (slate).
- **Risk pills** (`.risk-*`): low / guarded / elevated / high, always shown with a numeric score and a confidence %.
- **Findings cards:** title, severity, category, layer, impact weight, confidence, an `EVIDENCE` line and a recommendation.
- **API chip:** topbar indicator showing whether the Sentrix backend is connected; pages that need the backend show a retry state instead of fake data.
