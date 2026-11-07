# Sentrix — UI Design System Tokens (v2)

Aesthetic: deep-dark SOC console. Calm surface, restrained neon used **only** to encode severity/state.
Rule: color = meaning. Glow is reserved for CRITICAL/HIGH and live-agent states. Never decorative.

## Color palette

### Base (neutrals — 90% of the surface)
| Role | Hex / value | Usage |
|---|---|---|
| `--bg-void` | `#05080F` | app background (outermost) |
| `--bg-base` | `#0A0F1A` | page canvas |
| `--surface-1` | `#0F1623` | cards, panels |
| `--surface-2` | `#151E2E` | raised rows, inputs, hover |
| `--surface-glass` | `rgba(20,30,46,0.55)` + `backdrop-filter: blur(18px)` | sidebar, topbar, modals, drawers |
| `--border-subtle` | `rgba(148,163,184,0.12)` | card borders, dividers |
| `--border-strong` | `rgba(148,163,184,0.22)` | focused/active borders |
| `--text-hi` | `#E6EDF7` | primary text (13.9:1 on surface-1) |
| `--text-mid` | `#9AA9BF` | secondary text (6.2:1) |
| `--text-low` | `#63728A` | labels, meta (3.4:1 — 14px+ only) |

### Accent (identity — one hue)
| Role | Hex | Usage |
|---|---|---|
| `--accent` | `#22D3EE` | primary actions, links, active nav, focus ring |
| `--accent-deep` | `#06B6D4` | hover/pressed |
| `--accent-soft` | `rgba(34,211,238,0.12)` |
| `--brand-2` | `#6366F1` | brand gradient end (logo, wordmark, primary-button gradient) | active nav pill, selected row tint |
| `--ai` | `#A78BFA` | AI-generated content only (agents, AI analysis blocks) |
| `--rag` | `#2DD4BF` | RAG / retrieved-document provenance only |

Provenance colors are a hard contract used across the whole product:
**cyan = raw endpoint telemetry · teal = retrieved documents · amber-neutral slate = historical Sentrix data (`#94A3B8`) · violet = AI-generated.**

### Severity (semantic — never used for decoration)
| Level | Hex | Badge bg | Icon shape (never color alone) |
|---|---|---|---|
| CRITICAL | `#FB7185` | `rgba(251,113,133,0.14)` | filled octagon + `!!` |
| HIGH | `#FB923C` | `rgba(251,146,60,0.14)` | filled triangle |
| MEDIUM | `#FBBF24` | `rgba(251,191,36,0.14)` | filled diamond |
| LOW | `#38BDF8` | `rgba(56,189,248,0.12)` | filled circle |
| INFO / RESOLVED | `#34D399` | `rgba(52,211,153,0.12)` | check |
| OFFLINE / UNKNOWN | `#64748B` | `rgba(100,116,139,0.14)` | hollow circle |

Contrast: all severity hexes are ≥4.5:1 as text on `--surface-1`. Badges pair color + shape + text label.

### Chart series (derived from accent, harmonious)
`#38BDF8` → `#2DD4BF` → `#A78BFA` → `#FBBF24` → `#FB7185` → `#64748B`
Sequential data: single-hue cyan ramp `#0C4A6E → #38BDF8`. Grid lines `rgba(148,163,184,0.08)`, axis text `--text-low`, 12px.

### Gradients (subtle only)
- Hero/KPI wash: `linear-gradient(135deg, rgba(56,189,248,0.10), rgba(167,139,250,0.06) 60%, transparent)`
- Risk gauge arc: `conic-gradient(from 210deg, #34D399, #FBBF24, #FB923C, #FB7185)`
- Never a full-page gradient; never gradient text on body copy.

## Typography
- Display/headings: **Satoshi** (500/700) via Fontshare.
- Body/UI: **Inter** (400/500/600) — 15px base UI, 16px reading copy.
- Mono (telemetry, hashes, process trees, log lines, IDs, metrics): **JetBrains Mono** (400/500), `font-variant-numeric: tabular-nums lining-nums`.
- Scale: 34/26/20/17/15/13/12. Line height 1.5 body, 1.2 headings. Never letterspace lowercase; uppercase micro-labels (12px, `letter-spacing:.08em`, `--text-low`) for section eyebrows only.
- All numeric KPIs and table numbers: tabular-nums, mono.

## Space, radius, elevation
- Space scale: 4 / 8 / 12 / 16 / 24 / 32 / 48. Card padding 20–24. Grid gap 16–20.
- Radius: `--r-sm 8px` (badges/inputs), `--r-md 14px` (cards), `--r-lg 20px` (panels/modals), pill for nav/status chips.
- Shadow: `--sh-1 0 1px 2px rgba(0,0,0,.4)`, `--sh-2 0 8px 24px -8px rgba(0,0,0,.55)`, `--sh-glow-critical 0 0 0 1px rgba(251,113,133,.35), 0 0 24px -6px rgba(251,113,133,.35)` (critical cards only).
- 1px hairline borders everywhere instead of heavy shadows; dark UI reads structure from borders.

## Component system (canonical inventory)
`AppShell` · `Sidebar` (expanded 264px / collapsed 72px, icon+tooltip) · `TopBar` (global search ⌘K, env badge, monitoring-consent indicator, user menu) · `KpiCard` (label, value, delta, sparkline) · `RiskGauge` · `SeverityBadge` · `StatusDot` (pulse only when live) · `EndpointCard` · `EventRow` (virtualized table) · `TimelineRail` (incident lifecycle) · `AgentNode` + `AgentPipeline` · `EvidencePanel` (tabbed: Telemetry / RAG / History / AI) · `SourceChip` (doc name, page, similarity %) · `ProvenanceTag` · `PipelineStepper` (RAG ingest lifecycle) · `Dropzone` · `DocumentCard` · `ChatThread` + `AssistantAnswerCard` (sectioned) · `ConfidenceMeter` · `Drawer` · `Modal` · `Toast` · `Skeleton` · `EmptyState` · `DemoDataBanner`.

## Motion strategy
- Durations: 120ms (hover/press), 200ms (card/drawer), 320ms (page transition), 600–800ms (chart draw, number count-up).
- Easing: `cubic-bezier(.2,.8,.2,1)` enter, `cubic-bezier(.4,0,1,1)` exit.
- Allowed: hover lift 1–2px + border brighten, staggered card fade-in (40ms stagger, max 8 items), skeleton shimmer, agent pipeline "active node" pulse, alert slide-in from top-right, chart draw-in once per mount, sidebar width tween.
- Banned: parallax, 3D tilt, infinite glows on idle elements, bouncing, animated backgrounds, more than one thing animating in a viewport at a time.
- `@media (prefers-reduced-motion: reduce)` → all transitions ≤1ms, no pulse, no shimmer (static skeleton).

## Responsive behavior
- ≥1600px: 4-col KPI row, sidebar expanded, right evidence rail persistent.
- 1280–1599px: 4-col KPIs, evidence rail becomes drawer.
- 1024–1279px: 2-col KPIs, sidebar auto-collapses to icon rail.
- 768–1023px (tablet): 2-col KPIs, single-column charts, tables → stacked cards for <6 columns, horizontal scroll with sticky first column otherwise.
- <768px: read-only triage view (KPIs, alert list, assistant); heavy tables and pipeline diagrams collapse to accordions.
- Accessibility: visible 2px `--accent` focus ring on all interactives, keyboard-navigable pipeline/timeline, ARIA live region for new critical alerts, no info conveyed by color alone.
