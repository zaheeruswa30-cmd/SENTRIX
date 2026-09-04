# SecureWatch AI — Interactive Client-Side Demo

A single-page, no-backend, no-build demo of a defensive XDR triage console. Everything runs in
the browser tab: authentication, file ingestion, retrieval, detection rules, risk scoring and
report generation. **All data is synthetic and fabricated. There is no production system behind
this UI, and no offensive or remediation capability anywhere in it — investigation guidance only.**

## Run it

Serve the folder over HTTP (module-free vanilla JS, but `fetch`/worker-based PDF parsing needs a
real origin):

```bash
cd ui-prototype && python3 -m http.server 8099
# open http://127.0.0.1:8099/index.html
```

## Seeded accounts

| Role | Email | Password | Capabilities |
| --- | --- | --- | --- |
| Analyst | `analyst@securewatch.local` | `Demo1234!` | upload, delete, run analysis, advance incidents |
| Admin | `admin@securewatch.local` | `Admin1234!` | everything above + Settings › Users panel |
| Viewer | `viewer@securewatch.local` | `Viewer1234!` | read-only — upload / delete / run are disabled with a reason tooltip |

`Continue as demo analyst` on the sign-in screen logs straight in as the Analyst. Signup creates
an additional in-memory account and signs you in immediately.

## What is genuinely real (runs as code in your browser)

- **Authentication flow** — form validation, inline `Invalid credentials`, password show/hide,
  live password-strength scoring, signup + auto-login, forgot-password modal, session guard that
  redirects unauthenticated hash routes to `#/login`, working sign-out and account switching.
- **RBAC** — a real capability map (`upload`, `delete`, `run`, `manageUsers`, `advanceIncident`).
  Denied controls are actually `disabled` and carry an explanatory tooltip rather than being hidden.
- **File upload** — drag-and-drop and file picker, real byte reads, 25 MB cap, extension allowlist
  (`.txt`, `.md`, `.pdf`, `.docx`), and duplicate rejection by real SHA-256 computed with
  `crypto.subtle.digest`.
- **Text extraction** — `FileReader` for `.txt`/`.md`, pdf.js per-page extraction for `.pdf`,
  JSZip + `word/document.xml` parsing for `.docx`.
- **Chunking** — ~800 characters with 100-character overlap, split on heading/paragraph
  boundaries, each chunk carrying a `[doc: NAME · p.N]` provenance breadcrumb and its section heading.
- **Retrieval** — real TF-IDF term weighting, L2-normalised vectors and cosine similarity over the
  in-memory chunk index. Every score on screen is computed, not authored. Knowledge-base search
  returns the true top-5 chunks with term highlighting and expandable full-chunk views.
- **Detection** — 10 deterministic rules (`SW-R001`…`SW-R010`) with MITRE ATT&CK technique ids and
  per-rule severity floors, evaluated against event fields.
- **Risk scoring** — a deterministic function of rule floor, endpoint standing risk, retrieval
  support and historical similarity: `risk = max(computed, rule floor)`.
- **Agent pipeline timings** — the six node latencies and the total run duration are real
  `performance.now()` measurements of the work that just executed.
- **Charts** — recomputed from the in-memory dataset, so simulating a new alert changes them.
- **Report download** — a genuine Markdown file assembled from the run record and downloaded via
  `Blob` + `URL.createObjectURL`.

## What is simulated

- **The "AI".** There is **no language model in this demo.** Assessment prose is template-composed
  from matched rules and retrieved chunks; the streaming reveal is a visual effect over text that
  was already computed. This is labelled on every relevant surface as
  *"Simulated analysis engine — deterministic rules + client-side retrieval, no LLM in this demo."*
- **The embedding model.** Retrieval uses *"Demo embedding: client-side TF-IDF (no external model)"*.
  No neural embedding model (bge-m3 or otherwise) is used or claimed.
- **All telemetry.** Endpoints, events, incidents, users, and the two pre-seeded knowledge-base
  documents are fabricated defensive-security examples authored for this prototype.
- **Alert feed.** `Simulate new critical alert` injects a synthetic event; nothing is being observed.
- **Incident workflow.** Stage advance mutates in-memory state only.

Settings › **Demo mode — what is real vs simulated** contains this same breakdown in-app, split
into "Actually real" and "Simulated" tabs.

## Known limitation: state resets on reload

Browser storage APIs are unavailable in the preview iframe this demo is delivered through, so the
entire application state — your session, created accounts, uploaded documents, the TF-IDF index,
run history and chat transcript — lives in a single in-memory JavaScript store.

**Consequence:** reloading the page (or navigating away and back) resets everything to the seeded
state and signs you out. Hash-route navigation *within* the app (`#/dashboard` → `#/rag` → …) is
safe and preserves everything; that is precisely why the app was restructured into one
`index.html` with a hash router instead of separate pages.

## Architecture

| File | Role |
| --- | --- |
| `index.html` | Single page shell: `#root`, toast/modal/ARIA hosts, CDN fonts + Chart.js |
| `styles.css` | Design system implementation (tokens, shell, components, reduced-motion) |
| `data.js` | Synthetic dataset: users, endpoints, events, incidents, seeded documents |
| `core.js` | State store, hash router, RBAC gates, toasts, modals, command palette, icons |
| `rag.js` | Hashing, extraction, chunking, TF-IDF indexing, cosine retrieval, highlighting |
| `agents.js` | Detection rules, six-stage pipeline, risk function, report composition |
| `views-auth.js` | `#/login`, `#/signup`, forgot-password modal, password strength |
| `views-monitor.js` | `#/dashboard`, `#/endpoints`, `#/endpoint/:id`, `#/events`, `#/event/:id` |
| `views-incidents.js` | `#/incidents`, `#/incident/:id` |
| `views-ai.js` | `#/ai-center`, `#/assistant` |
| `views-rag.js` | `#/rag`, `#/knowledge-base` |
| `views-misc.js` | `#/reports`, `#/settings` (incl. honesty panel, Admin users panel) |

Routes: `#/login`, `#/signup`, `#/dashboard`, `#/endpoints`, `#/endpoint/:id`, `#/events`,
`#/event/:id`, `#/incidents`, `#/incident/:id`, `#/ai-center`, `#/rag`, `#/knowledge-base`,
`#/assistant`, `#/reports`, `#/settings`.

## Accessibility & quality notes

- Keyboard: Enter submits forms, Esc closes modals and the command palette, `⌘K` / `Ctrl+K` opens
  global search, visible focus rings throughout, skip link to main content.
- Live regions announce new alerts and password-strength changes.
- `prefers-reduced-motion` disables the streaming reveal, transitions and animations.
- Verified with no console or page errors across all routes at 1440 / 1280 / 1024 px.
