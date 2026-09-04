/* SecureWatch AI — Reports and Settings (incl. Demo mode + Admin users panel). */
(function () {
  'use strict';
  var SW = window.SW;

  /* ================= Reports ================= */
  SW.route('reports', { title: 'Reports', render: function (host) {
    host.innerHTML = SW.head('Reports',
      'Every report below is composed from a real agent run in this session — markdown is generated at download time',
      '<button class="btn btn-ghost" id="snapBtn">' + SW.icon('export', 15) + 'Export fleet snapshot</button>') +
      '<div class="grid g4 mb" id="repKpis"></div>' +
      '<div class="card panel"><div class="card-head"><div><h3>Run reports</h3>' +
        '<div class="faint">Generated from run records — no report exists until a pipeline has run</div></div></div>' +
        '<div id="repList"></div></div>' +
      '<div class="card panel" style="margin-top:16px"><div class="card-head"><div><h3>Report preview</h3>' +
        '<div class="faint" id="repWhich">Select a run to preview its markdown</div></div></div>' +
        '<div class="pre pre-wrap" id="repPre">No run selected.</div></div>';

    function drawKpis() {
      var runs = SW.state.runs.filter(function (r) { return r.status === 'complete'; });
      var avg = runs.length ? Math.round(runs.reduce(function (a, r) { return a + r.duration; }, 0) / runs.length) : 0;
      var cites = runs.reduce(function (a, r) { return a + r.citations.length; }, 0);
      var hi = runs.filter(function (r) { return r.risk && r.risk.risk >= 80; }).length;
      host.querySelector('#repKpis').innerHTML = [
        ['Reports available', runs.length, 'one per completed run'],
        ['Mean run duration', avg + ' ms', 'measured with performance.now()'],
        ['Total citations', cites, 'chunks + prior incidents'],
        ['Critical-band findings', hi, 'risk ≥ 80 after floor enforcement']
      ].map(function (k) {
        return '<div class="kpi"><div class="k-label">' + k[0] + '</div><div class="k-value" style="font-size:28px">' + k[1] + '</div>' +
          '<div class="k-foot"><span>' + k[2] + '</span></div></div>';
      }).join('');
    }
    function drawList() {
      var runs = SW.state.runs.filter(function (r) { return r.status === 'complete'; });
      host.querySelector('#repList').innerHTML = runs.length ? runs.map(function (r) {
        return '<div class="doc-row"><span class="doc-icon">' + SW.icon('reports', 16) + '</span>' +
          '<span class="doc-main"><span class="doc-name">' + r.id + ' — ' + SW.esc(r.eventTitle) + '</span>' +
          '<span class="doc-meta">' + r.eventId + ' · ' + r.endpoint + ' · ' + r.hits.length + ' rules · ' +
            r.citations.length + ' citations · ' + r.duration + ' ms · ' + SW.fmtDate(r.startedAt) + '</span></span>' +
          (r.risk ? SW.badge(r.risk.band) : '') +
          '<button class="btn btn-ghost btn-sm" data-preview="' + r.id + '">Preview</button>' +
          '<button class="btn btn-primary btn-sm" data-dl="' + r.id + '">' + SW.icon('export', 14) + 'Download .md</button></div>';
      }).join('') : SW.emptyState('No reports yet',
        'Run the analysis pipeline on an event and its report becomes available here.',
        '<a class="btn btn-primary" href="#/ai-center">Open AI Security Center</a>');
    }
    host.querySelector('#repList').addEventListener('click', function (e) {
      var p = e.target.closest('[data-preview]'), d = e.target.closest('[data-dl]');
      var id = p ? p.dataset.preview : d ? d.dataset.dl : null;
      if (!id) return;
      var run = SW.state.runs.filter(function (r) { return r.id === id; })[0];
      if (!run) return;
      if (d) { SW.agents.download(run); return; }
      host.querySelector('#repWhich').textContent = run.id + ' · ' + run.eventId + ' · composed ' + SW.fmtDate(run.startedAt);
      host.querySelector('#repPre').textContent = SW.agents.markdown(run);
    });
    host.querySelector('#snapBtn').addEventListener('click', function () {
      var c = SW.counts(), st = SW.rag.stats();
      var md = ['# SecureWatch AI — fleet snapshot', '', 'Generated ' + new Date().toISOString() + ' (synthetic demo data)', '',
        '| Metric | Value |', '| --- | --- |',
        '| Endpoints | ' + c.total + ' |', '| Online | ' + c.online + ' |',
        '| Events in window | ' + c.events + ' |', '| Critical events | ' + c.crit + ' |',
        '| Open incidents | ' + c.openInc + ' |', '| Mean endpoint risk | ' + c.fleetRisk + ' |',
        '| Indexed documents | ' + st.docs + ' |', '| Vector chunks | ' + st.chunks + ' |',
        '| Agent runs this session | ' + SW.state.runs.length + ' |', '',
        'Retrieval engine: ' + SW.rag.EMBED_LABEL, 'Analysis engine: ' + SW.agents.ENGINE_LABEL].join('\n');
      var blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = 'securewatch-snapshot.md';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      SW.toast('Snapshot exported', 'securewatch-snapshot.md written from live counters', 'ok');
    });
    drawKpis(); drawList();
  } });

  /* ================= Settings ================= */
  SW.route('settings', { title: 'Settings', render: function (host) {
    var u = SW.state.user;
    var real = [
      ['Authentication', 'Real form validation, password strength scoring, signup, role assignment and sign-out — accounts live in memory for this session.'],
      ['File upload', 'Real drag-and-drop and file picker, real byte reads, 25 MB cap, extension allowlist and SHA-256 duplicate detection via crypto.subtle.'],
      ['Text extraction', 'Real: FileReader for .txt/.md, pdf.js per-page extraction for .pdf, JSZip + word/document.xml for .docx.'],
      ['Chunking', 'Real: ~' + SW.rag.CHUNK_CHARS + ' characters with ' + SW.rag.OVERLAP + '-character overlap on heading and paragraph boundaries, with document/page breadcrumbs.'],
      ['Embeddings + retrieval', 'Real but simple: ' + SW.rag.EMBED_LABEL + '. Cosine similarity over L2-normalised TF-IDF vectors. Scores you see are computed, not faked.'],
      ['Detection', 'Real deterministic rule engine — ' + SW.agents.RULES.length + ' rules with MITRE ATT&CK ids and severity floors evaluated against event fields.'],
      ['Risk scoring', 'Real deterministic function of rule floor, endpoint standing risk, retrieval support and historical similarity; risk = max(computed, floor).'],
      ['Latency figures', 'Real: measured per node with performance.now().'],
      ['Charts and counters', 'Real: every KPI, chart and count is computed from the in-memory dataset as it changes.']
    ];
    var simulated = [
      ['Language model', 'There is none. ' + SW.agents.ENGINE_LABEL + ' Narrative text is template-composed from event fields, matched rules and retrieved chunks.'],
      ['Dataset', 'All endpoints, events and incidents are synthetic defensive-security samples authored for this demo.'],
      ['Agent “thinking”', 'Node timings include small deliberate delays so the pipeline is observable; the work at each node is real but tiny.'],
      ['Live alerts', 'Generated from templates on a timer or on demand via “Simulate alert”.'],
      ['Backend', 'None. No network calls except CDN assets (fonts, Chart.js, pdf.js, JSZip).'],
      ['Persistence', 'None. Browser storage APIs are unavailable in this preview, so all state resets on reload.']
    ];

    host.innerHTML = SW.head('Settings', 'Session preferences and an honest account of what is real in this demo',
      '<span class="demo-badge">Demo build</span>') +
      '<div class="grid g-2-1">' +
        '<div style="min-width:0;display:flex;flex-direction:column;gap:16px">' +
          '<div class="card panel"><div class="card-head"><div><h3>Demo mode — what is real vs simulated</h3>' +
            '<div class="faint">Read this before judging any number on screen</div></div>' +
            '<span class="prov-tag prov-rag"><i></i>Honesty panel</span></div>' +
            '<div class="tabs" role="tablist" id="dmTabs">' +
              '<button class="tab active" role="tab" aria-selected="true" data-target="dm-real">Actually real (' + real.length + ')</button>' +
              '<button class="tab" role="tab" aria-selected="false" data-target="dm-sim">Simulated (' + simulated.length + ')</button></div>' +
            '<div id="dmPanels">' +
              '<div class="tab-panel active" id="dm-real"><ul class="list-clean spaced">' + real.map(function (r) {
                return '<li><b>' + r[0] + '</b><p class="muted">' + SW.esc(r[1]) + '</p></li>'; }).join('') + '</ul></div>' +
              '<div class="tab-panel" id="dm-sim"><ul class="list-clean spaced">' + simulated.map(function (r) {
                return '<li><b>' + r[0] + '</b><p class="muted">' + SW.esc(r[1]) + '</p></li>'; }).join('') + '</ul></div>' +
            '</div></div>' +
          (SW.can('manageUsers') ?
          '<div class="card panel"><div class="card-head"><div><h3>Users</h3>' +
            '<div class="faint">Visible to the Admin role only · ' + SW.state.users.length + ' accounts in this session</div></div>' +
            '<span class="role-chip role-admin">Admin only</span></div>' +
            '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Capabilities</th><th></th></tr></thead><tbody id="userBody"></tbody></table></div>' +
            '<div class="hr"></div><div class="filters"><select id="newRole" aria-label="Role for the next created account">' +
              '<option>Analyst</option><option>Viewer</option><option>Admin</option></select>' +
              '<span class="faint">Role changes below apply immediately and re-render the shell if they affect you.</span></div></div>' : '') +
          '<div class="card panel"><div class="card-head"><h3>Session preferences</h3></div>' +
            '<div class="pref-row"><div><b>Reduced motion</b><p class="muted">' +
              (SW.reduced ? 'Detected from your system setting — animations and streaming reveals are disabled.' : 'Not requested by your system. Animations are enabled.') +
              '</p></div><span class="chip-state ' + (SW.reduced ? 'done' : 'idle') + '">' + (SW.reduced ? 'on' : 'off') + '</span></div>' +
            '<div class="pref-row"><div><b>Live alert simulation</b><p class="muted">A synthetic critical or high event is appended to the feed roughly every 22 seconds and announced to screen readers.</p></div>' +
              '<button class="btn btn-ghost btn-sm" id="simNow">Simulate now</button></div>' +
            '<div class="pref-row"><div><b>Sidebar</b><p class="muted">Collapse state is kept in memory for this session.</p></div>' +
              '<button class="btn btn-ghost btn-sm" id="togNav">Toggle</button></div>' +
            '<div class="pref-row"><div><b>Reset demo data</b><p class="muted">Clears agent runs, chat history and uploaded documents, then re-indexes the two seeded demo documents.</p></div>' +
              '<button class="btn btn-danger btn-sm" id="resetBtn">Reset</button></div></div>' +
        '</div>' +
        '<div style="min-width:0;display:flex;flex-direction:column;gap:16px">' +
          '<div class="card"><div class="card-head"><h3>Signed-in account</h3></div>' +
            '<div class="acct"><span class="avatar lg">' + SW.esc(u.name.slice(0, 1)) + '</span><div style="min-width:0">' +
            '<b>' + SW.esc(u.name) + '</b><div class="faint">' + SW.esc(u.email) + '</div>' +
            '<span class="role-chip role-' + u.role.toLowerCase() + '">' + u.role + '</span></div></div>' +
            '<div class="hr"></div><dl class="kv"><dt>Upload documents</dt><dd>' + (SW.can('upload') ? 'Allowed' : 'Denied') + '</dd>' +
            '<dt>Delete documents</dt><dd>' + (SW.can('delete') ? 'Allowed' : 'Denied') + '</dd>' +
            '<dt>Run agent analysis</dt><dd>' + (SW.can('run') ? 'Allowed' : 'Denied') + '</dd>' +
            '<dt>Advance incidents</dt><dd>' + (SW.can('advanceIncident') ? 'Allowed' : 'Denied') + '</dd>' +
            '<dt>Manage users</dt><dd>' + (SW.can('manageUsers') ? 'Allowed' : 'Denied') + '</dd></dl>' +
            '<div class="hr"></div><div class="filters"><button class="btn btn-ghost btn-sm" id="swBtn">' + SW.icon('swap', 14) + 'Switch account</button>' +
            '<button class="btn btn-ghost btn-sm" id="outBtn">' + SW.icon('logout', 14) + 'Sign out</button></div></div>' +
          '<div class="card"><div class="card-head"><h3>Engines in use</h3></div>' +
            '<ul class="list-clean"><li><span class="prov-tag prov-rag"><i></i>Retrieval</span><p class="muted">' + SW.rag.EMBED_LABEL + '</p></li>' +
            '<li><span class="prov-tag prov-ai"><i></i>Analysis</span><p class="muted">' + SW.agents.ENGINE_LABEL + '</p></li>' +
            '<li><span class="prov-tag prov-telemetry"><i></i>Telemetry</span><p class="muted">Synthetic defensive-security event set authored for this prototype.</p></li></ul></div>' +
          '<div class="card"><div class="card-head"><h3>Known limitation</h3></div>' +
            '<p class="muted">All browser storage APIs are unavailable in the preview iframe, so this build deliberately keeps every byte of state in memory. Reloading the page returns you to the sign-in screen with a fresh dataset.</p></div>' +
        '</div>' +
      '</div>';

    SW.wireTabs(host.querySelector('#dmTabs'), host.querySelector('#dmPanels'));
    host.querySelector('#simNow').addEventListener('click', function () { SW.pushLiveAlert(); });
    host.querySelector('#togNav').addEventListener('click', function () {
      SW.state.navCollapsed = !SW.state.navCollapsed;
      document.body.classList.toggle('nav-collapsed', SW.state.navCollapsed);
      var cb = document.getElementById('collapseBtn');
      if (cb) cb.setAttribute('aria-expanded', String(!SW.state.navCollapsed));
      SW.toast('Sidebar ' + (SW.state.navCollapsed ? 'collapsed' : 'expanded'), 'Kept in memory for this session.');
    });
    host.querySelector('#swBtn').addEventListener('click', SW.switchAccount);
    host.querySelector('#outBtn').addEventListener('click', SW.signOut);
    host.querySelector('#resetBtn').addEventListener('click', function () {
      SW.modal({
        title: 'Reset demo data?',
        body: '<p class="muted">Agent runs, assistant history and all uploaded documents will be discarded. The two seeded demo documents are re-indexed. Your session stays signed in.</p>',
        footer: '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-danger" id="doReset">Reset data</button>',
        onMount: function (m) {
          m.querySelector('#doReset').addEventListener('click', function () {
            SW.state.runs = []; SW.state.chat = []; SW.state.docs = []; SW.state.chunks = [];
            SW.initRag();
            SW.closeModal();
            SW.toast('Demo data reset', 'Runs and chat cleared · seeded documents re-indexed.', 'ok');
            SW.render();
          });
        }
      });
    });

    if (SW.can('manageUsers')) {
      var body = host.querySelector('#userBody');
      function drawUsers() {
        body.innerHTML = SW.state.users.map(function (x) {
          var caps = x.role === 'Viewer' ? 'read-only' : x.role === 'Admin' ? 'all capabilities' : 'upload · delete · run · advance';
          return '<tr><td class="strong">' + SW.esc(x.name) + (x.email === u.email ? ' <span class="tag-demo">you</span>' : '') + '</td>' +
            '<td class="mono">' + SW.esc(x.email) + '</td>' +
            '<td><span class="role-chip role-' + x.role.toLowerCase() + '">' + x.role + '</span></td>' +
            '<td class="faint">' + caps + '</td>' +
            '<td class="nowrap"><select data-setrole="' + SW.esc(x.email) + '" aria-label="Change role for ' + SW.esc(x.name) + '">' +
              ['Admin', 'Analyst', 'Viewer'].map(function (r) {
                return '<option' + (r === x.role ? ' selected' : '') + '>' + r + '</option>'; }).join('') + '</select></td></tr>';
        }).join('');
      }
      body.addEventListener('change', function (e) {
        var s = e.target.closest('[data-setrole]'); if (!s) return;
        var target = SW.state.users.filter(function (x) { return x.email === s.dataset.setrole; })[0];
        if (!target) return;
        target.role = s.value;
        SW.toast('Role updated', SW.esc(target.name) + ' is now ' + target.role + '.', 'ok');
        if (SW.state.user && SW.state.user.email === target.email) {
          SW.state.user.role = target.role;
          SW.render();
        } else drawUsers();
      });
      drawUsers();
    }
  } });
})();
