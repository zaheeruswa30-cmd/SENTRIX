/* Sentrix — monitoring views: dashboard, endpoints, endpoint detail, events. */
(function () {
  'use strict';
  var SW = window.SW;

  /* ---------- shared bits ---------- */
  SW.head = function (title, sub, actions) {
    return '<div class="page-head"><div><h1>' + title + '</h1><p>' + sub + '</p></div>' +
      '<div class="head-actions">' + (actions || '') + '</div></div>';
  };
  SW.banner = function () {
    return '<div class="demo-banner reveal" role="note">' + SW.icon('warn', 20) +
      '<p><b>Synthetic demo data.</b> Every hostname, alert, metric, document and AI output on this screen is fabricated for demonstration. ' +
      'Nothing is connected to a live environment and no response or remediation actions exist — investigation guidance only.</p></div>';
  };
  SW.emptyState = function (title, body, action) {
    return '<div class="empty"><div class="empty-ico">' + SW.icon('search', 22) + '</div><b>' + SW.esc(title) + '</b>' +
      '<p>' + SW.esc(body) + '</p>' + (action || '') + '</div>';
  };
  SW.sevRank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

  SW.counts = function () {
    var st = SW.state;
    var online = st.endpoints.filter(function (e) { return e.online; }).length;
    var crit = st.events.filter(function (e) { return e.severity === 'CRITICAL'; }).length;
    var high = st.events.filter(function (e) { return e.severity === 'HIGH'; }).length;
    var openInc = st.incidents.filter(function (i) { return i.stage < 5; }).length;
    var fleetRisk = Math.round(st.endpoints.reduce(function (a, e) { return a + e.risk; }, 0) / st.endpoints.length);
    return { total: st.endpoints.length, online: online, offline: st.endpoints.length - online,
      crit: crit, high: high, openInc: openInc, fleetRisk: fleetRisk, events: st.events.length };
  };
  SW.sevCounts = function (events) {
    var m = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    (events || SW.state.events).forEach(function (e) { if (m[e.severity] !== undefined) m[e.severity]++; });
    return m;
  };

  /* ================= Dashboard ================= */
  SW.route('dashboard', { title: 'Command Center', render: function (host) {
    host.innerHTML = SW.banner() +
      SW.head('Command Center', 'Fleet detection posture · computed live from the in-memory synthetic dataset',
        '<span class="badge offline"><i class="shape sh-ring" style="background:currentColor"></i>SYNTHETIC</span>' +
        '<button class="btn btn-ghost" id="simBtn">' + SW.icon('warn', 15) + 'Simulate new critical alert</button>' +
        '<button class="btn btn-primary" id="snapBtn">' + SW.icon('export', 15) + 'Export snapshot</button>') +
      '<div id="dashSkeleton"><div class="grid g4 mb">' + Array(4).join() +
        '<div class="sk sk-card"></div><div class="sk sk-card"></div><div class="sk sk-card"></div><div class="sk sk-card"></div></div>' +
        '<div class="grid g-2-1 mb"><div class="sk" style="height:320px;border-radius:14px"></div><div class="sk" style="height:320px;border-radius:14px"></div></div></div>' +
      '<div id="dashBody" hidden></div>';

    var body = host.querySelector('#dashBody');
    host.querySelector('#simBtn').addEventListener('click', function () { SW.pushLiveAlert(); });
    host.querySelector('#snapBtn').addEventListener('click', function () {
      var c = SW.counts(), st = SW.rag.stats();
      var md = ['# Sentrix — fleet snapshot (synthetic demo)', '', 'Generated ' + SW.fmtDate(new Date()), '',
        '| Metric | Value |', '|---|---|',
        '| Endpoints | ' + c.total + ' |', '| Online | ' + c.online + ' |', '| Events in window | ' + c.events + ' |',
        '| Critical events | ' + c.crit + ' |', '| Open incidents | ' + c.openInc + ' |',
        '| Mean endpoint risk | ' + c.fleetRisk + ' |', '| Indexed documents | ' + st.docs + ' |', '| Vector chunks | ' + st.chunks + ' |',
        '| Agent runs this session | ' + SW.state.runs.length + ' |'].join('\n');
      var blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = 'sentrix-snapshot.md';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      SW.toast('Snapshot exported', 'sentrix-snapshot.md written from live in-memory counters', 'ok');
    });

    setTimeout(function () {
      var sk = host.querySelector('#dashSkeleton');
      if (!sk || !document.body.contains(host)) return;   // navigated away before the skeleton resolved
      sk.remove();
      body.hidden = false;
      renderDash(body);
      SW.revealAll(body);
    }, SW.reduced ? 0 : 380);
  } });

  function kpiCard(k) {
    return '<div class="kpi reveal"><div class="k-label">' + k.label + '</div><div class="k-value">' + k.value + '</div>' +
      SW.spark(k.spark, k.color) +
      '<div class="k-foot"><span class="delta ' + k.dir + '">' + k.delta + '</span><span>·</span><span>' + k.foot + '</span></div></div>';
  }

  function renderDash(body) {
    var c = SW.counts(), sev = SW.sevCounts(), st = SW.rag.stats();
    body.innerHTML =
      '<div class="grid g4 mb" id="kpiRow">' + [
        kpiCard({ label: 'Managed endpoints', value: c.total, delta: '+2 wk', dir: 'flat', foot: c.online + ' reporting', spark: [9, 10, 10, 11, 11, 12, 12], color: '#38BDF8' }),
        kpiCard({ label: 'Events in window', value: c.events, delta: '+' + Math.max(1, Math.round(c.events / 8)) + ' 24h', dir: 'up', foot: 'live in-memory feed', spark: [14, 17, 15, 19, 21, 23, c.events], color: '#2DD4BF' }),
        kpiCard({ label: 'Critical + high', value: c.crit + c.high, delta: c.crit + ' critical', dir: 'up', foot: 'awaiting triage', spark: [3, 4, 5, 4, 6, 7, c.crit + c.high], color: '#FB7185' }),
        kpiCard({ label: 'Open incidents', value: c.openInc, delta: SW.state.runs.length + ' runs', dir: 'flat', foot: 'agent runs this session', spark: [2, 2, 3, 3, 3, 3, c.openInc], color: '#FB923C' })
      ].join('') + '</div>' +

      '<div class="grid g-2-1 mb">' +
        '<div class="card reveal"><div class="card-head"><div><h3>Security event trend</h3>' +
          '<div class="faint">7 days by severity · today’s bar recomputes as the feed and filters change</div></div>' +
          '<span class="prov-tag prov-telemetry"><i></i>Endpoint telemetry</span></div>' +
          '<div class="chart-box h260"><canvas id="trendChart" aria-label="Seven day security event trend by severity"></canvas></div>' +
          '<div class="legend"><span><i style="background:#FB7185"></i>Critical</span><span><i style="background:#FB923C"></i>High</span>' +
          '<span><i style="background:#FBBF24"></i>Medium</span><span><i style="background:#38BDF8"></i>Low</span></div></div>' +
        '<div class="card reveal"><div class="card-head"><h3>Fleet risk score</h3>' + SW.badge(SW.sevOf(c.fleetRisk)) + '</div>' +
          '<div class="gauge-wrap"><div class="gauge" id="riskGauge"></div><div>' +
          '<div class="faint">Mean of the standing risk scores of all ' + c.total + ' endpoints. Recomputes when an agent run raises a host’s risk.</div>' +
          '<div class="hr"></div><dl class="kv"><dt>Highest host</dt><dd>' + hottest().host + ' · ' + hottest().risk + '</dd>' +
          '<dt>Critical events</dt><dd>' + c.crit + '</dd><dt>Model</dt><dd>demo heuristic</dd></dl></div></div></div>' +
      '</div>' +

      '<div class="grid g3 mb">' +
        '<div class="card reveal"><div class="card-head"><h3>Severity distribution</h3></div>' +
          '<div class="chart-box h220"><canvas id="sevChart" aria-label="Severity distribution"></canvas></div><div class="legend" id="sevLegend"></div></div>' +
        '<div class="card reveal"><div class="card-head"><h3>Endpoint health by group</h3></div>' +
          '<div class="chart-box h220"><canvas id="healthChart" aria-label="Mean health score by group"></canvas></div>' +
          '<div class="faint" style="margin-top:10px">Mean security health score (0–100) per asset group.</div></div>' +
        '<div class="card reveal"><div class="card-head"><h3>Risk distribution</h3></div>' +
          '<div class="chart-box h220"><canvas id="riskChart" aria-label="Endpoint count by risk band"></canvas></div>' +
          '<div class="faint" style="margin-top:10px">' + c.total + ' endpoints bucketed by current risk band.</div></div>' +
      '</div>' +

      '<div class="grid g-2-1 mb">' +
        '<div class="card reveal"><div class="card-head"><div><h3>Recent security events</h3>' +
          '<div class="faint">Newest first · new synthetic alerts append live</div></div>' +
          '<a class="btn btn-ghost" href="#/events">All events' + SW.icon('arrow', 15) + '</a></div>' +
          '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Endpoint</th><th>Detection</th><th></th></tr></thead>' +
          '<tbody id="feedBody"></tbody></table></div></div>' +
        '<div style="display:flex;flex-direction:column;gap:18px;min-width:0">' +
          '<div class="card reveal"><div class="card-head"><h3>Agent activity</h3><span class="prov-tag prov-ai"><i></i>Simulated engine</span></div>' +
            '<div id="agentMini"></div><div class="hr"></div><a class="btn btn-ghost" href="#/ai-center">Open AI Security Center</a></div>' +
          '<div class="card reveal"><div class="card-head"><h3>Knowledge base</h3><span class="prov-tag prov-rag"><i></i>Retrieved docs</span></div>' +
            '<dl class="kv"><dt>Indexed documents</dt><dd id="kbDocs">' + st.docs + '</dd>' +
            '<dt>Vector chunks</dt><dd id="kbChunks">' + st.chunks + '</dd>' +
            '<dt>Vocabulary</dt><dd>' + st.terms + ' terms</dd>' +
            '<dt>Embedding</dt><dd>TF-IDF (client-side)</dd>' +
            '<dt>Index status</dt><dd style="color:#34D399">' + (st.chunks ? 'READY' : 'EMPTY') + '</dd></dl>' +
            '<div class="hr"></div><a class="btn btn-ghost" href="#/rag">Manage knowledge base</a></div>' +
        '</div>' +
      '</div>' +

      '<div class="card panel reveal"><div class="card-head"><div><h3>' + SW.state.incidents[0].id + ' lifecycle</h3>' +
        '<div class="faint">' + SW.esc(SW.state.incidents[0].title) + '</div></div>' +
        '<a class="btn btn-ghost" href="#/incident/' + SW.state.incidents[0].id + '">Open investigation</a></div>' +
        '<div class="rail">' + railHTML(SW.state.incidents[0]) + '</div></div>';

    drawGauge(body.querySelector('#riskGauge'), c.fleetRisk);
    drawCharts(body);
    renderFeed();
    renderAgentMini();

    function renderFeed() {
      var rows = SW.state.events.slice(0, 8).map(function (e) {
        return '<tr' + (e.live ? ' class="row-new"' : '') + '><td class="mono nowrap">' + SW.fmtTime(e.ts) + '</td>' +
          '<td>' + SW.badge(e.severity) + '</td><td class="mono strong">' + e.endpoint + '</td>' +
          '<td>' + SW.esc(e.title) + '</td>' +
          '<td class="nowrap"><a class="linkish" href="#/event/' + e.id + '">Inspect</a></td></tr>';
      }).join('');
      body.querySelector('#feedBody').innerHTML = rows;
    }
    function renderAgentMini() {
      var el = body.querySelector('#agentMini');
      if (!SW.state.runs.length) {
        el.innerHTML = '<p class="faint">No agent runs yet in this session. Open a security event and choose “Run analysis” to execute the pipeline.</p>';
        return;
      }
      el.innerHTML = '<ul class="list-clean">' + SW.state.runs.slice(0, 4).map(function (r) {
        return '<li class="event-line"><span class="dotcol"><span class="status-dot ' + (r.status === 'running' ? 'online' : 'offline') + '"></span></span>' +
          '<span class="txt"><b>' + r.id + ' <span class="chip-state ' + (r.status === 'complete' ? 'done' : 'running') + '" style="margin-left:6px">' + r.status + '</span></b>' +
          '<span style="display:block;color:var(--text-mid);font-family:var(--font-body);font-size:12.5px;margin:3px 0">' +
          SW.esc(r.eventId + ' · ' + r.eventTitle) + '</span>' +
          '<span>' + (r.risk ? 'risk ' + r.risk.risk + ' · ' : '') + r.duration + 'ms · ' + SW.ago(r.startedAt) + '</span></span></li>';
      }).join('') + '</ul>';
    }
    document.removeEventListener('sw:newevent', body._onNew || function () {});
    body._onNew = function () {
      if (!document.body.contains(body)) return;
      renderFeed();
      var c2 = SW.counts();
      var kpis = body.querySelectorAll('#kpiRow .k-value');
      if (kpis[1]) kpis[1].textContent = c2.events;
      if (kpis[2]) kpis[2].textContent = c2.crit + c2.high;
      drawCharts(body, true);
    };
    SW.listen('sw:newevent', body._onNew);
    SW.listen('sw:runupdate', function () {
      if (document.body.contains(body)) renderAgentMini();
    });
  }

  function hottest() {
    return SW.state.endpoints.slice().sort(function (a, b) { return b.risk - a.risk; })[0];
  }
  function drawGauge(el, val) {
    if (!el) return;
    var R = 52, CIRC = 2 * Math.PI * R, span = 0.75;
    el.innerHTML = '<svg width="116" height="116" viewBox="0 0 116 116" role="img" aria-label="Fleet risk score ' + val + ' of 100">' +
      '<defs><linearGradient id="gg" x1="0" y1="1" x2="1" y2="0"><stop offset="0%" stop-color="#34D399"/>' +
      '<stop offset="40%" stop-color="#FBBF24"/><stop offset="72%" stop-color="#FB923C"/><stop offset="100%" stop-color="#FB7185"/></linearGradient></defs>' +
      '<circle cx="58" cy="58" r="' + R + '" fill="none" stroke="#151E2E" stroke-width="9" stroke-linecap="round" stroke-dasharray="' + CIRC * span + ' ' + CIRC + '" transform="rotate(135 58 58)"/>' +
      '<circle cx="58" cy="58" r="' + R + '" fill="none" stroke="url(#gg)" stroke-width="9" stroke-linecap="round" stroke-dasharray="' + CIRC * span * val / 100 + ' ' + CIRC + '" transform="rotate(135 58 58)"/></svg>' +
      '<div class="g-center"><div class="g-val">' + val + '</div><div class="g-max">/ 100 ' + SW.sevOf(val).toLowerCase() + '</div></div>';
  }

  function drawCharts(body, refresh) {
    var sev = SW.sevCounts();
    var days = SW.seed.trendDays.concat(['Today']);
    var seed = SW.seed.trendSeed;
    var series = [
      ['Critical', seed.CRITICAL.concat([sev.CRITICAL]), '#FB7185', 'rgba(251,113,133,.10)'],
      ['High', seed.HIGH.concat([sev.HIGH]), '#FB923C', 'rgba(251,146,60,.08)'],
      ['Medium', seed.MEDIUM.concat([sev.MEDIUM]), '#FBBF24', null],
      ['Low', seed.LOW.concat([sev.LOW]), '#38BDF8', null]
    ];
    if (refresh) { SW.destroyCharts(); }
    SW.chart(body.querySelector('#trendChart'), {
      type: 'line',
      data: { labels: days, datasets: series.map(function (s) {
        return { label: s[0], data: s[1], borderColor: s[2], backgroundColor: s[3] || 'transparent', fill: !!s[3], tension: .35, pointRadius: 2.5, borderWidth: 2 };
      }) },
      options: { layout: { padding: { top: 6, right: 6 } }, interaction: { mode: 'index', intersect: false },
        scales: { x: SW.axis({ grid: { display: false } }), y: SW.axis({ beginAtZero: true, ticks: { color: '#63728A', padding: 8, maxTicksLimit: 6 } }) } }
    });
    var order = [['Critical', sev.CRITICAL, '#FB7185'], ['High', sev.HIGH, '#FB923C'], ['Medium', sev.MEDIUM, '#FBBF24'], ['Low', sev.LOW, '#38BDF8'], ['Info', sev.INFO, '#34D399']];
    SW.chart(body.querySelector('#sevChart'), {
      type: 'doughnut',
      data: { labels: order.map(function (o) { return o[0]; }), datasets: [{ data: order.map(function (o) { return o[1]; }), backgroundColor: order.map(function (o) { return o[2]; }), borderColor: '#0F1623', borderWidth: 2, hoverOffset: 6 }] },
      options: { cutout: '66%', layout: { padding: 6 } }
    });
    var lg = body.querySelector('#sevLegend');
    if (lg) lg.innerHTML = order.map(function (o) { return '<span><i style="background:' + o[2] + '"></i>' + o[0] + ' · ' + o[1] + '</span>'; }).join('');

    var groups = {};
    SW.state.endpoints.forEach(function (e) { (groups[e.group] = groups[e.group] || []).push(e); });
    var gk = Object.keys(groups);
    SW.chart(body.querySelector('#healthChart'), {
      type: 'bar',
      data: { labels: gk, datasets: [{ data: gk.map(function (k) {
        return Math.round(groups[k].reduce(function (a, e) { return a + e.health; }, 0) / groups[k].length); }),
        backgroundColor: gk.map(function (k) {
          var v = groups[k].reduce(function (a, e) { return a + e.health; }, 0) / groups[k].length;
          return v >= 80 ? '#34D399' : v >= 65 ? '#2DD4BF' : v >= 55 ? '#FBBF24' : '#FB923C'; }), borderRadius: 5, barThickness: 16 }] },
      options: { indexAxis: 'y', layout: { padding: { right: 10 } },
        scales: { x: SW.axis({ beginAtZero: true, max: 100, ticks: { color: '#63728A', padding: 6, maxTicksLimit: 5 } }),
          y: SW.axis({ grid: { display: false }, ticks: { color: '#9AA9BF', padding: 6 } }) } }
    });
    var bands = [0, 0, 0, 0];
    SW.state.endpoints.forEach(function (e) {
      bands[e.risk >= 80 ? 3 : e.risk >= 60 ? 2 : e.risk >= 40 ? 1 : 0]++;
    });
    SW.chart(body.querySelector('#riskChart'), {
      type: 'bar',
      data: { labels: ['Low', 'Guarded', 'Elevated', 'Critical'], datasets: [{ data: bands, backgroundColor: ['#38BDF8', '#2DD4BF', '#FBBF24', '#FB7185'], borderRadius: 6, barThickness: 34 }] },
      options: { scales: { x: SW.axis({ grid: { display: false }, ticks: { color: '#9AA9BF' } }), y: SW.axis({ beginAtZero: true, ticks: { color: '#63728A', maxTicksLimit: 5, precision: 0 } }) } }
    });
  }

  function railHTML(inc) {
    return SW.seed.stages.map(function (s, i) {
      var cls = i < inc.stage ? 'done' : i === inc.stage ? 'current' : 'todo';
      return '<div class="rail-node ' + cls + '"><div class="rail-dot">' + (cls === 'done' ? '✓' : i + 1) + '</div>' +
        '<div class="rail-name">' + s + '</div><div class="rail-time">' + (cls === 'todo' ? 'pending' : cls === 'current' ? 'in progress' : 'complete') + '</div></div>';
    }).join('');
  }
  SW.railHTML = railHTML;

  /* ================= Endpoints ================= */
  SW.route('endpoints', { title: 'Endpoints', render: function (host) {
    var q = '', group = 'all', sort = 'risk';
    host.innerHTML = SW.head('Endpoints', SW.state.endpoints.length + ' managed synthetic agents · click any card for the detail view',
      '<div class="searchbox" style="width:240px">' + SW.icon('search', 16) + '<input id="epSearch" type="search" placeholder="Filter host, OS, IP…" aria-label="Filter endpoints"></div>' +
      '<select id="epGroup" aria-label="Filter by group"><option value="all">All groups</option>' +
        Array.from(new Set(SW.state.endpoints.map(function (e) { return e.group; }))).map(function (g) { return '<option>' + g + '</option>'; }).join('') + '</select>' +
      '<select id="epSort" aria-label="Sort endpoints"><option value="risk">Sort: risk ↓</option><option value="health">Sort: health ↑</option><option value="host">Sort: host A–Z</option></select>') +
      '<div class="grid g4" id="epGrid"></div>';

    function draw() {
      var list = SW.state.endpoints.filter(function (e) {
        var okQ = !q || (e.host + ' ' + e.os + ' ' + e.ip + ' ' + e.user).toLowerCase().indexOf(q) >= 0;
        return okQ && (group === 'all' || e.group === group);
      });
      list.sort(function (a, b) {
        if (sort === 'risk') return b.risk - a.risk;
        if (sort === 'health') return a.health - b.health;
        return a.host.localeCompare(b.host);
      });
      var grid = host.querySelector('#epGrid');
      grid.innerHTML = list.length ? list.map(function (e) {
        return '<a class="ep-card reveal" href="#/endpoint/' + e.id + '">' +
          '<div class="ep-top"><div style="min-width:0"><div class="ep-host">' + e.host + '</div>' +
            '<div class="ep-os">' + SW.icon(SW.osIcon(e.os), 14) + '<span>' + SW.esc(e.os) + '</span></div>' +
            '<div class="ep-os"><span class="status-dot ' + (e.online ? 'online' : 'offline') + '"></span><span>' + (e.online ? 'Online · ' + e.lastSeen : 'Offline · ' + e.lastSeen) + '</span></div></div>' +
            SW.ring(e.health) + '</div>' +
          '<div class="ep-meta"><span>Risk<b>' + e.risk + '</b></span><span>IP<b>' + e.ip + '</b></span><span>User<b>' + SW.esc(e.user) + '</b></span>' +
            '<span>Events<b>' + SW.state.events.filter(function (x) { return x.endpoint === e.id; }).length + '</b></span></div>' +
          '<div class="meter">' + meterRow('CPU', e.cpu) + meterRow('MEM', e.mem) + meterRow('DSK', e.disk) + '</div></a>';
      }).join('') : SW.emptyState('No endpoints match', 'Clear the search or pick another group.');
      SW.revealAll(grid);
    }
    function meterRow(l, v) {
      return '<div class="meter-row"><span class="lbl">' + l + '</span><span class="bar"><i class="' + (v > 80 ? 'crit' : v > 65 ? 'warn' : '') + '" style="width:' + v + '%"></i></span><span class="val">' + v + '%</span></div>';
    }
    host.querySelector('#epSearch').addEventListener('input', function () { q = this.value.trim().toLowerCase(); draw(); });
    host.querySelector('#epGroup').addEventListener('change', function () { group = this.value; draw(); });
    host.querySelector('#epSort').addEventListener('change', function () { sort = this.value; draw(); });
    draw();
  } });

  /* ================= Endpoint detail ================= */
  SW.route('endpoint', { title: 'Endpoint detail', render: function (host, id) {
    var e = SW.state.endpoints.filter(function (x) { return x.id === id; })[0];
    if (!e) { host.innerHTML = SW.emptyState('Endpoint not found', 'No endpoint with id ' + (id || '—') + ' in the dataset.', '<a class="btn btn-primary" href="#/endpoints">Back to endpoints</a>'); return; }
    var evs = SW.state.events.filter(function (x) { return x.endpoint === e.id; });
    var incs = SW.state.incidents.filter(function (x) { return x.endpoint === e.id; });
    var runs = SW.state.runs.filter(function (r) { return r.endpoint === e.id; });

    host.innerHTML = '<div class="crumbs"><a href="#/endpoints">Endpoints</a>' + SW.icon('arrow', 13) + '<span>' + e.host + '</span></div>' +
      SW.head(e.host, SW.esc(e.os) + ' · ' + e.group + ' · ' + e.ip + ' · agent ' + e.agent,
        SW.badge(SW.sevOf(e.risk)) + '<span class="badge ' + (e.online ? 'info' : 'offline') + '"><i class="shape ' + (e.online ? 'sh-circle' : 'sh-ring') + '" style="background:currentColor"></i>' + (e.online ? 'ONLINE' : 'OFFLINE') + '</span>') +
      '<div class="grid g4 mb">' +
        statCard('Standing risk', e.risk + ' / 100', SW.sevOf(e.risk).toLowerCase(), e.risk) +
        statCard('Health score', e.health + ' / 100', 'security posture', e.health) +
        statCard('Open events', String(evs.length), evs.filter(function (x) { return x.severity === 'CRITICAL'; }).length + ' critical', Math.min(100, evs.length * 12)) +
        statCard('Patch drift', e.patchDrift + ' pkgs', 'behind baseline', Math.min(100, e.patchDrift * 8)) +
      '</div>' +
      '<div class="card panel">' +
        '<div class="tabs" id="epTabs" role="tablist">' +
          tab('t-over', 'Overview', true) + tab('t-tel', 'Telemetry') + tab('t-ev', 'Events (' + evs.length + ')') +
          tab('t-inc', 'Incidents (' + incs.length + ')') + tab('t-ai', 'AI runs (' + runs.length + ')') +
        '</div>' +
        '<div id="epPanels">' +
          '<div class="tab-panel active" id="t-over"><div class="grid g2">' +
            '<div><h3 style="margin-bottom:10px">Asset facts</h3><dl class="kv">' +
              '<dt>Hostname</dt><dd>' + e.host + '</dd><dt>Operating system</dt><dd>' + SW.esc(e.os) + '</dd>' +
              '<dt>Group</dt><dd>' + e.group + '</dd><dt>IP address</dt><dd>' + e.ip + '</dd>' +
              '<dt>Primary user</dt><dd>' + SW.esc(e.user) + '</dd><dt>Agent build</dt><dd>' + e.agent + '</dd>' +
              '<dt>Last check-in</dt><dd>' + e.lastSeen + '</dd>' +
              (e.priorRisk !== undefined ? '<dt>Risk before run</dt><dd>' + e.priorRisk + ' → ' + e.risk + '</dd>' : '') +
            '</dl></div>' +
            '<div><h3 style="margin-bottom:10px">Resource utilisation</h3>' +
              '<div class="chart-box h180"><canvas id="epChart" aria-label="Resource utilisation"></canvas></div>' +
              '<p class="faint" style="margin-top:10px">Synthetic point-in-time sample; no live agent is connected.</p></div>' +
          '</div></div>' +
          '<div class="tab-panel" id="t-tel"><span class="prov-tag prov-telemetry" style="margin-bottom:10px;display:inline-flex"><i></i>Raw telemetry</span>' +
            '<div class="pre">' + SW.esc(processTree(e, evs)) + '</div></div>' +
          '<div class="tab-panel" id="t-ev">' + (evs.length ? eventTable(evs) : SW.emptyState('No events', 'This host has no events in the current window.')) + '</div>' +
          '<div class="tab-panel" id="t-inc">' + (incs.length ? incs.map(incRow).join('') : SW.emptyState('No incidents', 'No incident references this host.')) + '</div>' +
          '<div class="tab-panel" id="t-ai">' + (runs.length ? runs.map(function (r) {
            return '<div class="doc-row"><span class="doc-icon">' + SW.icon('ai', 16) + '</span><span class="doc-main">' +
              '<span class="doc-name">' + r.id + ' · ' + SW.esc(r.eventTitle) + '</span>' +
              '<span class="doc-meta">' + (r.risk ? 'risk ' + r.risk.risk + ' (' + r.risk.band + ') · ' : '') + r.duration + 'ms · ' + r.citations.length + ' citations</span></span>' +
              '<a class="btn btn-ghost" href="#/ai-center">Open trace</a></div>';
          }).join('') : SW.emptyState('No agent runs for this host', 'Open an event on ' + e.host + ' and choose “Run analysis”.')) + '</div>' +
        '</div></div>';

    wireTabs(host.querySelector('#epTabs'), host.querySelector('#epPanels'));
    SW.chart(host.querySelector('#epChart'), {
      type: 'bar',
      data: { labels: ['CPU', 'Memory', 'Disk', 'Patch drift'], datasets: [{ data: [e.cpu, e.mem, e.disk, Math.min(100, e.patchDrift * 8)], backgroundColor: ['#38BDF8', '#2DD4BF', '#A78BFA', '#FB923C'], borderRadius: 6, barThickness: 26 }] },
      options: { scales: { x: SW.axis({ grid: { display: false }, ticks: { color: '#9AA9BF' } }), y: SW.axis({ beginAtZero: true, max: 100 }) } }
    });
    SW.revealAll(host);
  } });

  function statCard(label, value, foot, pct) {
    return '<div class="kpi reveal"><div class="k-label">' + label + '</div><div class="k-value" style="font-size:26px">' + value + '</div>' +
      '<div class="bar" style="margin-top:12px"><i class="' + (pct > 79 ? 'crit' : pct > 59 ? 'warn' : '') + '" style="width:' + Math.min(100, pct) + '%"></i></div>' +
      '<div class="k-foot"><span>' + foot + '</span></div></div>';
  }
  function tab(id, label, active) {
    return '<button class="tab' + (active ? ' active' : '') + '" role="tab" aria-selected="' + !!active + '" data-target="' + id + '">' + label + '</button>';
  }
  function wireTabs(tabsEl, panelsEl) {
    if (!tabsEl) return;
    tabsEl.addEventListener('click', function (ev) {
      var t = ev.target.closest('.tab'); if (!t) return;
      tabsEl.querySelectorAll('.tab').forEach(function (x) { x.classList.remove('active'); x.setAttribute('aria-selected', 'false'); });
      t.classList.add('active'); t.setAttribute('aria-selected', 'true');
      panelsEl.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.toggle('active', p.id === t.dataset.target); });
    });
  }
  SW.wireTabs = wireTabs;

  function processTree(e, evs) {
    var lines = ['# synthetic process / auth telemetry sample — ' + e.host + ' (' + e.os + ')', ''];
    evs.slice(0, 6).forEach(function (ev) {
      lines.push(SW.fmtTime(ev.ts) + '  ' + ev.severity + '  ' + ev.type + '  [' + ev.id + ']');
      Object.keys(ev.fields).forEach(function (k) { lines.push('    ' + k.padEnd(18) + ' ' + ev.fields[k]); });
      lines.push('');
    });
    if (evs.length === 0) lines.push('(no events recorded for this host in the current window)');
    return lines.join('\n');
  }
  function eventTable(evs) {
    return '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Detection</th><th>Status</th><th></th></tr></thead><tbody>' +
      evs.map(function (e) {
        return '<tr><td class="mono nowrap">' + SW.fmtTime(e.ts) + '</td><td>' + SW.badge(e.severity) + '</td>' +
          '<td class="nowrap">' + e.type + '</td><td class="strong">' + SW.esc(e.title) + '</td><td><span class="faint">' + e.status + '</span></td>' +
          '<td class="nowrap"><a class="linkish" href="#/event/' + e.id + '">Inspect</a></td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function incRow(i) {
    return '<div class="doc-row"><span class="doc-icon" style="background:rgba(251,113,133,.10);color:var(--sev-critical)">' + SW.icon('incident', 16) + '</span>' +
      '<span class="doc-main"><span class="doc-name">' + i.id + ' · ' + SW.esc(i.title) + '</span>' +
      '<span class="doc-meta">' + i.severity + ' · stage ' + SW.seed.stages[i.stage] + ' · ' + i.analyst + '</span></span>' +
      '<a class="btn btn-ghost" href="#/incident/' + i.id + '">Open</a></div>';
  }
  SW.incRow = incRow;

  /* ================= Security events ================= */
  SW.route('events', { title: 'Security Events', render: function (host) {
    var f = { q: '', sev: 'all', type: 'all', ep: 'all', sort: 'ts', dir: -1, page: 1, per: 10 };
    var types = Array.from(new Set(SW.state.events.map(function (e) { return e.type; }))).sort();
    var eps = Array.from(new Set(SW.state.events.map(function (e) { return e.endpoint; }))).sort();

    host.innerHTML = SW.head('Security Events', 'Filter, sort and page through the in-memory event stream · run the analysis pipeline on any row',
      '<button class="btn btn-ghost" id="simBtn2">' + SW.icon('warn', 15) + 'Simulate alert</button>') +
      '<div class="card mb"><div class="filters">' +
        '<div class="searchbox" style="flex:1 1 220px">' + SW.icon('search', 16) + '<input id="fq" type="search" placeholder="Search title, id, field values…" aria-label="Search events"></div>' +
        '<select id="fsev" aria-label="Filter severity"><option value="all">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>' +
        '<select id="ftype" aria-label="Filter type"><option value="all">All types</option>' + types.map(function (t) { return '<option>' + t + '</option>'; }).join('') + '</select>' +
        '<select id="fep" aria-label="Filter endpoint"><option value="all">All endpoints</option>' + eps.map(function (t) { return '<option>' + t + '</option>'; }).join('') + '</select>' +
        '<button class="btn btn-ghost" id="fclear">Clear</button>' +
      '</div>' +
      '<div class="chart-box h180" style="margin-top:14px"><canvas id="evChart" aria-label="Filtered events by severity"></canvas></div>' +
      '<div class="faint" style="margin-top:8px">Chart recomputes from the filtered result set (<span id="evCount">0</span> events).</div></div>' +
      '<div class="card"><div class="table-wrap"><table id="evTable"><thead><tr>' +
        th('ts', 'Time') + '<th>Severity</th>' + th('type', 'Type') + th('endpoint', 'Endpoint') + '<th>Detection</th>' + th('status', 'Status') + '<th>Analysis</th>' +
        '</tr></thead><tbody id="evBody"></tbody></table></div>' +
        '<div class="pager" id="pager"></div></div>';

    function th(key, label) {
      return '<th><button class="sort-btn" data-sort="' + key + '">' + label + '<span class="sort-ind" data-for="' + key + '"></span></button></th>';
    }
    function filtered() {
      var q = f.q;
      var list = SW.state.events.filter(function (e) {
        if (f.sev !== 'all' && e.severity !== f.sev) return false;
        if (f.type !== 'all' && e.type !== f.type) return false;
        if (f.ep !== 'all' && e.endpoint !== f.ep) return false;
        if (!q) return true;
        var hay = (e.id + ' ' + e.title + ' ' + e.type + ' ' + e.endpoint + ' ' + e.status + ' ' +
          Object.keys(e.fields).map(function (k) { return k + ' ' + e.fields[k]; }).join(' ')).toLowerCase();
        return hay.indexOf(q) >= 0;
      });
      list.sort(function (a, b) {
        var av, bv;
        if (f.sort === 'ts') { av = new Date(a.ts).getTime(); bv = new Date(b.ts).getTime(); }
        else if (f.sort === 'severity') { av = SW.sevRank[a.severity]; bv = SW.sevRank[b.severity]; }
        else { av = String(a[f.sort]); bv = String(b[f.sort]); return f.dir * av.localeCompare(bv); }
        return f.dir * (av - bv);
      });
      return list;
    }
    function draw() {
      var list = filtered();
      host.querySelector('#evCount').textContent = list.length;
      var pages = Math.max(1, Math.ceil(list.length / f.per));
      if (f.page > pages) f.page = pages;
      var slice = list.slice((f.page - 1) * f.per, f.page * f.per);
      host.querySelector('#evBody').innerHTML = slice.length ? slice.map(function (e) {
        var runBtn = '<button class="btn btn-primary btn-sm" data-run="' + e.id + '">' + SW.icon('play', 14) + 'Run analysis</button>';
        return '<tr' + (e.live ? ' class="row-new"' : '') + '><td class="mono nowrap">' + SW.fmtTime(e.ts) + '<div class="faint mono">' + new Date(e.ts).toISOString().slice(5, 10) + '</div></td>' +
          '<td>' + SW.badge(e.severity) + '</td><td class="nowrap">' + e.type + '</td>' +
          '<td class="mono strong"><a class="linkish" href="#/endpoint/' + e.endpoint + '">' + e.endpoint + '</a></td>' +
          '<td class="strong"><a class="linkish" href="#/event/' + e.id + '">' + SW.esc(e.title) + '</a><div class="faint mono">' + e.id + '</div></td>' +
          '<td><span class="faint">' + e.status + '</span></td>' +
          '<td class="nowrap">' + SW.gate('run', runBtn) + '</td></tr>';
      }).join('') : '<tr><td colspan="7">' + SW.emptyState('No events match these filters', 'Widen the severity, type or endpoint filter, or clear the search.') + '</td></tr>';

      host.querySelector('#pager').innerHTML = '<span class="faint">Showing ' + (list.length ? (f.page - 1) * f.per + 1 : 0) + '–' +
        Math.min(list.length, f.page * f.per) + ' of ' + list.length + '</span>' +
        '<span class="pager-btns"><button class="btn btn-ghost btn-sm" data-pg="prev"' + (f.page === 1 ? ' disabled' : '') + '>Previous</button>' +
        '<span class="faint mono">page ' + f.page + ' / ' + pages + '</span>' +
        '<button class="btn btn-ghost btn-sm" data-pg="next"' + (f.page >= pages ? ' disabled' : '') + '>Next</button></span>';

      host.querySelectorAll('.sort-ind').forEach(function (s) {
        s.textContent = s.dataset.for === f.sort ? (f.dir < 0 ? '↓' : '↑') : '';
      });
      var sev = SW.sevCounts(list);
      SW.destroyCharts();
      SW.chart(host.querySelector('#evChart'), {
        type: 'bar',
        data: { labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{ data: [sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW, sev.INFO], backgroundColor: ['#FB7185', '#FB923C', '#FBBF24', '#38BDF8', '#34D399'], borderRadius: 6, barThickness: 30 }] },
        options: { scales: { x: SW.axis({ grid: { display: false }, ticks: { color: '#9AA9BF' } }), y: SW.axis({ beginAtZero: true, ticks: { precision: 0, maxTicksLimit: 5 } }) } }
      });
    }
    host.querySelector('#fq').addEventListener('input', function () { f.q = this.value.trim().toLowerCase(); f.page = 1; draw(); });
    host.querySelector('#fsev').addEventListener('change', function () { f.sev = this.value; f.page = 1; draw(); });
    host.querySelector('#ftype').addEventListener('change', function () { f.type = this.value; f.page = 1; draw(); });
    host.querySelector('#fep').addEventListener('change', function () { f.ep = this.value; f.page = 1; draw(); });
    host.querySelector('#fclear').addEventListener('click', function () {
      f.q = ''; f.sev = 'all'; f.type = 'all'; f.ep = 'all'; f.page = 1;
      host.querySelector('#fq').value = ''; host.querySelector('#fsev').value = 'all';
      host.querySelector('#ftype').value = 'all'; host.querySelector('#fep').value = 'all';
      draw(); SW.toast('Filters cleared', 'Showing the full event set.');
    });
    host.querySelector('#simBtn2').addEventListener('click', function () { SW.pushLiveAlert(); draw(); });
    host.addEventListener('click', function (e) {
      var s = e.target.closest('[data-sort]');
      if (s) {
        if (f.sort === s.dataset.sort) f.dir = -f.dir; else { f.sort = s.dataset.sort; f.dir = -1; }
        draw(); return;
      }
      var p = e.target.closest('[data-pg]');
      if (p && !p.disabled) { f.page += p.dataset.pg === 'next' ? 1 : -1; draw(); return; }
      var r = e.target.closest('[data-run]');
      if (r && !r.disabled) { SW.pendingRun = r.dataset.run; SW.go('event/' + r.dataset.run); }
    });
    SW.listen('sw:newevent', function () { if (host.querySelector('#evBody')) draw(); });
    draw();
  } });
})();
