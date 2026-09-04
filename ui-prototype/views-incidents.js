/* SecureWatch AI — incident queue and incident detail with stage advance. */
(function () {
  'use strict';
  var SW = window.SW;

  function tab(id, label, active) {
    return '<button class="tab' + (active ? ' active' : '') + '" role="tab" aria-selected="' + !!active + '" data-target="' + id + '">' + label + '</button>';
  }
  function openCount() {
    return SW.state.incidents.filter(function (i) { return i.stage < SW.seed.stages.length - 1; }).length;
  }

  /* ================= Incident queue ================= */
  SW.route('incidents', { title: 'Incidents', render: function (host) {
    var f = { sev: 'all', stage: 'all', q: '' };
    host.innerHTML = SW.head('Incidents', SW.state.incidents.length + ' correlated cases · ' + openCount() + ' still open · synthetic data',
      '<a class="btn btn-ghost" href="#/events">Security events</a>') +
      '<div class="grid g4 mb" id="incKpis"></div>' +
      '<div class="card mb"><div class="filters">' +
        '<div class="searchbox" style="flex:1 1 220px">' + SW.icon('search', 16) +
        '<input id="iq" type="search" placeholder="Search incident id, title, tag, host…" aria-label="Search incidents"></div>' +
        '<select id="isev" aria-label="Filter severity"><option value="all">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>' +
        '<select id="istage" aria-label="Filter stage"><option value="all">All stages</option>' +
          SW.seed.stages.map(function (s, i) { return '<option value="' + i + '">' + s + '</option>'; }).join('') + '</select>' +
      '</div></div>' +
      '<div class="card"><div class="table-wrap"><table><thead><tr><th>Incident</th><th>Severity</th><th>Endpoint</th>' +
        '<th>Stage</th><th>Analyst</th><th>Opened</th><th>Events</th><th></th></tr></thead><tbody id="incBody"></tbody></table></div></div>';

    function drawKpis() {
      var incs = SW.state.incidents;
      var crit = incs.filter(function (i) { return i.severity === 'CRITICAL'; }).length;
      var closed = incs.length - openCount();
      var meanStage = incs.length ? (incs.reduce(function (a, i) { return a + i.stage; }, 0) / incs.length).toFixed(1) : '0';
      host.querySelector('#incKpis').innerHTML = [
        ['Open cases', openCount(), 'of ' + incs.length + ' total'],
        ['Critical', crit, 'highest severity band'],
        ['Resolved', closed, 'reached Resolution stage'],
        ['Mean stage index', meanStage, 'across all cases']
      ].map(function (k) {
        return '<div class="kpi"><div class="k-label">' + k[0] + '</div><div class="k-value" style="font-size:28px">' + k[1] + '</div>' +
          '<div class="k-foot"><span>' + k[2] + '</span></div></div>';
      }).join('');
    }
    function draw() {
      drawKpis();
      var list = SW.state.incidents.filter(function (i) {
        if (f.sev !== 'all' && i.severity !== f.sev) return false;
        if (f.stage !== 'all' && String(i.stage) !== f.stage) return false;
        if (!f.q) return true;
        return (i.id + ' ' + i.title + ' ' + i.endpoint + ' ' + i.analyst + ' ' + i.tags.join(' ')).toLowerCase().indexOf(f.q) >= 0;
      });
      host.querySelector('#incBody').innerHTML = list.length ? list.map(function (i) {
        return '<tr><td class="strong"><a class="linkish" href="#/incident/' + i.id + '">' + SW.esc(i.title) + '</a>' +
          '<div class="faint mono">' + i.id + '</div></td>' +
          '<td>' + SW.badge(i.severity) + '</td>' +
          '<td class="mono"><a class="linkish" href="#/endpoint/' + i.endpoint + '">' + i.endpoint + '</a></td>' +
          '<td class="nowrap"><span class="chip-state ' + (i.stage >= SW.seed.stages.length - 1 ? 'done' : 'running') + '">' + SW.seed.stages[i.stage] + '</span></td>' +
          '<td class="nowrap">' + SW.esc(i.analyst) + '</td>' +
          '<td class="mono nowrap">' + SW.fmtDate(i.opened) + '</td>' +
          '<td class="mono">' + i.eventIds.length + '</td>' +
          '<td class="nowrap"><a class="btn btn-ghost btn-sm" href="#/incident/' + i.id + '">Open</a></td></tr>';
      }).join('') : '<tr><td colspan="8">' + SW.emptyState('No incidents match', 'Clear the filters to see every case.') + '</td></tr>';
    }
    host.querySelector('#iq').addEventListener('input', function () { f.q = this.value.trim().toLowerCase(); draw(); });
    host.querySelector('#isev').addEventListener('change', function () { f.sev = this.value; draw(); });
    host.querySelector('#istage').addEventListener('change', function () { f.stage = this.value; draw(); });
    draw();
  } });

  /* ================= Incident detail ================= */
  SW.route('incident', { title: 'Incident', render: function (host, id) {
    var inc = SW.state.incidents.filter(function (i) { return i.id === id; })[0];
    if (!inc) { host.innerHTML = SW.emptyState('Incident not found', 'No incident with id ' + (id || '—') + '.',
      '<a class="btn btn-primary" href="#/incidents">Back to incidents</a>'); return; }
    var ep = SW.state.endpoints.filter(function (e) { return e.id === inc.endpoint; })[0];
    var evs = SW.state.events.filter(function (e) { return inc.eventIds.indexOf(e.id) >= 0; });
    var runs = SW.state.runs.filter(function (r) { return inc.eventIds.indexOf(r.eventId) >= 0; });
    var retrieval = SW.rag.search(inc.title + ' ' + inc.tags.join(' ') + ' ' + (evs[0] ? evs[0].type : ''), 4);
    var related = SW.state.incidents.filter(function (i) { return i.id !== inc.id && (i.endpoint === inc.endpoint || i.tags.some(function (t) { return inc.tags.indexOf(t) >= 0; })); }).slice(0, 4);

    function render() {
      var last = inc.stage >= SW.seed.stages.length - 1;
      host.innerHTML = '<div class="crumbs"><a href="#/incidents">Incidents</a>' + SW.icon('arrow', 13) + '<span>' + inc.id + '</span></div>' +
        SW.head(SW.esc(inc.title), inc.id + ' · opened ' + SW.fmtDate(inc.opened) + ' · owner ' + SW.esc(inc.analyst),
          SW.badge(inc.severity) +
          SW.gate('advanceIncident', '<button class="btn btn-primary" id="advBtn"' + (last ? ' disabled' : '') + '>' +
            SW.icon('check', 15) + (last ? 'Resolution reached' : 'Advance to ' + SW.seed.stages[inc.stage + 1]) + '</button>')) +
        '<div class="card panel mb"><div class="card-head"><div><h3>Investigation timeline</h3>' +
          '<div class="faint">Stage ' + (inc.stage + 1) + ' of ' + SW.seed.stages.length + ' · ' + SW.seed.stages[inc.stage] + '</div></div>' +
          '<span class="prov-tag prov-ai"><i></i>Workflow state (in memory)</span></div>' +
          '<div class="rail">' + SW.railHTML(inc) + '</div></div>' +
        '<div class="grid g-2-1">' +
          '<div style="min-width:0">' +
            '<div class="card mb"><div class="card-head"><h3>Case summary</h3></div>' +
              '<p class="lede">' + SW.esc(inc.summary) + '</p>' +
              '<div class="chip-row" style="margin-top:12px">' + inc.tags.map(function (t) { return '<span class="chip-mono">' + SW.esc(t) + '</span>'; }).join('') + '</div>' +
              (inc.resolution ? '<div class="hr"></div><div class="eyebrow">Analyst note</div><p class="muted">' + SW.esc(inc.resolution) + '</p>' : '') +
              '<p class="faint" style="margin-top:12px">Investigation guidance only — this demo exposes no response or remediation actions.</p></div>' +
            '<div class="card panel"><div class="tabs" role="tablist" id="incTabs">' +
              tab('t-tel', 'Telemetry (' + evs.length + ')', true) + tab('t-rag', 'RAG evidence (' + retrieval.length + ')') +
              tab('t-hist', 'History (' + related.length + ')') + tab('t-ai', 'AI runs (' + runs.length + ')') + '</div>' +
              '<div id="incPanels">' +
                '<div class="tab-panel active" id="t-tel">' + (evs.length ?
                  '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Detection</th><th></th></tr></thead><tbody>' +
                  evs.map(function (e) {
                    return '<tr><td class="mono nowrap">' + SW.fmtTime(e.ts) + '</td><td>' + SW.badge(e.severity) + '</td>' +
                      '<td class="nowrap">' + e.type + '</td><td class="strong">' + SW.esc(e.title) + '</td>' +
                      '<td class="nowrap"><a class="linkish" href="#/event/' + e.id + '">Inspect</a></td></tr>';
                  }).join('') + '</tbody></table></div>' : SW.emptyState('No linked events', 'This case has no events in the current window.')) + '</div>' +
                '<div class="tab-panel" id="t-rag">' + (retrieval.length ?
                  '<p class="faint" style="margin-bottom:10px">' + SW.rag.EMBED_LABEL + ' · query built from the case title and tags</p>' +
                  retrieval.map(function (r) {
                    return '<div class="kb-result"><div class="kb-top"><button class="source-chip" data-chunk="' + r.chunk.id + '" data-score="' + r.score + '">' +
                      SW.icon('doc', 13) + SW.esc(r.chunk.docName) + ' · p.' + r.chunk.page + '<span class="sim">' + r.score.toFixed(3) + '</span></button>' +
                      '<span class="chip-mono">' + r.chunk.id + '</span></div>' +
                      '<p class="kb-snip">' + SW.rag.highlight(r.chunk.text.slice(0, 280), r.terms) + '…</p></div>';
                  }).join('') :
                  '<p class="muted">No supporting documentation found in the knowledge base for this case. Upload relevant policy or prior-incident documents in RAG Intelligence.</p>') + '</div>' +
                '<div class="tab-panel" id="t-hist">' + (related.length ?
                  related.map(SW.incRow).join('') : SW.emptyState('No similar prior cases', 'No other incident shares this host or tag set.')) + '</div>' +
                '<div class="tab-panel" id="t-ai">' + (runs.length ?
                  '<div class="table-wrap"><table><thead><tr><th>Run</th><th>Event</th><th>Risk</th><th>Citations</th><th>Duration</th></tr></thead><tbody>' +
                  runs.map(function (r) {
                    return '<tr><td class="mono strong">' + r.id + '</td><td class="mono"><a class="linkish" href="#/event/' + r.eventId + '">' + r.eventId + '</a></td>' +
                      '<td>' + (r.risk ? SW.badge(r.risk.band) + ' <span class="mono">' + r.risk.risk + '</span>' : '—') + '</td>' +
                      '<td class="mono">' + r.citations.length + '</td><td class="mono nowrap">' + r.duration + ' ms</td></tr>';
                  }).join('') + '</tbody></table></div>' :
                  SW.emptyState('No agent runs for this case', 'Open any linked event and run the analysis pipeline — the run will appear here.',
                    evs.length ? '<a class="btn btn-primary" href="#/event/' + evs[0].id + '">Analyse ' + evs[0].id + '</a>' : '')) + '</div>' +
              '</div></div>' +
          '</div>' +
          '<div style="min-width:0;display:flex;flex-direction:column;gap:14px">' +
            '<div class="card"><div class="card-head"><h3>Affected host</h3></div>' + (ep ?
              '<dl class="kv"><dt>Host</dt><dd><a class="linkish" href="#/endpoint/' + ep.id + '">' + ep.host + '</a></dd>' +
              '<dt>OS</dt><dd>' + SW.esc(ep.os) + '</dd><dt>Group</dt><dd>' + ep.group + '</dd>' +
              '<dt>Standing risk</dt><dd>' + ep.risk + '</dd><dt>Health</dt><dd>' + ep.health + '</dd>' +
              '<dt>Agent</dt><dd>' + ep.agent + '</dd><dt>Last seen</dt><dd>' + ep.lastSeen + '</dd></dl>' :
              '<p class="muted">Host not present in the dataset.</p>') + '</div>' +
            '<div class="card"><div class="card-head"><h3>Stage progress</h3></div>' +
              '<div class="bar" style="height:10px"><i style="width:' + Math.round((inc.stage + 1) / SW.seed.stages.length * 100) + '%"></i></div>' +
              '<p class="faint" style="margin-top:10px">' + SW.seed.stages.map(function (s, i) {
                return (i <= inc.stage ? '✓ ' : '· ') + s; }).join('<br>') + '</p></div>' +
            '<div class="card"><div class="card-head"><h3>Severity mix of linked events</h3></div>' +
              '<div class="chart-box h180"><canvas id="incChart" aria-label="Linked event severity mix"></canvas></div></div>' +
          '</div>' +
        '</div>';

      SW.wireTabs(host.querySelector('#incTabs'), host.querySelector('#incPanels'));
      host.addEventListener('click', function (e) {
        var c = e.target.closest('[data-chunk]');
        if (c) SW.rag.openChunk(c.dataset.chunk, parseFloat(c.dataset.score));
      });
      var adv = host.querySelector('#advBtn');
      if (adv && !adv.disabled) adv.addEventListener('click', function () {
        inc.stage = Math.min(SW.seed.stages.length - 1, inc.stage + 1);
        if (inc.stage >= SW.seed.stages.length - 1) inc.resolution = inc.resolution || 'Case walked to Resolution during this demo session by ' + SW.state.user.name + '.';
        SW.toast('Stage advanced', inc.id + ' is now at ' + SW.seed.stages[inc.stage] + '.', 'ok');
        render();
      });
      var sev = SW.sevCounts(evs);
      SW.destroyCharts();
      SW.chart(host.querySelector('#incChart'), {
        type: 'doughnut',
        data: { labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{ data: [sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW, sev.INFO],
            backgroundColor: ['#FB7185', '#FB923C', '#FBBF24', '#38BDF8', '#34D399'], borderWidth: 0 }] },
        options: { cutout: '62%', plugins: { legend: { display: true, position: 'right', labels: { boxWidth: 10, color: '#9AA9BF', font: { size: 11 } } } } }
      });
    }
    render();
  } });
})();
