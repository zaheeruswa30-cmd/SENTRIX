/* Sentrix — agent pipeline UI, event detail, AI Security Center, assistant. */
(function () {
  'use strict';
  var SW = window.SW;
  var A = SW.agents;

  SW.engineChip = function () {
    return '<span class="ai-chip inline">' + SW.icon('ai', 14) + A.ENGINE_LABEL + '</span>';
  };

  /* ================= Pipeline rendering ================= */
  function nodeHTML(n, i) {
    var stateCls = n.state === 'done' ? 'done' : n.state === 'running' ? 'running' : n.state === 'failed' ? 'failed' : 'idle';
    return '<div class="agent-node ' + (n.state === 'running' ? 'running' : '') + '" data-node="' + n.key + '">' +
      '<div class="an-head"><span class="an-icon">' + SW.icon('ai', 16) + '</span>' +
        '<h4>' + n.name + '</h4><span class="chip-state ' + stateCls + '">' + n.state + '</span></div>' +
      '<div class="an-task">' + SW.esc(n.task) + '</div>' +
      (n.input ? '<div class="an-out an-in"><b>in ▸</b> ' + SW.esc(n.input) + '</div>' : '') +
      (n.output ? '<div class="an-out"><b>out ▸</b> ' + SW.esc(n.output) + '</div>' : '') +
      '<div class="an-foot"><span>step ' + (i + 1) + '/6</span><span>' + (n.latency ? n.latency + ' ms' : '—') + '</span></div></div>';
  }
  SW.renderPipeline = function (el, run) {
    el.innerHTML = '<div class="pipeline six">' + run.nodes.map(nodeHTML).join('') + '</div>';
  };

  /* Streaming-style reveal of composed text (content is generated, not hardcoded). */
  function streamParagraphs(el, paragraphs) {
    el.innerHTML = '';
    if (SW.reduced) {
      el.innerHTML = paragraphs.map(function (p) { return '<p>' + SW.esc(p) + '</p>'; }).join('');
      return Promise.resolve();
    }
    return paragraphs.reduce(function (chain, text) {
      return chain.then(function () {
        var p = document.createElement('p');
        el.appendChild(p);
        return new Promise(function (res) {
          var i = 0, step = Math.max(3, Math.round(text.length / 60));
          var t = setInterval(function () {
            i += step;
            p.textContent = text.slice(0, i);
            if (i >= text.length) { p.textContent = text; clearInterval(t); res(); }
          }, 24);
        });
      });
    }, Promise.resolve());
  }

  function citationChips(run) {
    var docs = run.retrieval.map(function (r) {
      return '<button class="source-chip" data-chunk="' + r.chunkId + '" data-score="' + r.score + '">' + SW.icon('doc', 13) +
        SW.esc(r.doc) + (r.page ? ' · p.' + r.page : '') + '<span class="sim">' + r.score.toFixed(2) + '</span></button>';
    });
    var incs = run.history.map(function (h) {
      return '<a class="source-chip hist" href="#/incident/' + h.id + '">' + SW.icon('incident', 13) + h.id +
        '<span class="sim">' + h.score.toFixed(2) + '</span></a>';
    });
    if (!docs.length && !incs.length) return '<p class="muted">No supporting documentation found in the knowledge base, and no similar prior incident was matched.</p>';
    return '<div class="chips">' + docs.concat(incs).join('') + '</div>';
  }

  function resultsHTML(run) {
    var r = run.risk;
    return '<div class="grid g-2-1">' +
      '<div style="min-width:0;display:flex;flex-direction:column;gap:14px">' +
        '<div class="answer-section as-ai"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>Composed analysis</span>' +
          '<span class="faint">' + run.id + ' · ' + run.duration + ' ms measured</span></div><div id="analysisText"></div></div>' +
        '<div class="answer-section as-telemetry"><div class="sec-head"><span class="prov-tag prov-telemetry"><i></i>Detection evidence</span></div>' +
          (run.hits.length ? '<ul class="rule-list">' + run.hits.map(function (h) {
            return '<li><span class="mitre-chip">' + h.mitre + '</span><b>' + h.id + ' ' + SW.esc(h.name) + '</b>' +
              '<span class="faint"> · floor ' + h.floor + ' · ' + h.tactic + '</span><p>' + SW.esc(h.why) + '</p></li>'; }).join('') + '</ul>'
            : '<p class="muted">No deterministic rule matched this event.</p>') + '</div>' +
        '<div class="answer-section as-rag"><div class="sec-head"><span class="prov-tag prov-rag"><i></i>Citations</span>' +
          '<span class="faint">' + SW.rag.EMBED_LABEL + '</span></div>' + citationChips(run) + '</div>' +
        '<div class="answer-section as-steps"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>Recommended defensive investigation</span></div>' +
          '<ol class="steps-list">' + run.steps.map(function (s) { return '<li>' + SW.esc(s) + '</li>'; }).join('') + '</ol>' +
          '<p class="faint" style="margin-top:10px">Read-only guidance. This demo contains no response or remediation actions.</p></div>' +
      '</div>' +
      '<div style="min-width:0;display:flex;flex-direction:column;gap:14px">' +
        '<div class="card"><div class="card-head"><h3>Risk assessment</h3>' + SW.badge(r.band) + '</div>' +
          '<div class="risk-big">' + r.risk + '<span>/100</span></div>' +
          '<div class="bar" style="height:10px;margin:10px 0 6px"><i class="' + (r.risk > 79 ? 'crit' : r.risk > 59 ? 'warn' : '') + '" style="width:' + r.risk + '%"></i></div>' +
          '<p class="faint">computed ' + r.computed + ' · rule floor ' + r.floor + ' · risk = max(computed, floor)' +
            (r.flooredBy ? ' — floor enforced by ' + r.flooredBy.id : '') + '</p>' +
          '<div class="hr"></div><table class="mini"><tbody>' + r.factors.map(function (f) {
            return '<tr><td>' + SW.esc(f.label) + '</td><td class="mono nowrap">+' + f.value + '</td></tr>'; }).join('') + '</tbody></table>' +
          '<div class="confidence"><div class="faint" style="margin-bottom:6px">Confidence ' + r.confidence + '% — deterministic, based on rule and evidence coverage</div>' +
          '<div class="conf-bar"><i style="width:' + r.confidence + '%"></i></div></div></div>' +
        '<div class="card"><div class="card-head"><h3>Run trace</h3></div><table class="mini"><tbody>' +
          run.nodes.map(function (n) {
            return '<tr><td>' + n.name + '</td><td class="mono nowrap">' + n.state + '</td><td class="mono nowrap">' + n.latency + ' ms</td></tr>'; }).join('') +
          '</tbody></table><div class="hr"></div>' +
          '<button class="btn btn-primary btn-block" data-report="' + run.id + '">' + SW.icon('export', 15) + 'Generate report (.md)</button></div>' +
      '</div></div>';
  }

  SW.wireResults = function (host) {
    host.addEventListener('click', function (e) {
      var c = e.target.closest('[data-chunk]');
      if (c) { SW.rag.openChunk(c.dataset.chunk, parseFloat(c.dataset.score)); return; }
      var rp = e.target.closest('[data-report]');
      if (rp) {
        var run = SW.state.runs.filter(function (r) { return r.id === rp.dataset.report; })[0];
        if (run) A.download(run);
      }
    });
  };

  /* Shared: run a pipeline into a container. */
  SW.runInto = function (pipeEl, resEl, eventId) {
    if (!SW.can('run')) { SW.toast('Not permitted', SW.denyReason('run'), 'warn'); return Promise.resolve(); }
    resEl.innerHTML = '<div class="card"><div class="sk sk-line" style="width:60%"></div><div class="sk sk-line" style="width:90%"></div>' +
      '<div class="sk sk-line" style="width:75%"></div></div>';
    return A.run(eventId, function (run) {
      SW.renderPipeline(pipeEl, run);
    }).then(function (run) {
      resEl.innerHTML = resultsHTML(run);
      streamParagraphs(resEl.querySelector('#analysisText'), run.analysis);
      return run;
    }).catch(function () {});
  };

  /* ================= Event detail + run ================= */
  SW.route('event', { title: 'Event analysis', render: function (host, id) {
    var ev = SW.state.events.filter(function (e) { return e.id === id; })[0];
    if (!ev) { host.innerHTML = SW.emptyState('Event not found', 'No event with id ' + (id || '—') + '.', '<a class="btn btn-primary" href="#/events">Back to events</a>'); return; }
    var ep = SW.state.endpoints.filter(function (e) { return e.id === ev.endpoint; })[0];
    var existing = SW.state.runs.filter(function (r) { return r.eventId === ev.id && r.status === 'complete'; })[0];

    host.innerHTML = '<div class="crumbs"><a href="#/events">Security Events</a>' + SW.icon('arrow', 13) + '<span>' + ev.id + '</span></div>' +
      SW.head(SW.esc(ev.title), ev.id + ' · ' + ev.type + ' · ' + ev.endpoint + ' · ' + SW.fmtDate(ev.ts),
        SW.badge(ev.severity) + SW.engineChip() +
        SW.gate('run', '<button class="btn btn-primary" id="runBtn">' + SW.icon('play', 15) + 'Run analysis</button>')) +
      '<div class="grid g-2-1 mb">' +
        '<div class="card"><div class="card-head"><h3>Raw telemetry</h3><span class="prov-tag prov-telemetry"><i></i>Endpoint telemetry</span></div>' +
          '<div class="pre">' + SW.esc(['event_id = ' + ev.id, 'timestamp = ' + SW.fmtDate(ev.ts), 'severity  = ' + ev.severity,
            'type      = ' + ev.type, 'endpoint  = ' + ev.endpoint, 'status    = ' + ev.status].concat(
            Object.keys(ev.fields).map(function (k) { return k.padEnd(9) + ' = ' + ev.fields[k]; })).join('\n')) + '</div></div>' +
        '<div class="card"><div class="card-head"><h3>Host context</h3></div>' + (ep ?
          '<dl class="kv"><dt>Host</dt><dd><a class="linkish" href="#/endpoint/' + ep.id + '">' + ep.host + '</a></dd>' +
          '<dt>OS</dt><dd>' + SW.esc(ep.os) + '</dd><dt>Group</dt><dd>' + ep.group + '</dd>' +
          '<dt>Standing risk</dt><dd>' + ep.risk + '</dd><dt>Health</dt><dd>' + ep.health + '</dd>' +
          '<dt>Primary user</dt><dd>' + SW.esc(ep.user) + '</dd></dl>' : '<p class="muted">Host not in the dataset.</p>') + '</div>' +
      '</div>' +
      '<div class="card panel mb"><div class="card-head"><div><h3>Agent pipeline</h3>' +
        '<div class="faint">Six deterministic nodes with measured latency · ' + A.RULES.length + ' rules loaded · ' + SW.state.chunks.length + ' chunks indexed</div></div>' +
        '<span class="prov-tag prov-ai"><i></i>Simulated engine</span></div>' +
        '<div id="pipe"><p class="muted" id="pipeIdle">Pipeline idle. Choose “Run analysis” to execute detection, retrieval, analysis, scoring, investigation and report generation against this event.</p></div></div>' +
      '<div id="results"></div>';

    var pipe = host.querySelector('#pipe'), res = host.querySelector('#results');
    SW.wireResults(host);
    if (existing) { SW.renderPipeline(pipe, existing); res.innerHTML = resultsHTML(existing); streamParagraphs(res.querySelector('#analysisText'), existing.analysis); }
    var btn = host.querySelector('#runBtn');
    if (btn) btn.addEventListener('click', function () {
      btn.disabled = true; btn.classList.add('is-busy');
      btn.innerHTML = '<span class="spinner"></span>Running…';
      SW.runInto(pipe, res, ev.id).then(function () {
        btn.disabled = false; btn.classList.remove('is-busy');
        btn.innerHTML = SW.icon('play', 15) + 'Re-run analysis';
      });
    });
    if (SW.pendingRun === ev.id) { SW.pendingRun = null; if (btn) btn.click(); }
  } });

  /* ================= AI Security Center ================= */
  SW.route('ai-center', { title: 'AI Security Center', render: function (host) {
    var candidates = SW.state.events.filter(function (e) { return e.severity !== 'INFO'; });
    host.innerHTML = SW.head('AI Security Center', 'Instrumentation for the simulated analysis engine — every row below is a real run record from this session',
      SW.engineChip()) +
      '<div class="card mb"><div class="filters">' +
        '<select id="runEvent" aria-label="Choose an event to analyse" style="flex:1 1 320px">' +
          candidates.map(function (e) { return '<option value="' + e.id + '">' + e.id + ' · ' + e.severity + ' · ' + e.endpoint + ' · ' + SW.esc(e.title).slice(0, 70) + '</option>'; }).join('') + '</select>' +
        SW.gate('run', '<button class="btn btn-primary" id="startRun">' + SW.icon('play', 15) + 'Run analysis pipeline</button>') +
        '<a class="btn btn-ghost" href="#/events">Browse all events</a>' +
      '</div>' +
      '<div class="faint" style="margin-top:10px">Detection is a deterministic rule match; retrieval is real cosine similarity over your indexed documents; risk is a deterministic function with rule severity floors. No language model is involved.</div></div>' +
      '<div class="card panel mb"><div class="card-head"><div><h3>Agent pipeline</h3><div class="faint" id="pipeSub">Idle</div></div>' +
        '<span class="prov-tag prov-ai"><i></i>Live node states</span></div><div id="pipe"></div></div>' +
      '<div id="results" class="mb"></div>' +
      '<div class="grid g-2-1">' +
        '<div class="card"><div class="card-head"><div><h3>Run trace history</h3><div class="faint">Persistent for this session · click a row to reopen the trace</div></div></div>' +
          '<div class="table-wrap"><table class="runs"><thead><tr><th>Run</th><th>Trigger event</th><th>Rules</th><th>Cites</th><th>Risk</th><th>Duration</th><th>Status</th></tr></thead>' +
          '<tbody id="runBody"></tbody></table></div></div>' +
        '<div class="card"><div class="card-head"><h3>Detection rule library</h3></div>' +
          '<ul class="rule-list compact">' + A.RULES.map(function (r) {
            return '<li><span class="mitre-chip">' + r.mitre + '</span><b>' + r.id + '</b> ' + SW.esc(r.name) +
              '<span class="faint"> · floor ' + r.floor + ' · ' + r.tactic + '</span></li>'; }).join('') + '</ul></div>' +
      '</div>';

    var pipe = host.querySelector('#pipe'), res = host.querySelector('#results');
    SW.wireResults(host);
    function idlePipe() {
      pipe.innerHTML = '<div class="pipeline six">' + A.NODES.map(function (n, i) {
        return nodeHTML({ key: n.key, name: n.name, task: n.task, state: 'idle', latency: 0 }, i); }).join('') + '</div>';
    }
    function drawRuns() {
      var b = host.querySelector('#runBody');
      b.innerHTML = SW.state.runs.length ? SW.state.runs.map(function (r) {
        return '<tr class="clickable" data-open="' + r.id + '"><td class="mono strong">' + r.id + '</td>' +
          '<td class="trig"><a class="linkish" href="#/event/' + r.eventId + '">' + r.eventId + '</a>' +
          '<div class="faint trunc" title="' + SW.esc(r.eventTitle) + '">' + SW.esc(r.eventTitle) + '</div></td>' +
          '<td class="mono">' + r.hits.length + '</td><td class="mono">' + r.citations.length + '</td>' +
          '<td>' + (r.risk ? SW.badge(r.risk.band) + ' <span class="mono">' + r.risk.risk + '</span>' : '<span class="faint">—</span>') + '</td>' +
          '<td class="mono nowrap">' + r.duration + ' ms</td>' +
          '<td><span class="chip-state ' + (r.status === 'complete' ? 'done' : r.status === 'failed' ? 'failed' : 'running') + '">' + r.status + '</span></td></tr>';
      }).join('') : '<tr><td colspan="7">' + SW.emptyState('No runs yet', 'Pick an event above and run the pipeline — each run is recorded here with real measured latencies.') + '</td></tr>';
    }
    var latest = SW.state.runs.filter(function (r) { return r.status === 'complete'; })[0];
    if (latest) { SW.renderPipeline(pipe, latest); res.innerHTML = resultsHTML(latest); streamParagraphs(res.querySelector('#analysisText'), latest.analysis);
      host.querySelector('#pipeSub').textContent = 'Showing ' + latest.id + ' · ' + latest.eventId; }
    else idlePipe();
    drawRuns();

    var sb = host.querySelector('#startRun');
    if (sb) sb.addEventListener('click', function () {
      var id = host.querySelector('#runEvent').value;
      sb.disabled = true; sb.innerHTML = '<span class="spinner"></span>Running…';
      host.querySelector('#pipeSub').textContent = 'Running against ' + id + '…';
      SW.runInto(pipe, res, id).then(function (run) {
        sb.disabled = false; sb.innerHTML = SW.icon('play', 15) + 'Run analysis pipeline';
        if (run) host.querySelector('#pipeSub').textContent = 'Completed ' + run.id + ' · ' + run.duration + ' ms measured';
        drawRuns();
      });
    });
    host.querySelector('#runBody').addEventListener('click', function (e) {
      var row = e.target.closest('[data-open]'); if (!row) return;
      if (e.target.closest('a')) return;
      var run = SW.state.runs.filter(function (r) { return r.id === row.dataset.open; })[0];
      if (!run || run.status !== 'complete') return;
      SW.renderPipeline(pipe, run);
      res.innerHTML = resultsHTML(run);
      streamParagraphs(res.querySelector('#analysisText'), run.analysis);
      host.querySelector('#pipeSub').textContent = 'Showing ' + run.id + ' · ' + run.eventId;
      window.scrollTo({ top: 0, behavior: SW.reduced ? 'auto' : 'smooth' });
    });
  } });

  /* ================= Assistant ================= */
  SW.route('assistant', { title: 'Assistant', render: function (host) {
    host.innerHTML = SW.head('Security assistant', 'Endpoint answers use client-side retrieval over the demo dataset; email identity questions are answered by Sentrix AI on the backend with cited evidence',
      SW.engineChip()) +
      '<div class="chat-layout">' +
        '<div class="card" style="min-width:0"><div class="card-head"><h3>Context</h3></div>' +
          '<dl class="kv"><dt>Indexed docs</dt><dd id="cxDocs">' + SW.rag.stats().docs + '</dd>' +
          '<dt>Chunks</dt><dd id="cxChunks">' + SW.rag.stats().chunks + '</dd>' +
          '<dt>Events</dt><dd>' + SW.state.events.length + '</dd><dt>Endpoints</dt><dd>' + SW.state.endpoints.length + '</dd>' +
          '<dt>Incidents</dt><dd>' + SW.state.incidents.length + '</dd></dl>' +
          '<div class="hr"></div><div class="eyebrow" style="margin-bottom:8px">Suggested prompts</div>' +
          '<div class="chips vert">' + SW.assistant.SUGGESTED.map(function (p) {
            return '<button class="prompt-chip" data-prompt="' + SW.esc(p) + '">' + SW.esc(p) + '</button>'; }).join('') + '</div>' +
          '<div class="hr"></div><button class="btn btn-ghost btn-block" id="clearChat">Clear conversation</button></div>' +
        '<div class="card" style="min-width:0"><div class="card-head"><div><h3>Conversation</h3>' +
          '<div class="faint">Message history is in memory for this session only</div></div></div>' +
          '<div id="thread" class="thread" aria-live="polite"></div>' +
          '<form class="composer" id="chatForm"><input id="chatInput" type="text" placeholder="Ask about an endpoint, an incident, a document — or an email address…" aria-label="Ask the assistant" autocomplete="off">' +
          '<button class="btn btn-primary" type="submit">Send' + SW.icon('arrow', 15) + '</button></form>' +
          '<p class="faint" style="margin-top:8px">Enter sends. Endpoint answers are composed client-side from the demo dataset. Email questions (addresses, SPF/DKIM/DMARC, MX, ownership) are answered by Sentrix AI on the backend with evidence citations.</p></div>' +
      '</div>';

    var thread = host.querySelector('#thread');
    /* Email context from #/assistant?record=<id> (set by the email record page). */
    if (SW.hashQuery && SW.hashQuery.record) SW.state.emailCtx = { id: SW.hashQuery.record, email: null };
    var ctxBar = document.createElement('div');
    ctxBar.className = 'email-ctx';
    thread.parentNode.insertBefore(ctxBar, thread);
    function drawCtx() {
      var c = SW.state.emailCtx;
      ctxBar.innerHTML = c ? SW.icon('mail', 14) + '<span>Email context: <b class="mono">' + SW.esc(c.email || c.id.slice(0, 8) + '…') + '</b> — email questions are answered by Sentrix AI from this record’s evidence.</span>' +
        '<button class="btn btn-sm btn-ghost" id="ctxClear">Clear</button>' : '';
      ctxBar.hidden = !c;
      var b = ctxBar.querySelector('#ctxClear');
      if (b) b.addEventListener('click', function () { SW.state.emailCtx = null; drawCtx(); });
    }
    if (SW.state.emailCtx && !SW.state.emailCtx.email && SW.api && SW.api.authed()) {
      SW.api.get('/email-identity/records/' + SW.state.emailCtx.id).then(function (r) { if (SW.state.emailCtx) { SW.state.emailCtx.email = r.email; drawCtx(); } }, function () {});
    }
    drawCtx();
    function backendHTML(d) {
      var KIND = { ai: ['prov-ai', 'AI Analysis'], telemetry: ['prov-telemetry', 'Evidence'], rag: ['prov-rag', 'RAG Sources'],
        history: ['prov-history', 'Historical Context'], risk: ['prov-ai', 'Risk Assessment'], steps: ['prov-ai', 'Recommended Steps'] };
      return '<div class="answer-section as-ai"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>' + SW.esc(d.assistant || 'Sentrix AI') + '</span>' +
          '<span class="faint">' + (d.llm_used ? 'LLM-phrased, evidence-grounded' : 'Deterministic, evidence-grounded') + (d.record ? ' · ' + SW.esc(d.record.email) : '') + '</span></div>' +
          '<p>' + SW.esc(d.summary) + '</p></div>' +
        (d.sections || []).map(function (sec) {
          var k = KIND[sec.kind] || KIND.ai;
          return '<div class="answer-section as-' + SW.esc(sec.kind) + '"><div class="sec-head"><span class="prov-tag ' + k[0] + '"><i></i>' + k[1] + '</span><span class="faint">' + SW.esc(sec.title || '') + '</span></div>' +
            (sec.text ? '<p>' + SW.esc(sec.text) + '</p>' : '') +
            (sec.bullets && sec.bullets.length ? (sec.kind === 'steps' ? '<ol class="steps-list">' : '<ul class="list-clean">') + sec.bullets.map(function (b) { return '<li>' + SW.esc(b) + '</li>'; }).join('') + (sec.kind === 'steps' ? '</ol>' : '</ul>') : '') +
            (sec.citations && sec.citations.length ? '<div class="chips cite-row">' + sec.citations.map(function (c) {
              var href = c.type === 'email_record' && c.ref ? '#/email-record/' + c.ref : c.type === 'kb_chunk' ? '#/knowledge-base' : c.type === 'domain_analysis' && d.record ? '#/email-domain/' + encodeURIComponent(d.record.domain) : null;
              return (href ? '<a class="source-chip" href="' + href + '">' : '<span class="source-chip">') + SW.icon('doc', 13) + SW.esc(c.label) + '<span class="sim">' + SW.esc(c.type.replace(/_/g, ' ')) + '</span>' + (href ? '</a>' : '</span>');
            }).join('') + '</div>' : '') + '</div>';
        }).join('') +
        '<p class="faint src-foot">' + SW.esc(d.disclaimer || '') + '</p>';
    }
    function answerHTML(a) {
      if (a.backend) return backendHTML(a.backend);
      if (a.backendError) return '<div class="answer-section as-ai"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>Sentrix AI</span></div><p>' + SW.esc(a.backendError) + '</p></div>';
      return a.sections.map(function (s) {
        if (s.kind === 'ai') return '<div class="answer-section as-ai"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>AI Analysis</span></div>' +
          s.paragraphs.map(function (p) { return '<p>' + SW.esc(p) + '</p>'; }).join('') + '</div>';
        if (s.kind === 'telemetry') return '<div class="answer-section as-telemetry"><div class="sec-head"><span class="prov-tag prov-telemetry"><i></i>Evidence</span></div>' +
          '<div class="pre">' + SW.esc(s.lines.join('\n')) + '</div></div>';
        if (s.kind === 'rag') return '<div class="answer-section as-rag"><div class="sec-head"><span class="prov-tag prov-rag"><i></i>RAG Sources</span>' +
          '<span class="faint">' + SW.rag.EMBED_LABEL + '</span></div><div class="chips">' + s.chips.map(function (c) {
            return '<button class="source-chip" data-chunk="' + c.chunkId + '" data-score="' + c.score + '">' + SW.icon('doc', 13) +
              SW.esc(c.doc) + (c.page ? ' · p.' + c.page : '') + (c.section ? ' · §' + SW.esc(c.section).slice(0, 20) : '') +
              '<span class="sim">' + c.score.toFixed(2) + '</span></button>'; }).join('') + '</div></div>';
        if (s.kind === 'history') return '<div class="answer-section as-history"><div class="sec-head"><span class="prov-tag prov-history"><i></i>Historical Context</span></div>' +
          '<ul class="list-clean">' + s.items.map(function (i) {
            return '<li><a class="linkish" href="#/incident/' + i.id + '">' + i.id + '</a> — ' + SW.esc(i.text) + '</li>'; }).join('') + '</ul></div>';
        if (s.kind === 'risk') return '<div class="answer-section as-risk"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>Risk Assessment</span>' +
          SW.badge(s.risk.band) + '</div><p>' + SW.esc(s.risk.why) + '</p>' +
          '<div class="bar" style="height:9px;margin-top:10px"><i class="' + (s.risk.score > 79 ? 'crit' : s.risk.score > 59 ? 'warn' : '') + '" style="width:' + s.risk.score + '%"></i></div>' +
          '<div class="confidence"><div class="faint" style="margin-bottom:6px">Confidence ' + s.risk.confidence + '%</div><div class="conf-bar"><i style="width:' + s.risk.confidence + '%"></i></div></div></div>';
        if (s.kind === 'steps') return '<div class="answer-section as-steps"><div class="sec-head"><span class="prov-tag prov-ai"><i></i>Recommended Defensive Investigation</span></div>' +
          '<ol class="steps-list">' + s.steps.map(function (x) { return '<li>' + SW.esc(x) + '</li>'; }).join('') + '</ol></div>';
        return '';
      }).join('') +
      '<p class="faint src-foot">Searched: ' + SW.esc(a.sourcesSearched.join(' · ')) +
        (a.retrievalEmpty ? ' — no supporting documentation found in the knowledge base.' : '.') + '</p>';
    }
    function drawThread() {
      if (!SW.state.chat.length) {
        thread.innerHTML = SW.emptyState('Ask a question to begin',
          'Try a suggested prompt, name a host such as WKS-042, or ask what policy says about encoded PowerShell.');
        return;
      }
      thread.innerHTML = SW.state.chat.map(function (m) {
        if (m.role === 'user') return '<div class="msg-user"><span class="avatar sm">' +
          (SW.state.user ? SW.state.user.name.slice(0, 1) : 'U') + '</span><div><b>You</b><p>' + SW.esc(m.text) + '</p></div></div>';
        if (m.pending) return '<div class="answer-card"><div class="typing" role="status" aria-label="Assistant is composing an answer">' +
          '<i></i><i></i><i></i><span class="faint">Retrieving from ' + SW.state.chunks.length + ' chunks and composing…</span></div></div>';
        return '<div class="answer-card">' + answerHTML(m.answer) + '</div>';
      }).join('');
      thread.scrollTop = thread.scrollHeight;
    }
    function send(text) {
      var q = String(text || '').trim();
      if (!q) return;
      SW.state.chat.push({ role: 'user', text: q });
      var pending = { role: 'assistant', pending: true };
      SW.state.chat.push(pending);
      drawThread();
      if (SW.email && SW.email.isEmailQuestion(q)) {
        var ctx = SW.state.emailCtx;
        var addr = (q.match(/[^\s"'<>(),;:]+@[^\s"'<>(),;:?]+\.[a-z0-9-]{2,}/i) || [])[0];
        if (!SW.api || !SW.api.authed()) {
          pending.pending = false;
          pending.answer = { backendError: 'Email questions are answered by the Sentrix API, which is not connected. Start the backend (uvicorn backend.app.main:app --reload) and sign in again.' };
          drawThread(); return;
        }
        SW.api.post('/ai/email/ask', { question: q, record_id: addr ? null : (ctx ? ctx.id : null), email: addr || null, run_if_missing: !!addr && SW.can('run') })
          .then(function (d) {
            if (d.record) SW.state.emailCtx = { id: d.record.id, email: d.record.email };
            drawCtx();
            pending.pending = false; pending.answer = { backend: d }; drawThread();
          }, function (err) { pending.pending = false; pending.answer = { backendError: 'Sentrix AI could not answer: ' + err.message }; drawThread(); });
        return;
      }
      setTimeout(function () {
        var ans = SW.assistant.answer(q);
        pending.pending = false;
        pending.answer = ans;
        drawThread();
      }, SW.reduced ? 20 : 620);
    }
    host.querySelector('#chatForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var input = host.querySelector('#chatInput');
      send(input.value);
      input.value = '';
      input.focus();
    });
    host.querySelectorAll('[data-prompt]').forEach(function (b) {
      b.addEventListener('click', function () {
        host.querySelector('#chatInput').value = b.dataset.prompt;
        send(b.dataset.prompt);
        host.querySelector('#chatInput').value = '';
      });
    });
    host.querySelector('#clearChat').addEventListener('click', function () {
      SW.state.chat = []; drawThread(); SW.toast('Conversation cleared', 'Message history removed from memory.');
    });
    thread.addEventListener('click', function (e) {
      var c = e.target.closest('[data-chunk]');
      if (c) SW.rag.openChunk(c.dataset.chunk, parseFloat(c.dataset.score));
    });
    drawThread();
  } });
})();
