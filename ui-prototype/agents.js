/* Sentrix — simulated analysis engine.
   Deterministic detection rules + real client-side retrieval + deterministic risk scoring.
   There is NO large language model here: every sentence is template-composed from the
   event fields, the matched rules and the retrieved chunks. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var A = (SW.agents = {});

  A.ENGINE_LABEL = 'Simulated analysis engine — deterministic rules + client-side retrieval, no LLM in this demo';

  /* ================= Detection rules (8 real matchers) ================= */
  function s(v) { return String(v == null ? '' : v).toLowerCase(); }
  A.RULES = [
    { id: 'SW-R001', name: 'Encoded PowerShell command', mitre: 'T1059.001', floor: 85, tactic: 'Execution',
      match: function (e) {
        var cl = s(e.fields.command_line);
        var hit = /(-enc\b|-encodedcommand|frombase64string|base64\s+-d)/.test(cl);
        return hit ? { why: 'Command line contains an encoded-payload switch (' + (cl.match(/(-enc\b|-encodedcommand|frombase64string|base64\s+-d)/)[0]) + ')' } : null;
      } },
    { id: 'SW-R002', name: 'Office application spawning a shell', mitre: 'T1566.001', floor: 75, tactic: 'Initial Access',
      match: function (e) {
        var chain = s(e.fields.parent) + ' ' + s(e.fields.grandparent);
        var proc = s(e.fields.process);
        var office = /(outlook|winword|excel|powerpnt)\.exe/.test(chain);
        var shell = /(powershell|cmd|wscript|cscript|mshta)/.test(proc + ' ' + s(e.fields.parent));
        return office && shell ? { why: 'Process ancestry ' + [e.fields.grandparent, e.fields.parent, e.fields.process].filter(Boolean).join(' → ') + ' is not expected on managed workstations' } : null;
      } },
    { id: 'SW-R003', name: 'LSASS handle access by non-standard process', mitre: 'T1003.001', floor: 90, tactic: 'Credential Access',
      match: function (e) {
        return /lsass/.test(s(e.fields.target_process)) ? { why: s(e.fields.process) + ' requested a handle to lsass.exe (access mask ' + (e.fields.access_mask || 'n/a') + ')' } : null;
      } },
    { id: 'SW-R004', name: 'Authentication brute-force burst', mitre: 'T1110', floor: 70, tactic: 'Credential Access',
      match: function (e) {
        var n = Number(e.fields.failed_count || 0);
        return n >= 20 ? { why: n + ' failed authentications from ' + (e.fields.remote_ip || 'unknown source') + ' on port ' + (e.fields.port || '?') } : null;
      } },
    { id: 'SW-R005', name: 'Fixed-cadence outbound beacon', mitre: 'T1071.001', floor: 75, tactic: 'Command and Control',
      match: function (e) {
        var iv = Number(e.fields.interval_seconds || 0);
        var ip = s(e.fields.remote_ip);
        var external = ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
        return iv > 0 && external ? { why: 'Repeating ' + iv + 's-interval traffic to external host ' + e.fields.remote_ip + ':' + (e.fields.port || '?') } : null;
      } },
    { id: 'SW-R006', name: 'Unsigned binary staged in a temp path', mitre: 'T1204.002', floor: 70, tactic: 'Execution',
      match: function (e) {
        var p = s(e.fields.file_path);
        var temp = /(\\temp\\|\/tmp\/|appdata\\local\\temp|users\\public)/.test(p);
        return temp && e.fields.signed === false ? { why: 'Unsigned file written to a staging path (' + e.fields.file_path + ')' } : null;
      } },
    { id: 'SW-R007', name: 'Autostart or scheduled persistence created', mitre: 'T1547.001', floor: 60, tactic: 'Persistence',
      match: function (e) {
        var cl = s(e.fields.command_line) + ' ' + s(e.fields.task_name) + ' ' + s(e.fields.schedule) + ' ' + s(e.fields.file_path);
        return /(currentversion\\run|schtasks|launchagents|crontab|\*\/\d+ )/.test(cl) || (e.type === 'Persistence')
          ? { why: 'Persistence artefact observed: ' + (e.fields.task_name || e.fields.command_line || e.fields.file_path || e.fields.schedule || e.type) } : null;
      } },
    { id: 'SW-R008', name: 'Bulk file collection by service account', mitre: 'T1119', floor: 65, tactic: 'Collection',
      match: function (e) {
        var n = Number(e.fields.file_count || 0);
        return n >= 500 ? { why: n + ' files read from ' + (e.fields.share || 'a monitored share') + ' by ' + (e.fields.user || 'unknown user') } : null;
      } },
    { id: 'SW-R009', name: 'Host and account discovery commands', mitre: 'T1069.001', floor: 45, tactic: 'Discovery',
      match: function (e) {
        var cl = s(e.fields.command_line);
        return /(net\s+localgroup|nltest|whoami\s+\/groups|net\s+group)/.test(cl) ? { why: 'Discovery command executed in a user session: ' + e.fields.command_line } : null;
      } },
    { id: 'SW-R010', name: 'Removable media enrolment', mitre: 'T1091', floor: 30, tactic: 'Initial Access',
      match: function (e) {
        return e.fields.removable === true ? { why: 'Removable volume involved (' + (e.fields.device || 'device') + ')' } : null;
      } }
  ];

  A.detect = function (ev) {
    var hits = [];
    A.RULES.forEach(function (r) {
      var m;
      try { m = r.match(ev); } catch (e) { m = null; }
      if (m) hits.push({ rule: r, why: m.why });
    });
    return hits;
  };

  /* ================= Historical similarity (real search over in-memory incidents) ====== */
  A.historyMatch = function (ev) {
    var q = ev.title + ' ' + ev.type + ' ' + Object.keys(ev.fields).map(function (k) { return k + ' ' + ev.fields[k]; }).join(' ');
    var qt = SW.rag.tokenize(q);
    var qset = {}; qt.forEach(function (t) { qset[t] = 1; });
    return SW.state.incidents.map(function (inc) {
      var it = SW.rag.tokenize(inc.title + ' ' + inc.summary + ' ' + inc.tags.join(' ') + ' ' + inc.endpoint + ' ' + (inc.resolution || ''));
      var seen = {}, overlap = 0, uniq = 0;
      it.forEach(function (t) { if (seen[t]) return; seen[t] = 1; uniq++; if (qset[t]) overlap++; });
      var jac = uniq ? overlap / (uniq + qt.length - overlap) : 0;
      var bump = inc.endpoint === ev.endpoint ? 0.12 : 0;
      return { incident: inc, score: Math.min(0.99, jac + bump), sameHost: inc.endpoint === ev.endpoint };
    }).filter(function (r) { return r.score >= 0.08; })
      .sort(function (a, b) { return b.score - a.score; }).slice(0, 3);
  };

  /* ================= Deterministic risk scoring ================= */
  A.score = function (ctx) {
    var floor = ctx.hits.reduce(function (m, h) { return Math.max(m, h.rule.floor); }, 0);
    var sevBase = { CRITICAL: 70, HIGH: 55, MEDIUM: 35, LOW: 18, INFO: 8 }[ctx.event.severity] || 20;
    var ep = ctx.endpoint || { risk: 40, health: 70, online: true };
    var factors = [];
    var v = sevBase * 0.45;
    factors.push({ label: 'Reported severity (' + ctx.event.severity + ')', value: +(sevBase * 0.45).toFixed(1) });
    var epPart = ep.risk * 0.22;
    v += epPart; factors.push({ label: 'Endpoint standing risk (' + ep.host + ' = ' + ep.risk + ')', value: +epPart.toFixed(1) });
    var rulePart = Math.min(28, ctx.hits.length * 9);
    v += rulePart; factors.push({ label: ctx.hits.length + ' detection rule(s) matched', value: +rulePart.toFixed(1) });
    var retPart = ctx.retrieval.length ? Math.min(10, ctx.retrieval[0].score * 22) : 0;
    v += retPart; factors.push({ label: ctx.retrieval.length ? 'Documented policy support (top similarity ' + ctx.retrieval[0].score.toFixed(2) + ')' : 'No supporting documentation retrieved', value: +retPart.toFixed(1) });
    var hisPart = ctx.history.length ? Math.min(9, ctx.history[0].score * 16) : 0;
    v += hisPart; factors.push({ label: ctx.history.length ? 'Historical precedent (' + ctx.history[0].incident.id + ')' : 'No similar prior incident', value: +hisPart.toFixed(1) });
    var healthPart = (100 - ep.health) * 0.06;
    v += healthPart; factors.push({ label: 'Endpoint health deficit (' + ep.health + '/100)', value: +healthPart.toFixed(1) });
    var computed = Math.round(Math.min(100, v));
    var risk = Math.max(computed, floor);
    return {
      computed: computed, floor: floor, risk: risk, factors: factors,
      band: SW.sevOf(risk),
      flooredBy: risk > computed && floor > 0 ? ctx.hits.filter(function (h) { return h.rule.floor === floor; })[0].rule : null,
      confidence: Math.min(96, 46 + ctx.hits.length * 9 + (ctx.retrieval.length ? 14 : 0) + (ctx.history.length ? 8 : 0))
    };
  };

  /* ================= Text composition (template-based, from real data) ================= */
  function fieldLines(ev) {
    return Object.keys(ev.fields).map(function (k) { return k + ' = ' + ev.fields[k]; });
  }
  function analysisText(ctx) {
    var ev = ctx.event, ep = ctx.endpoint, hits = ctx.hits;
    var out = [];
    out.push('Event ' + ev.id + ' on ' + ev.endpoint + ' (' + (ep ? ep.os : 'unknown OS') + ') was reported at ' +
      SW.fmtDate(ev.ts) + ' as ' + ev.severity + ' / ' + ev.type + ': ' + ev.title + '.');
    if (hits.length) {
      out.push('Rule evaluation matched ' + hits.length + ' of ' + A.RULES.length + ' deterministic detections: ' +
        hits.map(function (h) { return h.rule.name + ' (' + h.rule.mitre + ')'; }).join('; ') + '.');
      out.push('Supporting observation — ' + hits.map(function (h) { return h.why; }).join('. ') + '.');
    } else {
      out.push('No deterministic detection rule matched this event, so the assessment rests on reported severity, endpoint standing risk and correlation alone.');
    }
    if (ctx.related.length) {
      out.push('Correlation across the in-memory event set found ' + ctx.related.length + ' other event(s) on ' + ev.endpoint +
        ' within the same window, including ' + ctx.related.slice(0, 2).map(function (r) { return r.id + ' (' + r.severity + ' · ' + r.type + ')'; }).join(' and ') + '.');
    }
    if (ctx.retrieval.length) {
      out.push('Knowledge-base retrieval returned ' + ctx.retrieval.length + ' supporting passage(s); the closest is ' +
        ctx.retrieval[0].chunk.docName + (ctx.retrieval[0].chunk.section ? ' § ' + ctx.retrieval[0].chunk.section : '') +
        ' at cosine similarity ' + ctx.retrieval[0].score.toFixed(3) + '.');
    } else {
      out.push('No supporting documentation found in the knowledge base for this event.');
    }
    if (ctx.history.length) {
      out.push('The closest historical record is ' + ctx.history[0].incident.id + ' — ' + ctx.history[0].incident.title +
        ' (similarity ' + ctx.history[0].score.toFixed(2) + ')' + (ctx.history[0].incident.resolution ? ', which closed as: ' + ctx.history[0].incident.resolution : ', still open') + '.');
    }
    out.push('Uncertainty: this demo has no live EDR corroboration, no binary analysis and no user confirmation, so the finding is unvalidated telemetry.');
    return out;
  }
  function investigationSteps(ctx) {
    var ev = ctx.event, steps = [];
    var ruleIds = ctx.hits.map(function (h) { return h.rule.id; });
    if (ruleIds.indexOf('SW-R001') >= 0)
      steps.push('Retrieve the full command line for ' + (ev.fields.process || 'the process') + ' and decode the base64 payload in an isolated analysis environment — confirms or rules out the encoded-payload finding.');
    if (ruleIds.indexOf('SW-R002') >= 0 || ev.fields.parent)
      steps.push('Reconstruct process ancestry three levels above ' + (ev.fields.process || 'the process') + ' on ' + ev.endpoint + ' — confirms whether a productivity application initiated the chain.');
    if (ruleIds.indexOf('SW-R003') >= 0)
      steps.push('Enumerate every handle opened against lsass.exe in the same session and check the requesting binary signature — confirms or rules out credential access.');
    if (ruleIds.indexOf('SW-R004') >= 0)
      steps.push('Pull authentication logs for ' + (ev.fields.remote_ip || 'the source address') + ' across all hosts and check for any single success after the failures — establishes whether the burst succeeded anywhere.');
    if (ruleIds.indexOf('SW-R005') >= 0)
      steps.push('Review 24 hours of flow records for ' + (ev.fields.remote_ip || 'the destination') + ' and compare the byte-count distribution against a known-good client — confirms or rules out beaconing.');
    if (ruleIds.indexOf('SW-R006') >= 0)
      steps.push('Verify the digital signature, publisher and hash of ' + (ev.fields.file_path || 'the written file') + ', then check whether that hash appears on other managed endpoints — establishes provenance and spread.');
    if (ruleIds.indexOf('SW-R007') >= 0)
      steps.push('List all autostart entries and scheduled tasks on ' + ev.endpoint + ' created in the last 7 days — confirms the scope of the persistence artefact.');
    if (ruleIds.indexOf('SW-R008') >= 0)
      steps.push('Compare the read volume against the documented backup schedule for ' + (ev.fields.user || 'the service account') + ' — confirms or rules out an unscheduled collection.');
    steps.push('Check script-block / interpreter logging coverage on ' + ev.endpoint + ' for the 10 minutes preceding ' + SW.fmtTime(ev.ts) + ' — an evidence gap here weakens every other conclusion.');
    steps.push('Confirm with the signed-in user (' + (ev.fields.user || 'account owner') + ') whether the observed activity was expected — cheapest way to rule out a benign explanation.');
    return steps.slice(0, 6);
  }

  /* ================= Pipeline runner ================= */
  A.NODES = [
    { key: 'detection', name: 'Detection', task: 'Match event fields against deterministic rules' },
    { key: 'context', name: 'Context + Retrieval', task: 'Correlate telemetry, retrieve documents and prior incidents' },
    { key: 'analysis', name: 'Analysis', task: 'Compose the assessment from matched evidence' },
    { key: 'risk', name: 'Risk Assessment', task: 'Score deterministically and enforce rule floors' },
    { key: 'investigation', name: 'Investigation', task: 'Derive defensive investigation steps' },
    { key: 'report', name: 'Report', task: 'Assemble the exportable incident report' }
  ];

  function delay(ms) { return new Promise(function (r) { setTimeout(r, SW.reduced ? 10 : ms); }); }

  /* Runs the full 6-node pipeline for an event. onUpdate(run) fires on every transition. */
  A.run = function (eventId, onUpdate) {
    var ev = SW.state.events.filter(function (e) { return e.id === eventId; })[0];
    if (!ev) return Promise.reject(new Error('Unknown event ' + eventId));
    var ep = SW.state.endpoints.filter(function (e) { return e.id === ev.endpoint; })[0];

    var run = {
      id: 'RUN-' + String(1000 + SW.state.runs.length + 1),
      eventId: ev.id, eventTitle: ev.title, endpoint: ev.endpoint, severity: ev.severity,
      startedAt: new Date(), status: 'running', duration: 0,
      nodes: A.NODES.map(function (n) {
        return { key: n.key, name: n.name, task: n.task, state: 'queued', latency: 0, input: '', output: '' };
      }),
      hits: [], retrieval: [], history: [], related: [], risk: null, analysis: [], steps: [], citations: []
    };
    SW.state.runs.unshift(run);
    var t0 = performance.now();
    function upd() { if (onUpdate) onUpdate(run); document.dispatchEvent(new CustomEvent('sw:runupdate', { detail: run })); }
    function node(i) { return run.nodes[i]; }
    function start(i, input) {
      node(i).state = 'running'; node(i).input = input; node(i)._t = performance.now(); upd();
    }
    function done(i, output) {
      node(i).state = 'done';
      node(i).latency = Math.round(performance.now() - node(i)._t);
      node(i).output = output; upd();
    }
    upd();

    var ctx = { event: ev, endpoint: ep };

    return delay(220).then(function () {
      /* 1 — Detection */
      start(0, 'Event ' + ev.id + ' · ' + Object.keys(ev.fields).length + ' telemetry fields · ' + A.RULES.length + ' rules loaded');
      ctx.hits = A.detect(ev);
      run.hits = ctx.hits.map(function (h) { return { id: h.rule.id, name: h.rule.name, mitre: h.rule.mitre, floor: h.rule.floor, tactic: h.rule.tactic, why: h.why }; });
      return delay(340).then(function () {
        done(0, ctx.hits.length ? ctx.hits.map(function (h) { return h.rule.id + ' ' + h.rule.name + ' [' + h.rule.mitre + '] floor=' + h.rule.floor; }).join('\n') : 'No rule matched — 0/' + A.RULES.length);
        return delay(160);
      });
    }).then(function () {
      /* 2 — Context + retrieval */
      var query = ev.title + ' ' + ev.type + ' ' + (ev.fields.command_line || '') + ' ' + (ev.fields.process || '') + ' ' +
        (ev.fields.file_path || '') + ' ' + ctx.hits.map(function (h) { return h.rule.name + ' ' + h.rule.mitre; }).join(' ');
      start(1, 'Query: "' + query.trim().slice(0, 90) + '…" over ' + SW.state.chunks.length + ' indexed chunks and ' + SW.state.incidents.length + ' prior incidents');
      ctx.retrieval = SW.rag.search(query, 4);
      ctx.history = A.historyMatch(ev);
      ctx.related = SW.state.events.filter(function (o) {
        return o.id !== ev.id && o.endpoint === ev.endpoint;
      }).slice(0, 4);
      run.retrieval = ctx.retrieval.map(function (r) {
        return { chunkId: r.chunk.id, doc: r.chunk.docName, page: r.chunk.page, section: r.chunk.section, score: r.score, terms: r.terms, snippet: SW.rag.body(r.chunk).slice(0, 240) };
      });
      run.history = ctx.history.map(function (h) { return { id: h.incident.id, title: h.incident.title, score: h.score, resolution: h.incident.resolution }; });
      run.related = ctx.related.map(function (e) { return { id: e.id, severity: e.severity, type: e.type, title: e.title, ts: e.ts }; });
      run.citations = run.retrieval.map(function (r) { return { kind: 'doc', ref: r.chunkId, label: r.doc + (r.page ? ' p.' + r.page : ''), score: r.score }; })
        .concat(run.history.map(function (h) { return { kind: 'incident', ref: h.id, label: h.id + ' · ' + h.title, score: h.score }; }));
      return delay(420).then(function () {
        done(1, (ctx.retrieval.length ? ctx.retrieval.map(function (r) { return r.chunk.id + ' ' + r.chunk.docName + ' sim=' + r.score.toFixed(3); }).join('\n') : 'No supporting documentation found in the knowledge base') +
          '\n' + (ctx.history.length ? 'history: ' + ctx.history.map(function (h) { return h.incident.id + ' sim=' + h.score.toFixed(2); }).join(', ') : 'history: no similar prior incident') +
          '\nrelated events on host: ' + ctx.related.length);
        return delay(160);
      });
    }).then(function () {
      /* 3 — Analysis */
      start(2, ctx.hits.length + ' rule hit(s) · ' + ctx.retrieval.length + ' passage(s) · ' + ctx.history.length + ' prior incident(s)');
      ctx.analysis = analysisText(ctx);
      run.analysis = ctx.analysis;
      return delay(460).then(function () {
        done(2, ctx.analysis.length + ' composed paragraphs · ' + ctx.analysis.join(' ').split(/\s+/).length + ' words (template-composed, no LLM)');
        return delay(150);
      });
    }).then(function () {
      /* 4 — Risk */
      start(3, 'severity=' + ev.severity + ' · endpointRisk=' + (ep ? ep.risk : 'n/a') + ' · ruleFloor=' + ctx.hits.reduce(function (m, h) { return Math.max(m, h.rule.floor); }, 0));
      ctx.risk = A.score(ctx);
      run.risk = ctx.risk;
      if (ep) { ep.priorRisk = ep.risk; ep.risk = Math.max(ep.risk, Math.round(ctx.risk.risk * 0.9)); }
      return delay(380).then(function () {
        done(3, 'computed=' + ctx.risk.computed + ' floor=' + ctx.risk.floor + ' → risk=' + ctx.risk.risk + ' (' + ctx.risk.band + ')' +
          (ctx.risk.flooredBy ? '\nfloor enforced by ' + ctx.risk.flooredBy.id : '') + '\nconfidence=' + ctx.risk.confidence + '%');
        return delay(150);
      });
    }).then(function () {
      /* 5 — Investigation */
      start(4, 'rules=' + run.hits.map(function (h) { return h.id; }).join(',') + ' · risk=' + ctx.risk.risk);
      ctx.steps = investigationSteps(ctx);
      run.steps = ctx.steps;
      return delay(360).then(function () {
        done(4, ctx.steps.length + ' defensive investigation steps (read-only guidance; no response actions in this demo)');
        return delay(150);
      });
    }).then(function () {
      /* 6 — Report */
      start(5, 'analysis + ' + run.citations.length + ' citation(s) + ' + run.steps.length + ' steps');
      run.markdown = A.markdown(run);
      return delay(300).then(function () {
        done(5, 'report ready · ' + run.markdown.split('\n').length + ' lines · ' + run.citations.length + ' citations');
        run.status = 'complete';
        run.duration = Math.round(performance.now() - t0);
        ev.status = 'Analysed';
        ev.lastRun = run.id;
        upd();
        SW.toast('Analysis complete · ' + run.id, ev.id + ' → risk ' + run.risk.risk + ' (' + run.risk.band + ') · ' + run.citations.length + ' citations', 'ok');
        return run;
      });
    }).catch(function (err) {
      run.status = 'failed'; run.error = err.message;
      run.nodes.forEach(function (n) { if (n.state === 'running') n.state = 'failed'; });
      upd();
      SW.toast('Run failed', err.message, 'crit');
      throw err;
    });
  };

  /* ================= Markdown report + Blob download ================= */
  A.markdown = function (run) {
    var L = [];
    L.push('# Sentrix — Incident Analysis Report');
    L.push('');
    L.push('> SYNTHETIC DEMO OUTPUT. Generated in-browser by a simulated analysis engine');
    L.push('> (deterministic rules + client-side TF-IDF retrieval). No LLM, no live telemetry.');
    L.push('');
    L.push('| Field | Value |');
    L.push('|---|---|');
    L.push('| Run id | ' + run.id + ' |');
    L.push('| Event | ' + run.eventId + ' — ' + run.eventTitle + ' |');
    L.push('| Endpoint | ' + run.endpoint + ' |');
    L.push('| Reported severity | ' + run.severity + ' |');
    L.push('| Computed risk | ' + (run.risk ? run.risk.risk + '/100 (' + run.risk.band + ')' : 'n/a') + ' |');
    L.push('| Confidence | ' + (run.risk ? run.risk.confidence + '%' : 'n/a') + ' |');
    L.push('| Generated | ' + SW.fmtDate(run.startedAt) + ' |');
    L.push('| Pipeline duration | ' + run.duration + ' ms (measured) |');
    L.push('');
    L.push('## 1. Detection');
    if (run.hits.length) {
      run.hits.forEach(function (h) {
        L.push('- **' + h.id + ' ' + h.name + '** (' + h.mitre + ', ' + h.tactic + ', severity floor ' + h.floor + ') — ' + h.why);
      });
    } else { L.push('- No deterministic rule matched this event.'); }
    L.push('');
    L.push('## 2. Analysis');
    run.analysis.forEach(function (p) { L.push(p); L.push(''); });
    L.push('## 3. Evidence — raw telemetry');
    L.push('```');
    L.push('event_id = ' + run.eventId);
    (run.telemetry || []).forEach(function (l) { L.push(l); });
    L.push('```');
    L.push('');
    L.push('## 4. Knowledge-base citations');
    if (run.retrieval.length) {
      run.retrieval.forEach(function (r) {
        L.push('- `' + r.chunkId + '` — ' + r.doc + (r.page ? ' p.' + r.page : '') + (r.section ? ' § ' + r.section : '') +
          ' · cosine similarity ' + r.score.toFixed(3));
        L.push('  > ' + r.snippet.replace(/\s+/g, ' ').slice(0, 200) + '…');
      });
    } else { L.push('- No supporting documentation found in the knowledge base.'); }
    L.push('');
    L.push('## 5. Historical context');
    if (run.history.length) {
      run.history.forEach(function (h) {
        L.push('- ' + h.id + ' — ' + h.title + ' (similarity ' + h.score.toFixed(2) + ')' + (h.resolution ? ' · closed: ' + h.resolution : ' · still open'));
      });
    } else { L.push('- No similar prior incident in the in-memory incident set.'); }
    L.push('');
    L.push('## 6. Risk assessment');
    if (run.risk) {
      L.push('Computed score ' + run.risk.computed + ', rule floor ' + run.risk.floor + ', final risk **' + run.risk.risk + ' (' + run.risk.band + ')**.');
      L.push('');
      L.push('| Factor | Contribution |');
      L.push('|---|---|');
      run.risk.factors.forEach(function (f) { L.push('| ' + f.label + ' | ' + f.value + ' |'); });
    }
    L.push('');
    L.push('## 7. Recommended defensive investigation (read-only)');
    run.steps.forEach(function (s, i) { L.push((i + 1) + '. ' + s); });
    L.push('');
    L.push('## 8. Pipeline trace');
    L.push('| Node | State | Latency (ms) |');
    L.push('|---|---|---|');
    run.nodes.forEach(function (n) { L.push('| ' + n.name + ' | ' + n.state + ' | ' + n.latency + ' |'); });
    L.push('');
    L.push('_No response or remediation actions are proposed or available in this demo — investigation guidance only._');
    return L.join('\n');
  };

  A.download = function (run) {
    var md = run.markdown || A.markdown(run);
    var blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'Sentrix-' + run.id + '-' + run.eventId + '.md';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    SW.toast('Report downloaded', a.download + ' (' + SW.bytes(blob.size) + ')', 'ok');
  };

  /* ================= Assistant answering ================= */
  var Q = SW.assistant = {};

  Q.SUGGESTED = [
    'What does policy say about encoded PowerShell?',
    'Summarise the riskiest endpoints right now',
    'Which critical events are open?',
    'What happened in INC-2210?',
    'Search the knowledge base for LSASS guidance',
    'Is billing@invoice-payments-portal.example technically valid?',
    'Does example.com have legitimate mail infrastructure?',
    'Which authentication records are missing for contact@example.com?',
    'What is the difference between a valid email and verified ownership?'
  ];

  function topEvents(filterFn, n) {
    return SW.state.events.filter(filterFn).slice(0, n || 5);
  }

  /* Routes the question by intent, then answers from real data + real retrieval. */
  Q.answer = function (question) {
    var q = question.trim();
    var lower = q.toLowerCase();
    var res = { question: q, sections: [], sourcesSearched: [], id: SW.uid('ans') };
    var retrieval = SW.rag.search(q, 5);
    var epMatch = SW.state.endpoints.filter(function (e) { return lower.indexOf(e.host.toLowerCase()) >= 0; });
    var incMatch = SW.state.incidents.filter(function (i) { return lower.indexOf(i.id.toLowerCase()) >= 0; });
    var evMatch = SW.state.events.filter(function (e) { return lower.indexOf(e.id.toLowerCase()) >= 0; });
    var wantsRisky = /(risk|riskiest|worst|unhealthy|weakest)/.test(lower);
    var wantsCritical = /(critical|high severity|open alert|urgent|worst alerts)/.test(lower);
    var wantsOffline = /(offline|not reporting|stopped reporting)/.test(lower);
    var wantsRuns = /(agent|run|pipeline|analysis history)/.test(lower);
    var analysis = [], evidence = [], history = [], steps = [], risk = null;

    res.sourcesSearched.push(SW.state.chunks.length + ' indexed knowledge-base chunks');
    res.sourcesSearched.push(SW.state.events.length + ' in-memory security events');
    res.sourcesSearched.push(SW.state.endpoints.length + ' endpoints');
    res.sourcesSearched.push(SW.state.incidents.length + ' incident records');

    if (epMatch.length) {
      epMatch.slice(0, 2).forEach(function (ep) {
        var evs = SW.state.events.filter(function (e) { return e.endpoint === ep.id; });
        analysis.push(ep.host + ' is a ' + ep.os + ' host in the ' + ep.group + ' group at ' + ep.ip + '. It is currently ' +
          (ep.online ? 'online' : 'offline (last seen ' + ep.lastSeen + ')') + ' with standing risk ' + ep.risk +
          '/100 and health ' + ep.health + '/100. ' + evs.length + ' event(s) in the current window reference this host.');
        evidence = evidence.concat(evs.slice(0, 4).map(function (e) {
          return e.id + '  ' + SW.fmtTime(e.ts) + '  ' + e.severity.padEnd(8) + ' ' + e.type + ' — ' + e.title;
        }));
        risk = { score: ep.risk, band: SW.sevOf(ep.risk), why: 'Standing endpoint risk from the in-memory dataset (patch drift ' + ep.patchDrift + ', health ' + ep.health + ').', confidence: 72 };
        steps.push('Open the ' + ep.host + ' detail view and review the process, network and authentication tabs for the last 24 hours.');
      });
    }
    if (incMatch.length) {
      incMatch.forEach(function (inc) {
        analysis.push(inc.id + ' — ' + inc.title + ' (' + inc.severity + '). ' + inc.summary +
          ' It is at stage "' + SW.seed.stages[inc.stage] + '" and owned by ' + inc.analyst + '.');
        history.push({ id: inc.id, text: inc.resolution ? 'Closed: ' + inc.resolution : 'Still open at stage ' + SW.seed.stages[inc.stage] });
        risk = { score: { CRITICAL: 88, HIGH: 72, MEDIUM: 48, LOW: 25 }[inc.severity] || 40, band: inc.severity, why: 'Severity recorded on the incident record ' + inc.id + '.', confidence: 80 };
        steps.push('Review the evidence tabs on ' + inc.id + ' and confirm every linked event is accounted for.');
      });
    }
    if (evMatch.length) {
      evMatch.slice(0, 2).forEach(function (e) {
        var hits = A.detect(e);
        analysis.push(e.id + ' on ' + e.endpoint + ' at ' + SW.fmtDate(e.ts) + ': ' + e.title + '. Rule evaluation matches ' +
          (hits.length ? hits.map(function (h) { return h.rule.name + ' (' + h.rule.mitre + ')'; }).join(', ') : 'no deterministic rule') + '.');
        evidence = evidence.concat(fieldLines(e));
        steps.push('Run the analysis pipeline on ' + e.id + ' from the Security Events table to produce a cited assessment.');
      });
    }
    if (wantsRisky && !epMatch.length) {
      var top = SW.state.endpoints.slice().sort(function (a, b) { return b.risk - a.risk; }).slice(0, 5);
      analysis.push('The five highest-risk endpoints in the current in-memory snapshot are ' +
        top.map(function (e) { return e.host + ' (' + e.risk + ')'; }).join(', ') + '. Risk here is a demo heuristic combining standing risk, health and patch drift — not a validated model.');
      evidence = evidence.concat(top.map(function (e) {
        return e.host.padEnd(12) + ' risk=' + String(e.risk).padStart(3) + '  health=' + String(e.health).padStart(3) + '  patch_drift=' + e.patchDrift + '  ' + (e.online ? 'online' : 'offline');
      }));
      risk = { score: top[0].risk, band: SW.sevOf(top[0].risk), why: 'Highest standing endpoint risk is ' + top[0].host + ' at ' + top[0].risk + '/100.', confidence: 68 };
      steps.push('Start with ' + top[0].host + ': confirm its open events, then check whether its risk was raised by a recent agent run.');
    }
    if (wantsCritical) {
      var crit = topEvents(function (e) { return e.severity === 'CRITICAL' || e.severity === 'HIGH'; }, 6);
      analysis.push(crit.length + ' critical/high event(s) are present in the current window, spanning ' +
        Array.from(new Set(crit.map(function (e) { return e.endpoint; }))).join(', ') + '.');
      evidence = evidence.concat(crit.map(function (e) {
        return SW.fmtTime(e.ts) + '  ' + e.severity.padEnd(8) + e.endpoint.padEnd(13) + e.title;
      }));
      steps.push('Triage in severity order and run the pipeline on the newest CRITICAL event first.');
    }
    if (wantsOffline) {
      var off = SW.state.endpoints.filter(function (e) { return !e.online; });
      analysis.push(off.length ? off.length + ' endpoint(s) are not reporting: ' + off.map(function (e) { return e.host + ' (' + e.lastSeen + ')'; }).join(', ') + '.' : 'Every managed endpoint is currently reporting telemetry.');
      evidence = evidence.concat(off.map(function (e) { return e.host + '  last_seen=' + e.lastSeen + '  agent=' + e.agent; }));
    }
    if (wantsRuns) {
      if (SW.state.runs.length) {
        analysis.push(SW.state.runs.length + ' agent run(s) have executed in this session. The most recent is ' +
          SW.state.runs[0].id + ' on ' + SW.state.runs[0].eventId + ' (' + SW.state.runs[0].status + ', ' + SW.state.runs[0].duration + ' ms measured).');
        evidence = evidence.concat(SW.state.runs.slice(0, 5).map(function (r) {
          return r.id + '  ' + r.eventId + '  ' + (r.risk ? 'risk=' + r.risk.risk : 'risk=n/a') + '  ' + r.duration + 'ms  ' + r.status;
        }));
      } else {
        analysis.push('No agent runs have executed yet in this session. Open the AI Security Center or a security event and choose "Run analysis".');
      }
    }

    if (retrieval.length) {
      var lead = retrieval[0];
      analysis.push('Knowledge-base retrieval matched ' + retrieval.length + ' passage(s). The strongest is ' + lead.chunk.docName +
        (lead.chunk.section ? ' § ' + lead.chunk.section : '') + ' at similarity ' + lead.score.toFixed(3) + ', which states: “' +
        SW.rag.body(lead.chunk).replace(/\s+/g, ' ').slice(0, 260) + '…”');
    } else if (!analysis.length) {
      analysis.push('No supporting documentation found in the knowledge base for that question, and it did not match an endpoint, event or incident id in the in-memory dataset. Try naming a host (for example WKS-042), an incident (INC-2291), or a policy topic such as "encoded PowerShell".');
    }

    res.sections.push({ kind: 'ai', title: 'AI Analysis', paragraphs: analysis });
    if (evidence.length) res.sections.push({ kind: 'telemetry', title: 'Evidence', lines: evidence.slice(0, 10) });
    if (retrieval.length) res.sections.push({ kind: 'rag', title: 'RAG Sources', chips: retrieval.map(function (r) {
      return { chunkId: r.chunk.id, doc: r.chunk.docName, page: r.chunk.page, section: r.chunk.section, score: r.score, terms: r.terms };
    }) });
    if (history.length) res.sections.push({ kind: 'history', title: 'Historical Context', items: history });
    if (risk) res.sections.push({ kind: 'risk', title: 'Risk Assessment', risk: risk });
    if (steps.length) res.sections.push({ kind: 'steps', title: 'Recommended Defensive Investigation', steps: steps.slice(0, 5) });
    res.retrievalEmpty = retrieval.length === 0;
    return res;
  };
})();
