/* Sentrix — connects Email Identity Intelligence to the existing modules:
   AI Security Center, Incident Management, Reporting and the Knowledge Base / RAG views.
   Each panel is appended after the original view renders and loads from the Sentrix API. */
(function () {
  'use strict';
  var SW = window.SW, api = SW.api, X = SW.email;

  var EMAIL_WORDS = /\b(e-?mail|mailbox|spf|dkim|dmarc|mx|ownership|disposable|domain reputation|sender authentication|null mx)\b/i;
  X.isEmailQuestion = function (q) {
    return /[^\s@]+@[^\s@]+\.[a-z]{2,}/i.test(q) || EMAIL_WORDS.test(q) || !!(SW.state.emailCtx && /\b(this|it|record|address|verify|verified|valid|suspicious|fail|missing)\b/i.test(q));
  };

  function after(name, fn) {
    var def = SW.routes[name];
    if (!def) return;
    var orig = def.render;
    def.render = function (host, param) {
      orig.call(this, host, param);
      var seq = SW.renderSeq;
      var slot = document.createElement('div');
      slot.className = 'ei-slot';
      host.appendChild(slot);
      fn(slot, function () { return seq === SW.renderSeq && document.body.contains(slot); });
    };
  }
  function panel(title, sub, inner, actions) {
    return '<div class="card panel ei-panel"><div class="card-head"><div><h3>' + title + '</h3><div class="faint">' + sub + '</div></div>' +
      '<div class="row-gap">' + (actions || '') + '<span class="prov-tag prov-telemetry"><i></i>Sentrix API</span></div></div>' + inner + '</div>';
  }
  function offline(slot, title) {
    slot.innerHTML = panel(title, 'Live backend data', '<p class="faint">Not available — ' + (api.online() ? 'sign in with a Sentrix backend account' : 'the Sentrix API is not running (uvicorn backend.app.main:app --reload)') + '.</p>');
  }
  function withApi(slot, title, alive, go) {
    api.probe().then(function () {
      if (!alive()) return;
      if (!api.authed()) return offline(slot, title);
      go();
    });
  }

  /* ---------- AI Security Center: email analysis console ---------- */
  after('ai-center', function (slot, alive) {
    var T = 'Email identity analysis';
    withApi(slot, T, alive, function () {
      api.get('/email-identity/records?limit=50&sort=risk').then(function (r) {
        if (!alive()) return;
        slot.innerHTML = panel(T, 'Ask Sentrix AI about an email record — answers are grounded in DNS evidence, risk findings, ownership history and the knowledge base',
          '<div class="filters"><select id="eaRec" style="flex:1 1 260px" aria-label="Email record">' + (r.items.length ? r.items.map(function (x) {
            return '<option value="' + x.id + '">' + SW.esc(x.email) + ' · risk ' + x.risk_score + ' (' + x.risk_band + ')</option>'; }).join('') : '<option value="">No email records yet</option>') + '</select>' +
          '<select id="eaQ" style="flex:1 1 300px" aria-label="Question">' + ['Is this email address technically valid?', 'Does this domain have legitimate mail infrastructure?', 'Is email ownership verified?',
            'Why did this email fail verification?', 'Are there suspicious domain indicators?', 'Which authentication records are missing?', 'What steps should be taken to resolve the issue?']
            .map(function (q) { return '<option>' + q + '</option>'; }).join('') + '</select>' +
          '<button class="btn btn-primary" id="eaGo"' + (r.items.length ? '' : ' disabled') + '>' + SW.icon('ai', 15) + 'Analyse</button>' +
          '<a class="btn btn-ghost" href="#/email-verification">Email Verification</a></div><div id="eaOut" style="margin-top:14px"></div>');
        slot.querySelector('#eaGo').addEventListener('click', function () {
          var b = this, out = slot.querySelector('#eaOut');
          b.disabled = true; out.innerHTML = '<div class="loading-row"><span class="spinner"></span>Sentrix AI is gathering evidence…</div>';
          api.post('/ai/email/ask', { question: slot.querySelector('#eaQ').value, record_id: slot.querySelector('#eaRec').value, run_if_missing: false }).then(function (d) {
            b.disabled = false;
            out.innerHTML = '<div class="answer-card">' + '<p><b>' + SW.esc(d.assistant) + ':</b> ' + SW.esc(d.summary) + '</p>' +
              d.sections.map(function (s) {
                return '<div class="answer-section as-' + SW.esc(s.kind) + '"><div class="sec-head"><span class="prov-tag prov-' + (s.kind === 'rag' ? 'rag' : s.kind === 'telemetry' ? 'telemetry' : s.kind === 'history' ? 'history' : 'ai') + '"><i></i>' + SW.esc(s.title) + '</span></div>' +
                  (s.text ? '<p>' + SW.esc(s.text) + '</p>' : '') + (s.bullets ? '<ul class="list-clean">' + s.bullets.map(function (x) { return '<li>' + SW.esc(x) + '</li>'; }).join('') + '</ul>' : '') +
                  (s.citations && s.citations.length ? '<div class="faint" style="margin-top:6px">Evidence: ' + s.citations.map(function (c) { return SW.esc(c.label); }).join(' · ') + '</div>' : '') + '</div>';
              }).join('') + '<p class="faint src-foot">' + SW.esc(d.disclaimer) + '</p></div>';
          }, function (e) { b.disabled = false; out.innerHTML = '<div class="form-error">' + SW.esc(e.message) + '</div>'; });
        });
      }, function () { if (alive()) offline(slot, T); });
    });
  });

  /* ---------- Incidents: cases opened from email identity ---------- */
  var STATUSES = ['open', 'investigating', 'resolved', 'false_positive'];
  after('incidents', function (slot, alive) {
    var T = 'Email identity cases';
    withApi(slot, T, alive, function () {
      api.get('/incidents').then(function (r) {
        if (!alive()) return;
        var items = r.items.filter(function (i) { return i.source === 'email_identity'; });
        slot.innerHTML = panel(T, 'Incidents and investigation cases opened from suspicious email indicators (persisted in the Sentrix database)',
          items.length ? '<div class="table-wrap"><table><thead><tr><th>Key</th><th>Title</th><th>Type</th><th>Severity</th><th>Risk</th><th>Status</th><th>Opened</th><th>Evidence</th></tr></thead><tbody>' + items.map(function (i) {
            return '<tr><td class="mono strong">' + SW.esc(i.key) + '</td><td>' + SW.esc(i.title) + '</td><td>' + SW.esc(i.kind) + '</td><td>' + X.st(i.severity) + '</td><td class="mono">' + (i.risk_score != null ? i.risk_score : '—') + '</td>' +
              '<td>' + (SW.can('advanceIncident') ? '<select data-inc="' + i.id + '" aria-label="Case status">' + STATUSES.map(function (s) { return '<option' + (s === i.status ? ' selected' : '') + '>' + s + '</option>'; }).join('') + '</select>' : X.st(i.status)) + '</td>' +
              '<td class="mono">' + SW.esc(SW.fmtDate(i.opened_at)) + '</td><td>' + (i.source_ref ? '<a class="linkish" href="#/email-record/' + i.source_ref + '">email record</a>' : '—') + '</td></tr>';
          }).join('') + '</tbody></table></div>' : '<p class="faint">No email identity cases yet. Open one from an email record with suspicious indicators.</p>');
        slot.addEventListener('change', function (e) {
          var s = e.target.closest('select[data-inc]'); if (!s) return;
          api.patch('/incidents/' + s.dataset.inc, { status: s.value }).then(function () { SW.toast('Case updated', 'Status: ' + s.value, 'ok'); }, function (er) { SW.toast('Update failed', er.message); });
        });
      }, function () { if (alive()) offline(slot, T); });
    });
  });

  /* ---------- Reports: stored PDF reports ---------- */
  after('reports', function (slot, alive) {
    var T = 'Sentrix PDF reports';
    withApi(slot, T, alive, function () {
      api.get('/reports').then(function (r) {
        if (!alive()) return;
        slot.innerHTML = panel(T, 'Email investigation and summary reports generated by the backend (SHA-256 recorded for integrity)',
          (r.items.length ? '<div class="table-wrap"><table><thead><tr><th>Created</th><th>Title</th><th>Kind</th><th>Size</th><th>SHA-256</th><th></th></tr></thead><tbody>' + r.items.map(function (x) {
            return '<tr><td class="mono">' + SW.esc(SW.fmtDate(x.created_at)) + '</td><td>' + SW.esc(x.title) + '</td><td class="mono">' + SW.esc(x.kind) + '</td><td class="mono">' + Math.round(x.size_bytes / 1024) + ' KB</td>' +
              '<td class="mono faint">' + SW.esc((x.sha256 || '').slice(0, 16)) + '…</td><td><button class="btn btn-sm" data-dl="' + x.id + '">' + SW.icon('download', 13) + 'Download</button></td></tr>'; }).join('') + '</tbody></table></div>'
            : '<p class="faint">No backend reports yet.</p>'),
          '<button class="btn btn-sm btn-primary" id="genSum">' + SW.icon('download', 13) + 'Email identity summary PDF</button>');
        slot.addEventListener('click', function (e) {
          var b = e.target.closest('[data-dl]');
          if (b) api.download('/reports/' + b.dataset.dl + '/download').then(function (n) { SW.toast('Downloaded', n, 'ok'); }, function (er) { SW.toast('Download failed', er.message); });
          if (e.target.closest('#genSum')) api.download('/email-identity/report/summary.pdf').then(function (n) { SW.toast('Report generated', n, 'ok'); SW.render(); }, function (er) { SW.toast('Report failed', er.message); });
        });
      }, function () { if (alive()) offline(slot, T); });
    });
  });

  /* ---------- Knowledge Base + RAG: tenant-scoped backend knowledge ---------- */
  function kbPanel(slot, alive) {
    var T = 'Email security knowledge (backend RAG)';
    withApi(slot, T, alive, function () {
      api.get('/knowledge/documents').then(function (r) {
        if (!alive()) return;
        slot.innerHTML = panel(T, 'Tenant-isolated documents used by Sentrix AI: SPF/DKIM/DMARC guidance, playbooks and indexed email investigations',
          '<div class="searchbox">' + SW.icon('search', 16) + '<input id="bkQ" type="search" placeholder="Search email security knowledge (e.g. DMARC quarantine, null MX)…" aria-label="Search backend knowledge"></div>' +
          '<div id="bkOut" style="margin-top:12px"></div><div class="hr"></div>' +
          '<ul class="list-clean">' + r.items.map(function (d) {
            return '<li><b>' + SW.esc(d.title) + '</b> <span class="faint">· ' + SW.esc(d.doc_type) + ' · ' + d.chunk_count + ' chunks · ' + SW.esc(d.source || '') + '</span>' +
              (d.ref_type === 'email_record' && d.ref_id ? ' <a class="linkish" href="#/email-record/' + d.ref_id + '">record</a>' : '') + '</li>'; }).join('') + '</ul>');
        var tmr;
        slot.querySelector('#bkQ').addEventListener('input', function () {
          var q = this.value.trim(); clearTimeout(tmr);
          tmr = setTimeout(function () {
            var out = slot.querySelector('#bkOut');
            if (q.length < 2) { out.innerHTML = ''; return; }
            api.get('/knowledge/search?q=' + encodeURIComponent(q)).then(function (s) {
              out.innerHTML = s.hits.length ? s.hits.map(function (h) {
                return '<div class="kb-hit"><div class="faint"><b>' + SW.esc(h.citation) + '</b> · BM25 ' + h.score + '</div><p>' + SW.esc(h.text) + '</p></div>'; }).join('') : '<p class="faint">No matching passages.</p>';
            });
          }, 250);
        });
      }, function () { if (alive()) offline(slot, T); });
    });
  }
  after('knowledge-base', kbPanel);
  after('rag', kbPanel);
})();
