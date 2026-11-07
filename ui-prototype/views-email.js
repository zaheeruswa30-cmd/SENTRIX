/* Sentrix — Email Identity Intelligence views.
   Every number on these screens comes from the Sentrix API (/api/v1/email-identity). When the API is not
   reachable the views show a "not connected" state; they never fall back to fabricated data.

   The UI keeps six claims visually separate, mirroring the backend data model:
     valid syntax · existing domain · mail infrastructure · SPF/DKIM/DMARC posture · verified mailbox ownership
     · real-world identity (always "not assessed"). */
(function () {
  'use strict';
  var SW = window.SW;
  var api = SW.api;
  var EI = '/email-identity';
  var X = (SW.email = {});

  /* ---------------- formatting helpers ---------------- */
  var TONE = {
    good: ['valid', 'resolves', 'present', 'enforced', 'selector_found', 'signature_pass', 'not_disposable', 'verified',
      'low', 'pass', 'active', 'consumed', 'resolved', 'success', 'ok', 'listed_clean', 'clean'],
    warn: ['implicit', 'monitoring', 'no_address', 'permissive', 'multiple', 'pending', 'guarded', 'warn', 'elevated',
      'investigating', 'open', 'medium', 'expired', 'role'],
    bad: ['invalid', 'nxdomain', 'null_mx', 'absent', 'missing', 'not_found', 'signature_fail', 'disposable', 'locked',
      'failed', 'high', 'critical', 'error', 'fail', 'listed', 'suspicious', 'denied', 'failure'],
    neutral: ['not_checked', 'unknown', 'unverified', 'not_assessed', 'info', 'revoked', 'no_signature']
  };
  function tone(v) {
    v = String(v == null ? 'unknown' : v).toLowerCase();
    for (var k in TONE) if (TONE[k].indexOf(v) >= 0) return k;
    return 'neutral';
  }
  function label(v) { return String(v == null ? '—' : v).replace(/_/g, ' '); }
  X.st = function (v, text) {
    return '<span class="st st-' + tone(v) + '">' + SW.esc(text || label(v)) + '</span>';
  };
  function when(d) { return d ? '<span class="nowrap" title="' + SW.esc(SW.fmtDate(d)) + '">' + SW.ago(d) + '</span>' : '<span class="faint">—</span>'; }
  function riskCell(score, band) {
    if (score == null) return '<span class="faint">—</span>';
    return '<span class="risk-pill risk-' + SW.esc(band || 'low') + '"><b>' + score + '</b>' + SW.esc(band || '') + '</span>';
  }
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
  function issueText(i) { return typeof i === 'string' ? i : (i && i.message) || ''; }
  function issueSev(i) { return (i && i.severity) || 'info'; }
  X.tone = tone;

  /* Render-sequence guard so a slow request can't paint over a newer view. */
  function guard(host) {
    var seq = SW.renderSeq;
    return function () { return seq === SW.renderSeq && document.body.contains(host); };
  }
  function failInto(el, err) {
    if (err && err.status && err.status !== 0 && err.status !== 401) {
      el.innerHTML = '<div class="card"><div class="form-error" role="alert">' + SW.esc(err.message) + '</div></div>';
    } else el.innerHTML = api.unavailableHTML(err);
  }
  function needBackend(host, body) {
    if (!api.authed()) {
      return api.probe().then(function () {
        if (!api.authed() && SW.reconnectBackend) return SW.reconnectBackend();
      }).then(function () {
        if (SW.updateApiChip) SW.updateApiChip();
        if (!api.authed()) { body.innerHTML = api.unavailableHTML(); return false; }
        return true;
      });
    }
    return Promise.resolve(true);
  }
  function canWrite() { return SW.can('run'); }
  function deliverable(r) { return r.syntax_status === 'valid' && r.dns_status !== 'nxdomain' && ['present', 'implicit'].indexOf(r.mx_status) >= 0; }
  function gateBtn(html) { return SW.gate('run', html); }
  function subnav(active) {
    var items = [['email-verification', 'Verification'], ['email-domain', 'Domain intelligence'], ['email-auth', 'Authentication'],
      ['email-ownership', 'Ownership'], ['email-risk', 'Risk analysis'], ['email-history', 'History']];
    return '<nav class="subnav" aria-label="Email Identity Intelligence">' + items.map(function (i) {
      return '<a href="#/' + i[0] + '" class="' + (i[0] === active ? 'on' : '') + '"' + (i[0] === active ? ' aria-current="page"' : '') + '>' + i[1] + '</a>';
    }).join('') + '</nav>';
  }
  function page(host, active, title, sub, actions) {
    host.innerHTML = SW.head(title, sub, actions || '') + subnav(active) + '<div id="eiBody"><div class="card"><div class="loading-row"><span class="spinner"></span>Loading from Sentrix API…</div></div></div>';
    return host.querySelector('#eiBody');
  }
  function kpi(lbl, val, foot, cls) {
    return '<div class="kpi' + (cls ? ' ' + cls : '') + '"><div class="k-label">' + lbl + '</div><div class="k-value" style="font-size:28px">' + val + '</div>' +
      '<div class="k-foot"><span>' + foot + '</span></div></div>';
  }
  function distinction() {
    return '<details class="card mb distinction"><summary><b>What these checks can — and cannot — establish</b><span class="faint"> · six separate claims</span></summary>' +
      '<ol class="claims">' +
        '<li><b>Valid email syntax</b> — the text is a well-formed address. Says nothing about delivery.</li>' +
        '<li><b>Existing email domain</b> — the domain resolves in DNS.</li>' +
        '<li><b>Configured mail infrastructure</b> — MX hosts exist, so the domain can receive mail.</li>' +
        '<li><b>SPF / DKIM / DMARC</b> — the domain owner\u2019s anti-spoofing configuration. A DKIM key in DNS is not proof that any message passed DKIM.</li>' +
        '<li><b>Verified mailbox ownership</b> — someone proved they can read mail at this address via a one-time code or link.</li>' +
        '<li><b>Real-world identity</b> — <u>never</u> established by email checks. Sentrix does not judge whether a person is genuine or trustworthy.</li>' +
      '</ol></details>';
  }

  /* ---------------- shared actions ---------------- */
  function newCheckModal(prefill, done) {
    if (!canWrite()) { SW.toast('Read-only role', SW.denyReason('run')); return; }
    SW.modal({
      title: 'Run email identity check',
      body: '<form id="ckForm" class="stack" novalidate>' +
        '<div class="form-error" role="alert" hidden></div>' +
        '<label class="fl">Email address<input id="ckEmail" type="text" autocomplete="off" spellcheck="false" placeholder="name@company.com" value="' + SW.esc(prefill || '') + '"></label>' +
        '<label class="fl">Purpose of the check <span class="faint">(recorded in the audit trail)</span><input id="ckPurpose" type="text" value="Customer onboarding review" maxlength="200"></label>' +
        '<label class="fl">DKIM selectors to probe <span class="faint">(optional, comma-separated — common selectors are always tried)</span><input id="ckSel" type="text" placeholder="s1, mail, k2" spellcheck="false"></label>' +
        '<label class="check"><input type="checkbox" id="ckForce"><span>Bypass the DNS cache and re-query now</span></label>' +
        '<label class="fl">Or bulk check (one address per line, max 25)<textarea id="ckBulk" rows="3" spellcheck="false" placeholder="a@example.com&#10;b@example.org"></textarea></label>' +
        '<p class="faint">Only DNS lookups against the domain are performed. No mail is sent and no mailbox is probed (no SMTP RCPT checks).</p></form>',
      footer: '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-primary" id="ckGo">' + SW.icon('play', 15) + 'Run check</button>',
      onMount: function (m) {
        m.querySelector('#ckEmail').focus();
        m.querySelector('#ckGo').addEventListener('click', function () {
          var b = this, fe = m.querySelector('.form-error');
          var email = m.querySelector('#ckEmail').value.trim(), purpose = m.querySelector('#ckPurpose').value.trim();
          var bulk = m.querySelector('#ckBulk').value.split(/[\s,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
          fe.hidden = true;
          if (!email && !bulk.length) { fe.hidden = false; fe.textContent = 'Enter an email address (or a list for bulk checking).'; return; }
          if (purpose.length < 3) { fe.hidden = false; fe.textContent = 'State the purpose of the check (at least 3 characters).'; return; }
          b.disabled = true; b.innerHTML = '<span class="spinner"></span>Checking DNS…';
          var p;
          if (bulk.length) {
            if (email) bulk.unshift(email);
            p = api.post(EI + '/records/bulk', { emails: bulk.slice(0, 25), purpose: purpose }).then(function (r) { return { bulk: r.items }; });
          } else {
            var sel = m.querySelector('#ckSel').value.split(/[\s,]+/).filter(Boolean);
            p = api.post(EI + '/records', { email: email, purpose: purpose, dkim_selectors: sel, force: m.querySelector('#ckForce').checked });
          }
          p.then(function (r) {
            SW.closeModal();
            if (r.bulk) { SW.toast('Bulk check complete', plural(r.bulk.length, 'address') + ' checked', 'ok'); if (done) done(); }
            else { SW.toast('Check complete', r.email + ' · risk ' + r.risk_score + ' (' + r.risk_band + ')', 'ok'); SW.go('email-record/' + r.id); }
          }, function (err) {
            b.disabled = false; b.innerHTML = SW.icon('play', 15) + 'Run check';
            fe.hidden = false; fe.textContent = err.message;
          });
        });
      }
    });
  }
  X.newCheck = newCheckModal;

  function caseModal(rec, done) {
    var sev = rec.risk_band === 'high' ? 'high' : rec.risk_band === 'elevated' ? 'medium' : 'low';
    SW.modal({
      title: 'Open a case for ' + rec.email,
      body: '<div class="stack"><div class="form-error" role="alert" hidden></div>' +
        '<label class="fl">Case type<select id="cKind"><option value="investigation">Investigation case — gather more evidence</option><option value="incident">Security incident — suspected malicious activity</option></select></label>' +
        '<label class="fl">Severity<select id="cSev">' + ['low', 'medium', 'high', 'critical'].map(function (s) {
          return '<option' + (s === sev ? ' selected' : '') + '>' + s + '</option>'; }).join('') + '</select></label>' +
        '<label class="fl">Title<input id="cTitle" maxlength="300" value="' + SW.esc('Suspicious email indicators: ' + rec.email) + '"></label>' +
        '<label class="fl">Analyst note<textarea id="cNote" rows="3" maxlength="4000" placeholder="Context, why you are escalating, next steps…"></textarea></label>' +
        '<p class="faint">The case links to this record\u2019s evidence and risk findings. It records technical indicators about the address and domain — not a judgement about the person.</p></div>',
      footer: '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-primary" id="cGo">Create case</button>',
      onMount: function (m) {
        m.querySelector('#cGo').addEventListener('click', function () {
          var b = this; b.disabled = true;
          api.post(EI + '/records/' + rec.id + '/incident', {
            kind: m.querySelector('#cKind').value, severity: m.querySelector('#cSev').value,
            title: m.querySelector('#cTitle').value.trim() || null, note: m.querySelector('#cNote').value.trim() || null
          }).then(function (r) {
            SW.closeModal();
            SW.toast((r.kind === 'incident' ? 'Incident ' : 'Investigation ') + r.incident_key + ' opened', r.title, 'ok');
            if (done) done(r);
          }, function (err) { b.disabled = false; var fe = m.querySelector('.form-error'); fe.hidden = false; fe.textContent = err.message; });
        });
      }
    });
  }

  function ownershipModal(rec, ov, done) {
    var active = ov && ov.active_challenge;
    SW.modal({
      title: 'Mailbox ownership verification',
      body: '<div class="stack"><div class="form-error" role="alert" hidden></div>' +
        '<p class="muted">Sentrix emails a one-time code and a confirmation link to <b class="mono">' + SW.esc(rec.email) + '</b>. ' +
        'Only a hash of each secret is stored; the code is never shown here or written to logs. Verification proves the recipient can read that mailbox — it does not prove who they are.</p>' +
        (active ? '<div class="note-box">Active challenge · expires ' + SW.esc(SW.fmtDate(active.expires_at)) + ' · ' + active.attempts_remaining + ' attempt(s) left · delivery ' + SW.esc(active.delivery_status) + ' via ' + SW.esc(active.delivery_provider) + '</div>' : '') +
        '<label class="check"><input type="checkbox" id="oConsent"><span>I confirm this address belongs to someone who requested or expects verification, and I am authorised to send it a verification message.</span></label>' +
        '<div class="row-gap"><button class="btn btn-primary btn-sm" id="oSend">' + SW.icon('mail', 14) + (active ? 'Resend verification' : 'Send verification') + '</button>' +
          '<span class="faint" id="oSendInfo">' + (ov ? ov.sends_remaining_24h + ' send(s) left today' + (ov.resend_available_in_seconds ? ' · resend in ' + ov.resend_available_in_seconds + 's' : '') : '') + '</span></div>' +
        '<div class="hr"></div>' +
        '<label class="fl">Enter the code the recipient read back to you<input id="oCode" inputmode="numeric" autocomplete="one-time-code" maxlength="12" placeholder="6-digit code" class="mono"></label>' +
        '<button class="btn btn-sm" id="oVerify"' + (active ? '' : ' disabled') + '>' + SW.icon('check', 14) + 'Verify code</button></div>',
      footer: '<button class="btn btn-ghost" data-close>Close</button>',
      onMount: function (m) {
        var fe = m.querySelector('.form-error');
        function err(e) { fe.hidden = false; fe.textContent = e.message; }
        m.querySelector('#oSend').addEventListener('click', function () {
          var b = this;
          if (!m.querySelector('#oConsent').checked) { err({ message: 'Confirm that you are authorised to send the verification message.' }); return; }
          fe.hidden = true; b.disabled = true;
          api.post(EI + '/records/' + rec.id + '/ownership/' + (active ? 'resend' : 'start'), { consent: true }).then(function (v) {
            b.disabled = false; active = v.active_challenge;
            m.querySelector('#oVerify').disabled = !active;
            m.querySelector('#oSendInfo').textContent = 'Sent · ' + v.sends_remaining_24h + ' send(s) left today · expires ' + (active ? SW.fmtDate(active.expires_at) : '');
            SW.toast('Verification sent', 'Delivered via ' + (active ? active.delivery_provider : 'mail provider') + '. The code is not displayed here.', 'ok');
            if (done) done();
          }, function (e) { b.disabled = false; err(e); });
        });
        m.querySelector('#oVerify').addEventListener('click', function () {
          var code = m.querySelector('#oCode').value.trim(), b = this;
          if (!code) { err({ message: 'Enter the code.' }); return; }
          fe.hidden = true; b.disabled = true;
          api.post(EI + '/records/' + rec.id + '/ownership/verify', { code: code }).then(function (v) {
            b.disabled = false;
            if (v.status === 'verified') { SW.closeModal(); SW.toast('Ownership verified', rec.email + ' — mailbox control confirmed', 'ok'); if (done) done(); }
            else {
              var left = v.active_challenge ? v.active_challenge.attempts_remaining : 0;
              err({ message: v.status === 'locked' ? 'Too many incorrect attempts — the challenge is locked. Start a new verification later.' : 'Incorrect code. ' + left + ' attempt(s) remaining.' });
              if (done) done();
            }
          }, function (e) { b.disabled = false; err(e); });
        });
      }
    });
  }

  function dkimModal(recordId, done) {
    SW.modal({
      title: 'Verify DKIM signatures on a real message',
      body: '<div class="stack"><div class="form-error" role="alert" hidden></div>' +
        '<p class="muted">Upload an <span class="mono">.eml</span> file or paste the raw message <b>with full headers</b>. Sentrix verifies each <span class="mono">DKIM-Signature</span> cryptographically against the public key in DNS. ' +
        'The body is discarded; only a SHA-256 fingerprint and header summary are kept.</p>' +
        '<label class="fl">Message file (.eml, max 2 MB)<input type="file" id="dFile" accept=".eml,message/rfc822,text/plain"></label>' +
        '<label class="fl">…or paste raw message<textarea id="dRaw" rows="7" class="mono" spellcheck="false" placeholder="DKIM-Signature: v=1; a=rsa-sha256; d=…&#10;From: …&#10;Subject: …&#10;&#10;body"></textarea></label>' +
        '<div id="dOut"></div></div>',
      footer: '<button class="btn btn-ghost" data-close>Close</button><button class="btn btn-primary" id="dGo">Verify signatures</button>',
      onMount: function (m) {
        m.querySelector('#dGo').addEventListener('click', function () {
          var b = this, fe = m.querySelector('.form-error'), fd = new FormData();
          var f = m.querySelector('#dFile').files[0], raw = m.querySelector('#dRaw').value;
          if (!f && !raw.trim()) { fe.hidden = false; fe.textContent = 'Choose a file or paste the raw message.'; return; }
          if (f) fd.append('file', f); else fd.append('raw', raw);
          if (recordId) fd.append('record_id', recordId);
          fe.hidden = true; b.disabled = true; b.innerHTML = '<span class="spinner"></span>Verifying…';
          api.post(EI + '/dkim/verify', fd).then(function (r) {
            b.disabled = false; b.textContent = 'Verify signatures';
            m.querySelector('#dOut').innerHTML = dkimResultHTML(r);
            if (done) done(r);
          }, function (e) { b.disabled = false; b.textContent = 'Verify signatures'; fe.hidden = false; fe.textContent = e.message; });
        });
      }
    });
  }
  function dkimResultHTML(r) {
    return '<div class="card inset"><div class="card-head"><h3>Result</h3>' + X.st(r.status === 'signature_pass' ? 'pass' : r.status === 'signature_fail' ? 'fail' : r.status, label(r.status)) + '</div>' +
      '<p>' + SW.esc(r.explanation) + '</p>' +
      '<dl class="kv" style="margin-top:10px"><dt>From</dt><dd>' + SW.esc(r.from_address || '—') + '</dd><dt>Fingerprint</dt><dd>' + SW.esc((r.message_sha256 || '').slice(0, 32)) + '…</dd></dl>' +
      (r.signatures && r.signatures.length ? '<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th>#</th><th>d=</th><th>s=</th><th>Algorithm</th><th>Verified</th><th>Aligned with From</th><th>Error</th></tr></thead><tbody>' +
        r.signatures.map(function (s) {
          return '<tr><td class="mono">' + s.index + '</td><td class="mono">' + SW.esc(s.domain) + '</td><td class="mono">' + SW.esc(s.selector) + '</td><td class="mono">' + SW.esc(s.algorithm) + '</td>' +
            '<td>' + X.st(s.verified ? 'pass' : 'fail', s.verified ? 'verified' : 'failed') + '</td><td>' + X.st(s.aligned_with_from ? 'pass' : 'warn', s.aligned_with_from ? 'aligned' : 'not aligned') + '</td>' +
            '<td class="faint">' + SW.esc(s.error || '') + '</td></tr>';
        }).join('') + '</tbody></table></div>' : '') +
      (r.receiver_claims && r.receiver_claims.length ? '<div class="eyebrow" style="margin-top:12px">Authentication-Results (receiver claims, not re-verified)</div><div class="pre">' + SW.esc(r.receiver_claims.join('\n')) + '</div>' : '') +
      '<p class="faint" style="margin-top:8px">' + SW.esc(r.note || '') + '</p></div>';
  }

  /* ================= Email Verification dashboard ================= */
  var FILTERS = [['', 'All'], ['verified', 'Verified'], ['unverified', 'Unverified'], ['invalid', 'Invalid'], ['suspicious', 'Suspicious'], ['pending', 'Pending']];
  SW.route('email-verification', { title: 'Email Verification', render: function (host) {
    var body = page(host, 'email-verification', 'Email Verification',
      'Technical validity, domain authentication and mailbox ownership — each assessed and shown separately',
      gateBtn('<button class="btn btn-primary" id="newCheck">' + SW.icon('plus', 15) + 'New check</button>') +
      '<button class="btn btn-ghost" id="sumPdf">' + SW.icon('download', 15) + 'Summary PDF</button>');
    var alive = guard(host);
    var f = { filter: SW.hashQuery.filter || '', q: '' };
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      body.innerHTML = '<div class="grid g5 mb" id="kpis"></div>' + distinction() +
        '<div class="card"><div class="filters">' +
          '<div class="chip-group" role="tablist" aria-label="Filter records">' + FILTERS.map(function (x) {
            return '<button class="fchip' + (f.filter === x[0] ? ' on' : '') + '" data-f="' + x[0] + '" role="tab" aria-selected="' + (f.filter === x[0]) + '">' + x[1] + '<span class="n" data-n="' + (x[0] || 'total') + '"></span></button>'; }).join('') + '</div>' +
          '<div class="searchbox" style="flex:1 1 220px">' + SW.icon('search', 16) + '<input id="rq" type="search" placeholder="Search email or domain…" aria-label="Search records"></div>' +
        '</div>' +
        '<div class="table-wrap"><table class="ei-table"><thead><tr><th>Email address</th><th>Domain</th><th>Syntax</th><th>DNS</th><th>MX</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Disposable</th><th>Ownership</th><th>Risk</th><th>Investigation findings</th><th>Last checked</th></tr></thead>' +
        '<tbody id="rBody"><tr><td colspan="13"><div class="loading-row"><span class="spinner"></span>Loading…</div></td></tr></tbody></table></div>' +
        '<div class="faint" id="rFoot" style="margin-top:10px"></div></div>';
      function drawStats() {
        api.get(EI + '/stats').then(function (s) {
          if (!alive()) return;
          host.querySelector('#kpis').innerHTML =
            kpi('Records', s.total, plural(s.domains, 'domain') + ' analysed') +
            kpi('Ownership verified', s.verified, 'mailbox control proven', 'k-good') +
            kpi('Pending verification', s.pending, 'challenge sent, awaiting code') +
            kpi('Technically invalid', s.invalid, 'syntax, DNS or MX failure', 'k-bad') +
            kpi('Suspicious indicators', s.suspicious, 'avg risk ' + s.avg_risk + ' · ' + plural(s.linked_cases, 'linked case'), 'k-warn');
          ['total', 'verified', 'unverified', 'invalid', 'suspicious', 'pending'].forEach(function (k) {
            var el = host.querySelector('[data-n="' + k + '"]'); if (el) el.textContent = s[k];
          });
        });
      }
      var tmr;
      function draw() {
        var qs = '?limit=200' + (f.filter ? '&filter=' + f.filter : '') + (f.q ? '&q=' + encodeURIComponent(f.q) : '');
        api.get(EI + '/records' + qs).then(function (r) {
          if (!alive()) return;
          var tb = host.querySelector('#rBody');
          tb.innerHTML = r.items.length ? r.items.map(function (x) {
            return '<tr class="clickable" data-id="' + x.id + '"><td class="strong mono"><a class="linkish" href="#/email-record/' + x.id + '">' + SW.esc(x.email) + '</a>' +
              (x.incident_id ? ' <span class="tag-demo" title="Linked to a case">case</span>' : '') + '</td>' +
              '<td class="mono">' + SW.esc(x.domain || '—') + '</td>' +
              '<td>' + X.st(x.syntax_status) + '</td><td>' + X.st(x.dns_status) + '</td><td>' + X.st(x.mx_status) + '</td>' +
              '<td>' + X.st(x.spf_status) + '</td><td>' + X.st(x.dkim_status, x.dkim_status === 'selector_found' ? 'key found' : null) + '</td><td>' + X.st(x.dmarc_status) + '</td>' +
              '<td>' + X.st(x.disposable_status, x.disposable_status === 'not_disposable' ? 'no' : x.disposable_status === 'disposable' ? 'yes' : null) + '</td>' +
              '<td>' + X.st(x.ownership_status) + '</td>' +
              '<td>' + riskCell(x.risk_score, x.risk_band) + (x.risk_confidence != null ? '<div class="faint">conf. ' + x.risk_confidence + '%</div>' : '') + '</td>' +
              '<td class="findings-cell">' + (x.top_findings.length ? SW.esc(x.top_findings.slice(0, 2).join(' · ')) + (x.findings_count > 2 ? ' <span class="faint">+' + (x.findings_count - 2) + '</span>' : '') : '<span class="faint">No findings</span>') + '</td>' +
              '<td class="mono">' + when(x.last_checked_at) + '</td></tr>';
          }).join('') : '<tr><td colspan="13">' + SW.emptyState(f.filter || f.q ? 'No matching records' : 'No email checks yet',
            f.filter || f.q ? 'Try another filter or search term.' : 'Run your first check with “New check”. Sentrix will query DNS for the domain\u2019s MX, SPF, DKIM and DMARC records.') + '</td></tr>';
          host.querySelector('#rFoot').textContent = 'Showing ' + r.items.length + ' of ' + r.total + ' record(s) · data from ' + api.state.base;
        }, function (e) { if (alive()) failInto(body, e); });
      }
      host.querySelectorAll('.fchip').forEach(function (b) {
        b.addEventListener('click', function () {
          f.filter = b.dataset.f;
          host.querySelectorAll('.fchip').forEach(function (x) { x.classList.toggle('on', x === b); x.setAttribute('aria-selected', String(x === b)); });
          draw();
        });
      });
      host.querySelector('#rq').addEventListener('input', function () { var v = this.value.trim(); clearTimeout(tmr); tmr = setTimeout(function () { f.q = v; draw(); }, 250); });
      host.querySelector('#rBody').addEventListener('click', function (e) {
        var tr = e.target.closest('tr[data-id]'); if (tr && !e.target.closest('a')) SW.go('email-record/' + tr.dataset.id);
      });
      drawStats(); draw();
      X.refreshDashboard = function () { drawStats(); draw(); };
    });
    var nb = host.querySelector('#newCheck');
    if (nb) nb.addEventListener('click', function () { newCheckModal('', function () { if (X.refreshDashboard) X.refreshDashboard(); }); });
    host.querySelector('#sumPdf').addEventListener('click', function () {
      api.download(EI + '/report/summary.pdf', 'sentrix-email-identity-summary.pdf').then(function (n) { SW.toast('Report downloaded', n + ' · stored in Reports', 'ok'); }, function (e) { SW.toast('Report failed', e.message); });
    });
  } });

  /* ================= Record detail ================= */
  SW.route('email-record', { title: 'Email record', render: function (host, id) {
    var body = page(host, 'email-verification', 'Email record', 'Evidence-linked results for a single address', '<a class="btn btn-ghost" href="#/email-verification">← All records</a>');
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      load();
    });
    function load() {
      Promise.all([api.get(EI + '/records/' + id), api.get(EI + '/records/' + id + '/ownership')]).then(function (res) {
        if (alive()) draw(res[0], res[1]);
      }, function (e) { if (alive()) failInto(body, e); });
    }
    function draw(r, ov) {
      document.title = r.email + ' · Sentrix';
      host.querySelector('.page-head h1').textContent = r.email;
      host.querySelector('.page-head p').innerHTML = 'Purpose: ' + SW.esc(r.purpose) + ' · checked ' + plural(r.check_count, 'time') + ' · last ' + SW.esc(SW.fmtDate(r.last_checked_at));
      var da = r.domain_analysis || {};
      var risk = r.risk || {};
      var suspicious = (r.classifications || []).indexOf('suspicious') >= 0 || (r.risk_score || 0) >= 45;
      body.innerHTML =
        '<div class="card mb actions-bar">' +
          gateBtn('<button class="btn btn-sm" data-a="recheck">' + SW.icon('refresh', 14) + 'Re-run checks</button>') +
          gateBtn('<button class="btn btn-sm" data-a="own"' + (!deliverable(r) && r.ownership_status !== 'verified' ? ' disabled title="The address cannot receive mail, so a verification message cannot be delivered."' : '') + '>' + SW.icon('badgecheck', 14) + (r.ownership_status === 'verified' ? 'Ownership verified' : 'Verify ownership') + '</button>') +
          gateBtn('<button class="btn btn-sm" data-a="dkim">' + SW.icon('key', 14) + 'Verify a message (DKIM)</button>') +
          '<a class="btn btn-sm" href="#/assistant?record=' + r.id + '">' + SW.icon('ai', 14) + 'Ask Sentrix AI</a>' +
          gateBtn('<button class="btn btn-sm" data-a="kb">' + SW.icon('kb', 14) + 'Add to knowledge base</button>') +
          '<button class="btn btn-sm" data-a="pdf">' + SW.icon('download', 14) + 'PDF report</button>' +
          (r.incident_id ? '<a class="btn btn-sm" href="#/incidents">Linked case open</a>' :
            gateBtn('<button class="btn btn-sm ' + (suspicious ? 'btn-danger' : '') + '" data-a="case">' + SW.icon('incident', 14) + 'Create incident / case</button>')) +
        '</div>' +
        '<div class="grid g-2-1 mb">' +
          '<div class="card"><div class="card-head"><div><h3>Validity layers</h3><div class="faint">Each layer is a separate claim — passing one does not imply the next</div></div></div>' +
            '<ol class="ladder">' + (r.layers || []).map(function (l) {
              return '<li class="lad lad-' + SW.esc(l.state) + '"><span class="lad-dot" aria-hidden="true"></span><div><b>' + SW.esc(l.label) + '</b> ' + X.st(l.state, l.state === 'not_assessed' ? 'not assessed' : l.state) +
                '<div class="faint">' + SW.esc(l.meaning) + '</div><div class="mono lad-detail">' + SW.esc(l.detail) + '</div></div></li>';
            }).join('') + '</ol></div>' +
          '<div class="card"><div class="card-head"><h3>Risk assessment</h3>' + riskCell(r.risk_score, r.risk_band) + '</div>' +
            '<div class="bar" style="height:9px"><i class="' + (r.risk_score >= 70 ? 'crit' : r.risk_score >= 45 ? 'warn' : '') + '" style="width:' + (r.risk_score || 0) + '%"></i></div>' +
            '<div class="confidence"><div class="faint" style="margin:8px 0 6px">Confidence ' + (risk.confidence != null ? risk.confidence : '—') + '%</div><div class="conf-bar"><i style="width:' + (risk.confidence || 0) + '%"></i></div></div>' +
            '<p style="margin-top:12px">' + SW.esc(risk.summary || '') + '</p>' +
            '<p class="faint" style="margin-top:10px">' + SW.esc(risk.disclaimer || '') + '</p>' +
            '<dl class="kv" style="margin-top:12px"><dt>Engine</dt><dd>' + SW.esc(risk.engine_version || '—') + '</dd><dt>Ownership</dt><dd>' + SW.esc(label(r.ownership_status)) + (r.ownership_verified_at ? ' · ' + SW.esc(SW.fmtDate(r.ownership_verified_at)) : '') + '</dd>' +
            '<dt>Role mailbox</dt><dd>' + (r.is_role_account ? 'yes (shared address)' : 'no') + '</dd></dl></div>' +
        '</div>' +
        '<div class="card"><div class="tabs" role="tablist" id="rTabs">' +
          '<button class="tab active" role="tab" data-target="tFind">Findings (' + (risk.findings || []).length + ')</button>' +
          '<button class="tab" role="tab" data-target="tDns">DNS &amp; authentication</button>' +
          '<button class="tab" role="tab" data-target="tDom">Domain intelligence</button>' +
          '<button class="tab" role="tab" data-target="tOwn">Ownership</button>' +
          '<button class="tab" role="tab" data-target="tAudit">Audit trail</button></div>' +
        '<div id="rPanels">' +
          '<div class="tab-panel active" id="tFind">' + findingsHTML(risk.findings || []) + '</div>' +
          '<div class="tab-panel" id="tDns">' + dnsHTML(da) + '</div>' +
          '<div class="tab-panel" id="tDom">' + domainIntelHTML(da) + '</div>' +
          '<div class="tab-panel" id="tOwn">' + ownershipHTML(r, ov) + '</div>' +
          '<div class="tab-panel" id="tAudit"><div class="loading-row"><span class="spinner"></span>Loading audit trail…</div></div>' +
        '</div></div>';
      SW.wireTabs(body.querySelector('#rTabs'), body.querySelector('#rPanels'));
      api.get(EI + '/records/' + r.id + '/audit').then(function (a) { if (alive()) body.querySelector('#tAudit').innerHTML = auditHTML(a.items, false); });
      body.querySelector('.actions-bar').addEventListener('click', function (e) {
        var b = e.target.closest('button[data-a]'); if (!b || b.disabled) return;
        var a = b.dataset.a;
        if (a === 'recheck') {
          b.disabled = true; b.innerHTML = '<span class="spinner"></span>Re-checking…';
          api.post(EI + '/records/' + r.id + '/recheck').then(function () { SW.toast('Checks re-run', 'Fresh DNS lookups recorded', 'ok'); load(); }, function (er) { SW.toast('Re-check failed', er.message); load(); });
        } else if (a === 'own') ownershipModal(r, ov, load);
        else if (a === 'dkim') dkimModal(r.id, load);
        else if (a === 'case') caseModal(r, load);
        else if (a === 'kb') api.post(EI + '/records/' + r.id + '/knowledge').then(function (d) { SW.toast('Indexed into knowledge base', d.title + ' · ' + d.chunks + ' chunk(s)', 'ok'); }, function (er) { SW.toast('Indexing failed', er.message); });
        else if (a === 'pdf') api.download(EI + '/records/' + r.id + '/report.pdf').then(function (n) { SW.toast('Report downloaded', n, 'ok'); }, function (er) { SW.toast('Report failed', er.message); });
      });
      var ob = body.querySelector('[data-own-open]');
      if (ob) ob.addEventListener('click', function () { ownershipModal(r, ov, load); });
    }
  } });

  function findingsHTML(list) {
    if (!list.length) return SW.emptyState('No findings', 'No risk indicators were found for this address. That does not establish anything about the person who uses it.');
    return '<ul class="findings">' + list.map(function (f) {
      return '<li class="finding sev-' + SW.esc(f.severity) + '"><div class="f-head"><b>' + SW.esc(f.title) + '</b>' + X.st(f.severity) +
        '<span class="faint">' + SW.esc(label(f.category)) + ' · layer: ' + SW.esc(label(f.layer)) + ' · impact +' + f.impact + ' · confidence ' + f.confidence + '%</span></div>' +
        '<div class="f-evidence"><span class="eyebrow">Evidence</span> <span class="mono">' + SW.esc(f.evidence) + '</span></div>' +
        (f.recommendation ? '<div class="f-rec">' + SW.icon('arrow', 13) + SW.esc(f.recommendation) + '</div>' : '') + '</li>';
    }).join('') + '</ul>';
  }
  function mechBlock(name, a) {
    if (!a || !a.status) return '<div class="mech"><div class="mech-head"><b>' + name + '</b>' + X.st('not_checked') + '</div></div>';
    return '<div class="mech"><div class="mech-head"><b>' + name + '</b>' + X.st(a.status, a.status === 'selector_found' ? 'key found' : null) + '<span class="faint mono">' + SW.esc(a.query_name || '') + '</span></div>' +
      '<p>' + SW.esc(a.explanation || '') + '</p>' +
      (a.raw_records && a.raw_records.length ? '<div class="pre">' + SW.esc(a.raw_records.join('\n')) + '</div>' : '<div class="faint">No record returned.</div>') +
      ((a.issues || []).length ? '<ul class="issues">' + a.issues.map(function (i) { return '<li>' + X.st(issueSev(i)) + ' ' + SW.esc(issueText(i)) + '</li>'; }).join('') + '</ul>' : '') +
      '<div class="faint">Checked ' + (a.checked_at ? SW.esc(SW.fmtDate(a.checked_at)) : '—') + '</div></div>';
  }
  function dnsHTML(da) {
    if (!da || !da.domain) return SW.emptyState('No DNS analysis', 'The address failed syntax validation, so no DNS lookups were made.');
    var sel = da.dkim_selectors || [], sigs = da.dkim_signature_checks || [];
    return '<div class="note-box mb">' + SW.icon('warn', 16) + '<span><b>DKIM key discovery is not DKIM verification.</b> Finding a public key in DNS only shows the domain can sign mail. To verify that a specific message passed DKIM, use “Verify a message (DKIM)” with the real message and headers.</span></div>' +
      '<div class="mech-grid">' + mechBlock('DNS (A/AAAA)', da.dns) + mechBlock('MX', da.mx) + mechBlock('SPF', da.spf) + mechBlock('DMARC', da.dmarc) + mechBlock('DKIM key discovery', da.dkim) + '</div>' +
      (sel.length ? '<h4 class="sub-h">DKIM selectors probed</h4><div class="table-wrap"><table><thead><tr><th>Selector</th><th>Status</th><th>Key</th><th>Issues</th></tr></thead><tbody>' + sel.map(function (s) {
        var p = s.parsed || {};
        return '<tr><td class="mono">' + SW.esc(s.selector || '') + '</td><td>' + X.st(s.status, s.status === 'selector_found' ? 'key found' : null) + '</td><td class="mono">' + SW.esc((p.key_type || '') + (p.key_bits ? ' ' + p.key_bits + '-bit' : '') + (p.revoked ? ' · revoked' : '') + (p.testing ? ' · test mode' : '')) + '</td>' +
          '<td class="faint">' + SW.esc((s.issues || []).map(issueText).join(' · ')) + '</td></tr>'; }).join('') + '</tbody></table></div>' : '') +
      (sigs.length ? '<h4 class="sub-h">Message signature verifications</h4><div class="table-wrap"><table><thead><tr><th>When</th><th>Result</th><th>Explanation</th></tr></thead><tbody>' + sigs.map(function (s) {
        return '<tr><td class="mono">' + when(s.checked_at) + '</td><td>' + X.st(s.status) + '</td><td>' + SW.esc(s.explanation) + '</td></tr>'; }).join('') + '</tbody></table></div>' : '') +
      '<p class="faint" style="margin-top:10px">Resolver: ' + SW.esc(da.resolver_used || '—') + ' · cached until ' + (da.expires_at ? SW.esc(SW.fmtDate(da.expires_at)) : '—') + '</p>';
  }
  function domainIntelHTML(da) {
    if (!da || !da.domain) return SW.emptyState('No domain analysis', 'No domain could be extracted from this address.');
    var rep = da.reputation_detail || {};
    return '<div class="grid g2"><div><dl class="kv">' +
      '<dt>Domain</dt><dd>' + SW.esc(da.domain) + (da.is_idn ? ' (internationalised)' : '') + '</dd>' +
      '<dt>A records</dt><dd>' + SW.esc((da.a_records || []).join(', ') || '—') + '</dd>' +
      '<dt>NS</dt><dd>' + SW.esc((da.ns_records || []).join(', ') || '—') + '</dd>' +
      '<dt>MX</dt><dd>' + SW.esc((da.mx_records || []).map(function (m) { return m.preference + ' ' + m.host + (m.resolves ? '' : ' (no address)'); }).join(', ') || '—') + '</dd>' +
      '<dt>Disposable</dt><dd>' + (da.is_disposable ? 'yes — ' + SW.esc(da.disposable_source || 'blocklist') : 'no') + '</dd>' +
      '<dt>Free provider</dt><dd>' + (da.is_free_provider ? 'yes' : 'no') + '</dd>' +
      '<dt>Domain age</dt><dd>' + (da.domain_age_days != null ? da.domain_age_days + ' days (' + SW.esc(da.age_source) + ')' : 'unknown — ' + SW.esc(label(da.age_source))) + '</dd>' +
      '<dt>Reputation</dt><dd>' + SW.esc(label(da.reputation_status)) + '</dd></dl>' +
      '<div class="faint" style="margin-top:10px">' + Object.keys(rep).map(function (k) { return SW.esc(k.toUpperCase()) + ': ' + SW.esc(label(rep[k].status)) + (rep[k].reason ? ' — ' + SW.esc(rep[k].reason) : ''); }).join('<br>') + '</div></div>' +
      '<div><h4 class="sub-h" style="margin-top:0">Suspicious domain indicators</h4>' + ((da.suspicious_indicators || []).length ? '<ul class="issues">' + da.suspicious_indicators.map(function (s) {
        return '<li>' + X.st(s.severity || 'medium') + ' ' + SW.esc(s.message || s.detail || s.code || JSON.stringify(s)) + '</li>'; }).join('') + '</ul>' : '<p class="faint">None found.</p>') +
      '<h4 class="sub-h">Threat intelligence matches</h4>' + ((da.threat_matches || []).length ? '<ul class="issues">' + da.threat_matches.map(function (t) {
        return '<li>' + X.st(t.severity || 'high') + ' <span class="mono">' + SW.esc(t.value || '') + '</span> ' + SW.esc(t.description || '') + ' <span class="faint">(' + SW.esc(t.source || 'intel') + ', confidence ' + (t.confidence != null ? t.confidence + '%' : '—') + ')</span></li>'; }).join('') + '</ul>' : '<p class="faint">No matches in this organisation\u2019s threat intelligence.</p>') +
      '<a class="btn btn-sm btn-ghost" style="margin-top:10px" href="#/email-domain/' + encodeURIComponent(da.domain) + '">Open domain intelligence</a></div></div>';
  }
  function ownershipHTML(r, ov) {
    var a = ov.active_challenge;
    return '<div class="grid g2"><div><dl class="kv"><dt>Status</dt><dd>' + X.st(ov.status) + '</dd>' +
      '<dt>Verified at</dt><dd>' + (ov.verified_at ? SW.esc(SW.fmtDate(ov.verified_at)) : '—') + '</dd>' +
      '<dt>Method</dt><dd>' + SW.esc(ov.method || '—') + '</dd>' +
      '<dt>Active challenge</dt><dd>' + (a ? 'expires ' + SW.esc(SW.fmtDate(a.expires_at)) + ' · ' + a.attempts_remaining + ' attempt(s) left · ' + SW.esc(a.delivery_status) : 'none') + '</dd>' +
      '<dt>Sends (24h)</dt><dd>' + ov.sends_last_24h + ' used · ' + ov.sends_remaining_24h + ' left</dd></dl>' +
      (canWrite() && deliverable(r) && ov.status !== 'verified' ? '<button class="btn btn-primary btn-sm" style="margin-top:12px" data-own-open>' + SW.icon('mail', 14) + (a ? 'Resend or enter code' : 'Start verification') + '</button>' : '') + '</div>' +
      '<div class="note-box">' + SW.icon('shield', 16) + '<span>' + SW.esc(ov.meaning) + ' Technical validity and domain reputation are reported separately and are not affected by ownership status.</span></div></div>';
  }
  function auditHTML(items, withEmail) {
    if (!items.length) return SW.emptyState('No audit entries', 'Actions on email records are logged here.');
    return '<div class="table-wrap"><table><thead><tr><th>When</th>' + (withEmail ? '<th>Email</th>' : '') + '<th>Action</th><th>Outcome</th><th>Actor</th><th>Detail</th></tr></thead><tbody>' + items.map(function (a) {
      return '<tr><td class="mono nowrap">' + SW.esc(SW.fmtDate(a.at)) + '</td>' + (withEmail ? '<td class="mono">' + (a.record_id ? '<a class="linkish" href="#/email-record/' + a.record_id + '">' + SW.esc(a.email || a.record_id) + '</a>' : '—') + '</td>' : '') +
        '<td class="mono">' + SW.esc(a.action) + '</td><td>' + X.st(a.outcome) + '</td><td class="faint">' + SW.esc(a.actor_type) + '</td>' +
        '<td class="faint mono trunc" style="max-width:380px" title="' + SW.esc(JSON.stringify(a.detail)) + '">' + SW.esc(Object.keys(a.detail || {}).map(function (k) { return k + '=' + (typeof a.detail[k] === 'object' ? JSON.stringify(a.detail[k]) : a.detail[k]); }).join(' · ')) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  X.auditHTML = auditHTML;

  /* ================= Domain Intelligence ================= */
  SW.route('email-domain', { title: 'Domain Intelligence', render: function (host, domain) {
    if (domain) return domainDetail(host, decodeURIComponent(domain));
    var body = page(host, 'email-domain', 'Domain Intelligence', 'DNS, mail infrastructure, disposable and reputation indicators per mail domain — plus organisation threat intelligence',
      gateBtn('<button class="btn btn-primary" id="anBtn">' + SW.icon('globe', 15) + 'Analyse a domain</button>'));
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      Promise.all([api.get(EI + '/domains?limit=300'), api.get('/threat-intel/indicators')]).then(function (res) {
        if (!alive()) return;
        var d = res[0].items, ti = res[1].items;
        body.innerHTML = '<div class="card mb"><div class="table-wrap"><table><thead><tr><th>Domain</th><th>DNS</th><th>MX</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Disposable</th><th>Suspicious</th><th>Threat intel</th><th>Addresses</th><th>Analysed</th></tr></thead><tbody>' +
          (d.length ? d.map(function (x) {
            return '<tr class="clickable" data-d="' + SW.esc(x.domain) + '"><td class="strong mono"><a class="linkish" href="#/email-domain/' + encodeURIComponent(x.domain) + '">' + SW.esc(x.domain) + '</a>' + (x.is_free_provider ? ' <span class="tag-demo">free provider</span>' : '') + '</td>' +
              '<td>' + X.st(x.dns_status) + '</td><td>' + X.st(x.mx_status) + '</td><td>' + X.st(x.spf_status) + '</td><td>' + X.st(x.dkim_status, x.dkim_status === 'selector_found' ? 'key found' : null) + '</td><td>' + X.st(x.dmarc_status) + '</td>' +
              '<td>' + X.st(x.is_disposable ? 'disposable' : 'not_disposable', x.is_disposable ? 'yes' : 'no') + '</td>' +
              '<td>' + (x.suspicious_count ? X.st('suspicious', String(x.suspicious_count)) : '<span class="faint">0</span>') + '</td>' +
              '<td>' + (x.threat_match_count ? X.st('high', x.threat_match_count + ' match') : '<span class="faint">0</span>') + '</td>' +
              '<td class="mono">' + x.address_count + '</td><td class="mono">' + when(x.analyzed_at) + '</td></tr>'; }).join('')
            : '<tr><td colspan="11">' + SW.emptyState('No domains analysed', 'Domains appear here after an email check or a direct domain analysis.') + '</td></tr>') +
          '</tbody></table></div></div>' +
          '<div class="card"><div class="card-head"><div><h3>Threat intelligence indicators</h3><div class="faint">Organisation-scoped domains and addresses matched during every check</div></div>' +
            gateBtn('<button class="btn btn-sm" id="tiAdd">' + SW.icon('plus', 14) + 'Add indicator</button>') + '</div>' +
          '<div class="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Source</th><th>Description</th><th></th></tr></thead><tbody id="tiBody">' +
          (ti.length ? ti.map(function (t) {
            return '<tr><td class="mono">' + SW.esc(t.indicator_type) + '</td><td class="mono strong">' + SW.esc(t.value) + '</td><td>' + X.st(t.severity) + '</td><td class="mono">' + t.confidence + '%</td><td class="faint">' + SW.esc(t.source) + '</td><td>' + SW.esc(t.description || '') + '</td>' +
              '<td>' + gateBtn('<button class="btn btn-sm btn-ghost" data-del="' + t.id + '" aria-label="Remove indicator">' + SW.icon('x', 13) + '</button>') + '</td></tr>'; }).join('')
            : '<tr><td colspan="7">' + SW.emptyState('No indicators', 'Add known-bad domains or addresses to flag them in email checks.') + '</td></tr>') +
          '</tbody></table></div></div>';
        body.querySelector('tbody').addEventListener('click', function (e) {
          var tr = e.target.closest('tr[data-d]'); if (tr && !e.target.closest('a')) SW.go('email-domain/' + encodeURIComponent(tr.dataset.d));
        });
        var add = body.querySelector('#tiAdd');
        if (add) add.addEventListener('click', tiModal);
        body.querySelector('#tiBody').addEventListener('click', function (e) {
          var b = e.target.closest('[data-del]'); if (!b) return;
          api.del('/threat-intel/indicators/' + b.dataset.del).then(function () { SW.toast('Indicator removed', ''); SW.render(); }, function (er) { SW.toast('Remove failed', er.message); });
        });
      }, function (e) { if (alive()) failInto(body, e); });
    });
    var ab = host.querySelector('#anBtn');
    if (ab) ab.addEventListener('click', function () {
      SW.modal({ title: 'Analyse a mail domain', body: '<div class="stack"><div class="form-error" role="alert" hidden></div><label class="fl">Domain<input id="adDom" placeholder="example.com" spellcheck="false"></label>' +
        '<label class="fl">DKIM selectors (optional)<input id="adSel" placeholder="s1, mail" spellcheck="false"></label><p class="faint">Performs DNS lookups only (A/AAAA, MX, SPF, DMARC, DKIM key discovery).</p></div>',
        footer: '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-primary" id="adGo">Analyse</button>',
        onMount: function (m) {
          m.querySelector('#adGo').addEventListener('click', function () {
            var b = this, d = m.querySelector('#adDom').value.trim();
            if (!d) return;
            b.disabled = true; b.innerHTML = '<span class="spinner"></span>Querying DNS…';
            api.post(EI + '/domains/analyze', { domain: d, dkim_selectors: m.querySelector('#adSel').value.split(/[\s,]+/).filter(Boolean) }).then(function (r) {
              SW.closeModal(); SW.go('email-domain/' + encodeURIComponent(r.domain));
            }, function (er) { b.disabled = false; b.textContent = 'Analyse'; var fe = m.querySelector('.form-error'); fe.hidden = false; fe.textContent = er.message; });
          });
        } });
    });
  } });
  function tiModal() {
    SW.modal({ title: 'Add threat intelligence indicator', body: '<div class="stack"><div class="form-error" role="alert" hidden></div>' +
      '<label class="fl">Type<select id="tType"><option value="domain">domain</option><option value="email">email</option></select></label>' +
      '<label class="fl">Value<input id="tVal" spellcheck="false" placeholder="phish-example.test"></label>' +
      '<label class="fl">Severity<select id="tSev"><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select></label>' +
      '<label class="fl">Confidence (%)<input id="tConf" type="number" min="0" max="100" value="70"></label>' +
      '<label class="fl">Source<select id="tSrc"><option value="analyst">analyst</option><option value="abuse_report">abuse report</option><option value="feed">feed</option></select></label>' +
      '<label class="fl">Description<input id="tDesc" maxlength="500" placeholder="Where this indicator came from"></label></div>',
      footer: '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-primary" id="tGo">Add</button>',
      onMount: function (m) {
        m.querySelector('#tGo').addEventListener('click', function () {
          var q = function (s) { return m.querySelector(s).value.trim(); };
          api.post('/threat-intel/indicators', { indicator_type: q('#tType'), value: q('#tVal'), severity: q('#tSev'), confidence: parseInt(q('#tConf'), 10) || 50, source: q('#tSrc') || 'analyst', description: q('#tDesc') })
            .then(function () { SW.closeModal(); SW.toast('Indicator added', 'Applies to future checks and re-checks', 'ok'); SW.render(); },
              function (er) { var fe = m.querySelector('.form-error'); fe.hidden = false; fe.textContent = er.message; });
        });
      } });
  }
  function domainDetail(host, domain) {
    var body = page(host, 'email-domain', domain, 'Domain intelligence', '<a class="btn btn-ghost" href="#/email-domain">← All domains</a>' +
      gateBtn('<button class="btn btn-primary" id="reAn">' + SW.icon('refresh', 15) + 'Re-analyse</button>'));
    document.title = domain + ' · Sentrix';
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      api.get(EI + '/domains/' + encodeURIComponent(domain)).then(function (d) {
        if (!alive()) return;
        var recs = d.addresses || [];
        body.innerHTML = '<div class="card mb">' + domainIntelHTML(d) + '</div><div class="card mb"><div class="card-head"><h3>DNS &amp; authentication</h3></div>' + dnsHTML(d) + '</div>' +
          '<div class="card"><div class="card-head"><h3>Addresses at this domain</h3></div>' + (recs.length ? '<ul class="list-clean">' + recs.map(function (x) {
            return '<li><a class="linkish mono" href="#/email-record/' + x.id + '">' + SW.esc(x.email) + '</a> ' + X.st(x.ownership_status) + ' ' + riskCell(x.risk_score, x.risk_band) + '</li>'; }).join('') + '</ul>' : '<p class="faint">No email records reference this domain yet.</p>') + '</div>';
      }, function (e) { if (alive()) failInto(body, e); });
    });
    var rb = host.querySelector('#reAn');
    if (rb) rb.addEventListener('click', function () {
      rb.disabled = true;
      api.post(EI + '/domains/analyze', { domain: domain }).then(function () { SW.toast('Domain re-analysed', domain, 'ok'); SW.render(); }, function (e) { rb.disabled = false; SW.toast('Analysis failed', e.message); });
    });
  }

  /* ================= Email Authentication ================= */
  SW.route('email-auth', { title: 'Email Authentication', render: function (host) {
    var body = page(host, 'email-auth', 'Email Authentication', 'SPF, DKIM and DMARC DNS records and cryptographic DKIM verification of real messages',
      gateBtn('<button class="btn btn-primary" id="dkBtn">' + SW.icon('key', 15) + 'Verify a message (DKIM)</button>'));
    var alive = guard(host), mech = '';
    var EXPL = [
      ['SPF', 'Sender Policy Framework (RFC 7208). A TXT record listing which servers may send mail for the domain. Ends in an "all" policy (-all hard fail, ~all soft fail). Limited to 10 DNS lookups.'],
      ['DKIM', 'DomainKeys Identified Mail (RFC 6376). The sending server signs messages; receivers fetch the public key at <selector>._domainkey.<domain>. Key discovery shows signing capability only — verification needs the actual message.'],
      ['DMARC', 'RFC 7489. A policy at _dmarc.<domain> telling receivers what to do when SPF/DKIM fail or are not aligned with the visible From domain: none (monitor), quarantine or reject.']
    ];
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      body.innerHTML = '<div class="grid g3 mb">' + EXPL.map(function (e) { return '<div class="card"><div class="card-head"><h3>' + e[0] + '</h3></div><p class="muted">' + SW.esc(e[1]) + '</p></div>'; }).join('') + '</div>' +
        '<div class="card"><div class="filters"><div class="chip-group">' + [['', 'All'], ['spf', 'SPF'], ['dkim', 'DKIM keys'], ['dkim_signature', 'DKIM signatures'], ['dmarc', 'DMARC'], ['mx', 'MX']].map(function (x) {
          return '<button class="fchip' + (x[0] === mech ? ' on' : '') + '" data-m="' + x[0] + '">' + x[1] + '</button>'; }).join('') + '</div></div>' +
        '<div class="table-wrap"><table><thead><tr><th>Domain</th><th>Mechanism</th><th>Status</th><th>Query</th><th>Raw record</th><th>Issues</th><th>Checked</th></tr></thead><tbody id="aBody"></tbody></table></div></div>';
      function draw() {
        api.get(EI + '/auth-results?limit=300' + (mech ? '&mechanism=' + mech : '')).then(function (r) {
          if (!alive()) return;
          body.querySelector('#aBody').innerHTML = r.items.length ? r.items.map(function (a) {
            return '<tr><td class="mono strong"><a class="linkish" href="#/email-domain/' + encodeURIComponent(a.domain || '') + '">' + SW.esc(a.domain || '—') + '</a></td><td class="mono">' + SW.esc(a.mechanism) + '</td>' +
              '<td>' + X.st(a.status, a.status === 'selector_found' ? 'key found' : null) + '</td><td class="mono faint">' + SW.esc(a.query_name || '') + '</td>' +
              '<td class="mono trunc" style="max-width:300px" title="' + SW.esc((a.raw_records || []).join('\n')) + '">' + SW.esc((a.raw_records || []).join(' | ') || '—') + '</td>' +
              '<td class="faint">' + SW.esc((a.issues || []).map(issueText).join(' · ') || '—') + '</td><td class="mono">' + when(a.checked_at) + '</td></tr>';
          }).join('') : '<tr><td colspan="7">' + SW.emptyState('No results', 'Authentication lookups appear after email or domain checks.') + '</td></tr>';
        }, function (e) { if (alive()) failInto(body, e); });
      }
      body.querySelectorAll('.fchip').forEach(function (b) { b.addEventListener('click', function () {
        mech = b.dataset.m; body.querySelectorAll('.fchip').forEach(function (x) { x.classList.toggle('on', x === b); }); draw(); }); });
      draw();
    });
    var dk = host.querySelector('#dkBtn');
    if (dk) dk.addEventListener('click', function () { dkimModal(null, function () { SW.render(); }); });
  } });

  /* ================= Ownership Verification ================= */
  SW.route('email-ownership', { title: 'Ownership Verification', render: function (host) {
    var body = page(host, 'email-ownership', 'Ownership Verification', 'Consent-based one-time code / link verification of mailbox control');
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      api.get(EI + '/ownership').then(function (r) {
        if (!alive()) return;
        var s = r.settings, items = r.items;
        var cnt = function (st) { return items.filter(function (i) { return i.ownership.status === st; }).length; };
        body.innerHTML = '<div class="grid g4 mb">' + kpi('Verified', cnt('verified'), 'mailbox control proven', 'k-good') + kpi('Pending', cnt('pending'), 'awaiting code or link') +
            kpi('Locked / failed', cnt('locked') + cnt('failed'), 'too many wrong attempts', 'k-bad') + kpi('Unverified', cnt('unverified') + cnt('expired'), 'never verified or expired') + '</div>' +
          '<div class="grid g-2-1 mb"><div class="card"><div class="card-head"><h3>How ownership verification works</h3></div><ol class="steps-list">' +
            '<li>An analyst starts verification for a record and confirms they are authorised to contact the address.</li>' +
            '<li>The backend generates a cryptographically random link token and 6-digit code; only their hashes are stored.</li>' +
            '<li>A Sentrix-branded message is sent through the configured provider (' + SW.esc(s.provider) + ').</li>' +
            '<li>The recipient clicks the link or reads the code back. Expired, reused or wrong tokens are rejected; attempts are limited.</li>' +
            '<li>Status, method and timestamp are recorded, every step is written to the audit trail, and risk is recomputed.</li></ol>' +
            '<p class="faint" style="margin-top:10px">Verified ownership shows control of the mailbox. It is not real-world identity verification.</p></div>' +
          '<div class="card"><div class="card-head"><h3>Policy</h3></div><dl class="kv"><dt>Token lifetime</dt><dd>' + s.ttl_minutes + ' minutes</dd><dt>Max attempts</dt><dd>' + s.max_attempts + ' per challenge</dd>' +
            '<dt>Max sends</dt><dd>' + s.max_sends_per_day + ' per address / 24h</dd><dt>Resend cooldown</dt><dd>' + s.resend_cooldown_seconds + ' s</dd><dt>Delivery</dt><dd>' + SW.esc(s.provider) + '</dd></dl>' +
            (s.provider === 'dev_outbox' ? '<p class="faint" style="margin-top:10px">Development mode: messages are written to <span class="mono">outbox/</span> instead of being sent. Configure SMTP or SendGrid in <span class="mono">.env</span> for real delivery.</p>' : '') + '</div></div>' +
          '<div class="card"><div class="table-wrap"><table><thead><tr><th>Email</th><th>Status</th><th>Method</th><th>Verified at</th><th>Active challenge</th><th>Sends left (24h)</th><th></th></tr></thead><tbody id="oBody">' +
          (items.length ? items.map(function (i, n) {
            var o = i.ownership, a = o.active_challenge;
            return '<tr><td class="mono strong"><a class="linkish" href="#/email-record/' + i.record.id + '">' + SW.esc(i.record.email) + '</a></td><td>' + X.st(o.status) + '</td><td class="mono">' + SW.esc(o.method || '—') + '</td>' +
              '<td class="mono">' + (o.verified_at ? SW.esc(SW.fmtDate(o.verified_at)) : '—') + '</td>' +
              '<td class="faint">' + (a ? 'expires ' + SW.ago(a.expires_at).replace(' ago', '') + ' · ' + a.attempts_remaining + ' attempts · ' + SW.esc(a.delivery_status) : '—') + '</td>' +
              '<td class="mono">' + o.sends_remaining_24h + '</td><td>' + (deliverable(i.record) && o.status !== 'verified' ? gateBtn('<button class="btn btn-sm" data-n="' + n + '">' + (a ? 'Enter code' : 'Verify') + '</button>') : '') + '</td></tr>';
          }).join('') : '<tr><td colspan="7">' + SW.emptyState('No records', 'Run an email check first.') + '</td></tr>') + '</tbody></table></div></div>';
        body.querySelector('#oBody').addEventListener('click', function (e) {
          var b = e.target.closest('[data-n]'); if (!b) return;
          var i = items[+b.dataset.n]; ownershipModal(i.record, i.ownership, function () { SW.render(); });
        });
      }, function (e) { if (alive()) failInto(body, e); });
    });
  } });

  /* ================= Email Risk Analysis ================= */
  SW.route('email-risk', { title: 'Email Risk Analysis', render: function (host) {
    var body = page(host, 'email-risk', 'Email Risk Analysis', 'Explainable, evidence-linked risk scoring — indicators about addresses and domains, never verdicts about people');
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      Promise.all([api.get(EI + '/stats'), api.get(EI + '/records?limit=200&sort=risk')]).then(function (res) {
        if (!alive()) return;
        var s = res[0], recs = res[1].items.slice().sort(function (a, b) { return (b.risk_score || 0) - (a.risk_score || 0); });
        var bands = ['low', 'guarded', 'elevated', 'high'];
        var findings = {};
        recs.forEach(function (r) { r.top_findings.forEach(function (t) { findings[t] = (findings[t] || 0) + 1; }); });
        var topF = Object.keys(findings).sort(function (a, b) { return findings[b] - findings[a]; }).slice(0, 10);
        body.innerHTML = '<div class="grid g-2-1 mb"><div class="card"><div class="card-head"><h3>Risk band distribution</h3><span class="faint">average ' + s.avg_risk + ' / 100</span></div><div style="height:220px"><canvas id="bandChart"></canvas></div></div>' +
          '<div class="card"><div class="card-head"><h3>Scoring method</h3></div><ul class="list-clean small">' +
            '<li><b>low</b> 0–19 · <b>guarded</b> 20–44 · <b>elevated</b> 45–69 · <b>high</b> 70–100</li>' +
            '<li>Each finding adds an impact weight and carries its own evidence and confidence.</li>' +
            '<li>Inputs: syntax, DNS/MX, SPF/DKIM/DMARC posture, disposable and free-provider lists, look-alike/homoglyph indicators, threat-intel matches, enrichment (RDAP age, DNSBL) when enabled, ownership status.</li>' +
            '<li>Verified ownership reduces risk; a failed technical check never labels a person as fraudulent.</li></ul></div></div>' +
          '<div class="grid"><div class="card"><div class="card-head"><h3>Highest-risk records</h3></div><div class="table-wrap"><table><thead><tr><th>Email</th><th>Risk</th><th>Confidence</th><th>Ownership</th><th>Main drivers</th></tr></thead><tbody>' +
            (recs.length ? recs.slice(0, 15).map(function (r) {
              return '<tr><td class="mono"><a class="linkish" href="#/email-record/' + r.id + '">' + SW.esc(r.email) + '</a></td><td>' + riskCell(r.risk_score, r.risk_band) + '</td><td class="mono">' + (r.risk_confidence != null ? r.risk_confidence + '%' : '—') + '</td><td>' + X.st(r.ownership_status) + '</td>' +
                '<td class="faint">' + SW.esc(r.top_findings.slice(0, 2).join(' · ') || '—') + '</td></tr>'; }).join('') : '<tr><td colspan="5">' + SW.emptyState('No records', 'Run an email check first.') + '</td></tr>') + '</tbody></table></div></div>' +
          '<div class="card"><div class="card-head"><h3>Most common findings</h3></div>' + (topF.length ? '<ul class="bars-list">' + topF.map(function (t) {
            return '<li><span>' + SW.esc(t) + '</span><div class="bar"><i style="width:' + Math.round(findings[t] / recs.length * 100) + '%"></i></div><span class="mono">' + findings[t] + '</span></li>'; }).join('') + '</ul>' : '<p class="faint">No findings recorded.</p>') + '</div></div>';
        if (window.Chart) {
          var c = new Chart(body.querySelector('#bandChart'), { type: 'bar', data: { labels: bands, datasets: [{ data: bands.map(function (b) { return s.bands[b] || 0; }),
            backgroundColor: ['#34D399', '#22D3EE', '#FBBF24', '#FB7185'], borderRadius: 6, maxBarThickness: 56 }] },
            options: { scales: { x: SW.axis({ grid: { display: false } }), y: SW.axis({ beginAtZero: true, ticks: { precision: 0, color: '#63728A' } }) } } });
          SW.charts.push(c);
        }
      }, function (e) { if (alive()) failInto(body, e); });
    });
  } });

  /* ================= Investigation History ================= */
  SW.route('email-history', { title: 'Investigation History', render: function (host) {
    var body = page(host, 'email-history', 'Investigation History', 'Checks, cases, reports and the verification audit trail for this organisation');
    var alive = guard(host);
    needBackend(host, body).then(function (ok) {
      if (!ok || !alive()) return;
      var reqs = [api.get(EI + '/history')];
      if (SW.can('run')) reqs.push(api.get(EI + '/audit?limit=300'));
      Promise.all(reqs).then(function (res) {
        if (!alive()) return;
        var h = res[0], au = res[1];
        body.innerHTML = '<div class="card"><div class="tabs" role="tablist" id="hTabs">' +
          '<button class="tab active" data-target="hCases">Cases (' + h.cases.length + ')</button><button class="tab" data-target="hReports">Reports &amp; KB (' + h.reports.length + ')</button>' +
          '<button class="tab" data-target="hChecks">Checks (' + h.checks.length + ')</button>' + (au ? '<button class="tab" data-target="hAudit">Verification audit log</button>' : '') + '</div><div id="hPanels">' +
          '<div class="tab-panel active" id="hCases">' + (h.cases.length ? '<div class="table-wrap"><table><thead><tr><th>Key</th><th>Title</th><th>Type</th><th>Severity</th><th>Status</th><th>Opened</th><th>Record</th></tr></thead><tbody>' + h.cases.map(function (c) {
            return '<tr><td class="mono strong">' + SW.esc(c.key) + '</td><td>' + SW.esc(c.title) + '</td><td>' + SW.esc(c.kind) + '</td><td>' + X.st(c.severity) + '</td><td>' + X.st(c.status) + '</td><td class="mono">' + SW.esc(SW.fmtDate(c.opened_at)) + '</td>' +
              '<td>' + (c.record_id ? '<a class="linkish" href="#/email-record/' + c.record_id + '">open</a>' : '—') + '</td></tr>'; }).join('') + '</tbody></table></div>' : SW.emptyState('No cases yet', 'Create an incident or investigation case from an email record.')) + '</div>' +
          '<div class="tab-panel" id="hReports">' + (h.reports.length ? '<div class="table-wrap"><table><thead><tr><th>Created</th><th>Title</th><th>Email</th><th>Artefacts</th><th></th></tr></thead><tbody>' + h.reports.map(function (r) {
            return '<tr><td class="mono">' + SW.esc(SW.fmtDate(r.created_at)) + '</td><td>' + SW.esc(r.title) + '</td><td class="mono">' + SW.esc(r.email || '—') + '</td>' +
              '<td class="faint">' + [r.report_id ? 'PDF' : '', r.incident_id ? 'case' : '', r.kb_document_id ? 'KB doc' : ''].filter(Boolean).join(' · ') + '</td>' +
              '<td>' + (r.report_id ? '<button class="btn btn-sm" data-rep="' + r.report_id + '">' + SW.icon('download', 13) + 'PDF</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : SW.emptyState('No reports yet', 'Generate a PDF report or index a record into the knowledge base.')) + '</div>' +
          '<div class="tab-panel" id="hChecks">' + auditHTML(h.checks, true) + '</div>' +
          (au ? '<div class="tab-panel" id="hAudit">' + auditHTML(au.items, true) + '</div>' : '') + '</div></div>';
        SW.wireTabs(body.querySelector('#hTabs'), body.querySelector('#hPanels'));
        body.addEventListener('click', function (e) {
          var b = e.target.closest('[data-rep]'); if (!b) return;
          api.download('/reports/' + b.dataset.rep + '/download').then(function (n) { SW.toast('Downloaded', n, 'ok'); }, function (er) { SW.toast('Download failed', er.message); });
        });
      }, function (e) { if (alive()) failInto(body, e); });
    });
  } });

  /* ================= Public: verify-email (link target) ================= */
  SW.route('verify-email', { auth: false, title: 'Verify email', render: function (root) {
    var token = SW.hashQuery.token || '';
    /* Remove the token from the address bar and history immediately. */
    try { history.replaceState(null, '', location.pathname + location.search + '#/verify-email'); } catch (e) {}
    root.innerHTML = '<div class="verify-wrap"><div class="verify-card card">' +
      '<div class="auth-brand" style="justify-content:center;margin-bottom:18px">' + SW.LOGO_SVG(36) +
      '<div><div class="brand-name" style="font-size:18px;letter-spacing:.14em">SENTRIX</div><div class="brand-sub">Email ownership verification</div></div></div>' +
      '<div id="vOut"><div class="loading-row" style="justify-content:center"><span class="spinner"></span>Confirming…</div></div></div></div>';
    var out = root.querySelector('#vOut');
    if (!token) { out.innerHTML = '<h1 class="v-title">Link incomplete</h1><p class="muted">This verification link is missing its token. Open the link from the email again, or ask for a new code.</p>'; return; }
    api.post(EI + '/ownership/confirm', { token: token }, { noAuth: true }).then(function (r) {
      token = null;
      out.innerHTML = '<div class="v-ok">' + SW.icon('check', 28) + '</div><h1 class="v-title">Email address confirmed</h1><p class="muted">' + SW.esc(r.message) + '</p>' +
        '<p class="faint" style="margin-top:10px">' + SW.esc(r.email_masked || '') + '</p>' +
        '<p class="faint" style="margin-top:14px">This confirms you can receive mail at this address. It does not verify your identity.</p>';
    }, function (e) {
      token = null;
      out.innerHTML = '<h1 class="v-title">Verification not completed</h1><p class="muted">' + SW.esc(e.status ? e.message : 'The Sentrix service could not be reached. Please try the link again later.') + '</p>' +
        '<p class="faint" style="margin-top:12px">Links expire and can be used only once. Ask the organisation that contacted you to send a new verification.</p>';
    });
  } });
})();
