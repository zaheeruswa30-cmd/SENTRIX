/* Sentrix — authentication views. The console session lives in memory; when the Sentrix API is running,
   sign-in and registration are also performed against /api/v1/auth so the Email Identity module works. */
(function () {
  'use strict';
  var SW = window.SW;

  var LOGO = SW.LOGO_SVG(36);

  function shellWrap(inner) {
    return '' +
      '<div class="auth-wrap">' +
        '<section class="auth-aside">' +
          '<div class="auth-brand">' + LOGO +
            '<div><div class="brand-name" style="font-size:18px;letter-spacing:.14em">SENTRIX</div><div class="brand-sub">Security Operations Platform</div></div>' +
          '</div>' +
          '<h2 class="auth-tagline">Intelligent Security Operations, Threat Detection and Digital Identity Intelligence.</h2>' +
          '<ul class="auth-points">' +
            '<li>' + SW.icon('check', 16) + '<span><b>Real client-side RAG.</b> Upload .txt, .md, .pdf or .docx and the browser parses, chunks and indexes it with TF-IDF for genuine retrieval.</span></li>' +
            '<li>' + SW.icon('check', 16) + '<span><b>Deterministic detection rules.</b> Ten defensive rules with MITRE ATT&amp;CK ids and severity floors drive every assessment.</span></li>' +
            '<li>' + SW.icon('check', 16) + '<span><b>Email Identity Intelligence.</b> Real DNS, MX, SPF, DKIM and DMARC checks, consent-based mailbox ownership verification and an explainable risk engine — served by the Sentrix API.</span></li>' +
            '<li>' + SW.icon('check', 16) + '<span><b>Investigation only.</b> No response or remediation actions exist anywhere in this demo.</span></li>' +
          '</ul>' +
          '<div class="auth-note" role="note">' + SW.icon('warn', 18) +
            '<p><b>Endpoint telemetry is synthetic.</b> Hosts, alerts and incidents in the Monitor section are demo data. Email Identity checks are real and run on the backend. Tokens are kept in memory only — the session resets on reload.</p><p class="faint" id="apiState" style="margin-top:6px">Checking Sentrix API…</p></div>' +
        '</section>' +
        '<section class="auth-main">' + inner + '</section>' +
      '</div>';
  }

  function field(o) {
    return '<div class="fld' + (o.wide ? ' wide' : '') + '">' +
      '<label for="' + o.id + '">' + o.label + '</label>' +
      (o.select
        ? '<select id="' + o.id + '" name="' + o.id + '">' + o.options.map(function (x) {
            return '<option value="' + x[0] + '"' + (x[2] ? ' selected' : '') + '>' + x[1] + '</option>'; }).join('') + '</select>'
        : '<div class="input-wrap">' + (o.icon ? '<span class="in-icon">' + SW.icon(o.icon, 16) + '</span>' : '') +
          '<input id="' + o.id + '" name="' + o.id + '" type="' + (o.type || 'text') + '" placeholder="' + (o.ph || '') + '" ' +
          'autocomplete="' + (o.auto || 'off') + '"' + (o.icon ? ' class="has-icon"' : '') +
          ' aria-describedby="' + o.id + '-err">' +
          (o.toggle ? '<button type="button" class="in-toggle" data-toggle="' + o.id + '" aria-label="Show password" aria-pressed="false">' + SW.icon('eye', 16) + '</button>' : '') +
          '</div>') +
      (o.hint ? '<div class="fld-hint">' + o.hint + '</div>' : '') +
      '<div class="fld-err" id="' + o.id + '-err" role="alert"></div></div>';
  }
  function showErr(form, id, msg) {
    var el = form.querySelector('#' + id + '-err');
    if (el) el.textContent = msg || '';
    var input = form.querySelector('#' + id);
    if (input) input.classList.toggle('invalid', !!msg);
    if (msg && input) input.setAttribute('aria-invalid', 'true');
    else if (input) input.removeAttribute('aria-invalid');
  }
  function clearErrs(form) {
    form.querySelectorAll('.fld-err').forEach(function (e) { e.textContent = ''; });
    form.querySelectorAll('input').forEach(function (i) { i.classList.remove('invalid'); i.removeAttribute('aria-invalid'); });
    var f = form.querySelector('.form-error'); if (f) { f.textContent = ''; f.hidden = true; }
  }
  function wireToggles(root) {
    root.querySelectorAll('[data-toggle]').forEach(function (b) {
      b.addEventListener('click', function () {
        var input = root.querySelector('#' + b.dataset.toggle);
        var show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        b.innerHTML = SW.icon(show ? 'eyeoff' : 'eye', 16);
        b.setAttribute('aria-pressed', String(show));
        b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        input.focus();
      });
    });
  }
  function busy(btn, on, label) {
    btn.disabled = on;
    btn.classList.toggle('is-busy', on);
    if (on) { btn._label = btn.innerHTML; btn.innerHTML = '<span class="spinner" aria-hidden="true"></span>' + (label || 'Signing in…'); }
    else if (btn._label) btn.innerHTML = btn._label;
  }
  function emailOk(v) { return /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v); }

  var ROLE = { admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' };
  var creds = null;   // kept in this closure only, used to re-link the backend session after a reconnect
  function legacy(email) { return String(email || '').trim().replace(/@securewatch\.local$/i, '@sentrix.local'); }
  SW.legacyEmail = legacy;

  /* Attempts backend sign-in; always resolves. Result: backend user or null. */
  function connectBackend(email, pw) {
    creds = { email: email, pw: pw };
    if (!SW.api) return Promise.resolve(null);
    return SW.api.login(email, pw).catch(function () { return null; });
  }
  SW.reconnectBackend = function () {
    if (!creds || !SW.api) return Promise.resolve(null);
    return SW.api.login(creds.email, creds.pw).catch(function () { return null; });
  };
  function apiStateLine(root) {
    if (!SW.api) return;
    SW.api.probe().then(function (ok) {
      var el = root.querySelector('#apiState');
      if (el) el.innerHTML = ok ? '<span class="st st-good">API online</span> ' + SW.esc(SW.api.state.base)
        : '<span class="st st-warn">API offline</span> Email Identity needs the backend: <span class="mono">uvicorn backend.app.main:app --reload</span>';
    });
  }

  function login(user) {
    SW.state.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    SW.destroyCharts();
    document.getElementById('root').innerHTML = '';
    SW.go('dashboard');
    SW.toast('Signed in as ' + user.name, user.role + ' · ' + user.email +
      (SW.api && SW.api.authed() ? ' · Sentrix API connected' : ' · Sentrix API not connected (email module unavailable)'), SW.api && SW.api.authed() ? 'ok' : undefined);
  }
  SW.loginAs = login;

  function forgotModal() {
    SW.modal({
      title: 'Password reset is disabled in this demo',
      body: '<p class="muted">Self-service password reset is not implemented yet. Ask your Sentrix administrator to reset your account.</p>' +
        '<p class="muted" style="margin-top:10px">Use one of the seeded accounts, or create a new account (it lives in memory until you reload):</p>' +
        '<div class="cred-list" style="margin-top:12px">' + SW.state.users.filter(function (u) { return u.seeded; }).map(function (u) {
          return '<div class="cred"><b>' + u.role + '</b><span class="mono">' + u.email + '</span><span class="mono">' + u.password + '</span></div>';
        }).join('') + '</div>'
    });
  }

  /* ================= Login ================= */
  SW.route('login', { auth: false, render: function (root) {
    root.innerHTML = shellWrap(
      '<div class="auth-card">' +
        '<h1>Sign in</h1>' +
        '<p class="auth-sub">Use a seeded account, or continue instantly as the demo analyst.</p>' +
        '<button class="btn btn-demo" id="demoBtn">' + SW.icon('play', 16) + 'Continue as demo analyst</button>' +
        '<div class="or"><span>or sign in with credentials</span></div>' +
        '<form id="loginForm" novalidate>' +
          '<div class="form-error" role="alert" hidden></div>' +
          field({ id: 'email', label: 'Work email', type: 'email', ph: 'analyst@sentrix.local', icon: 'mail', auto: 'username', wide: true }) +
          field({ id: 'password', label: 'Password', type: 'password', ph: '••••••••••', icon: 'lock', toggle: true, auto: 'current-password', wide: true }) +
          '<div class="form-row split"><label class="check"><input type="checkbox" id="remember"><span>Keep me signed in</span></label>' +
            '<button type="button" class="linkish" id="forgotBtn">Forgot password?</button></div>' +
          '<button class="btn btn-primary btn-block" type="submit" id="submitBtn">Sign in' + SW.icon('arrow', 16) + '</button>' +
        '</form>' +
        '<div class="cred-box">' +
          '<div class="eyebrow">Seeded demo accounts — click to fill</div>' +
          '<div class="cred-list">' + SW.state.users.filter(function (u) { return u.seeded; }).map(function (u) {
            return '<button type="button" class="cred" data-email="' + u.email + '" data-pw="' + u.password + '">' +
              '<b>' + u.role + '</b><span class="mono">' + u.email + '</span><span class="mono">' + u.password + '</span></button>';
          }).join('') + '</div>' +
        '</div>' +
        '<p class="auth-foot">Don’t have an account? <a href="#/signup" id="toSignup">Create account</a></p>' +
      '</div>');

    var form = root.querySelector('#loginForm');
    wireToggles(root);
    root.querySelectorAll('.cred[data-email]').forEach(function (b) {
      b.addEventListener('click', function () {
        form.email.value = b.dataset.email;
        form.password.value = b.dataset.pw;
        clearErrs(form);
        form.querySelector('#submitBtn').focus();
        SW.toast('Credentials filled', b.dataset.email);
      });
    });
    root.querySelector('#forgotBtn').addEventListener('click', forgotModal);
    root.querySelector('#demoBtn').addEventListener('click', function () {
      var btn = this;
      busy(btn, true, 'Preparing demo session…');
      var demo = SW.state.users.filter(function (u) { return u.email === 'analyst@sentrix.local'; })[0];
      connectBackend(demo.email, demo.password).then(function () { login(demo); });
    });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearErrs(form);
      var email = form.email.value.trim(), pw = form.password.value;
      var bad = false;
      if (!email) { showErr(form, 'email', 'Enter your work email.'); bad = true; }
      else if (!emailOk(email)) { showErr(form, 'email', 'That does not look like a valid email address.'); bad = true; }
      if (!pw) { showErr(form, 'password', 'Enter your password.'); bad = true; }
      if (bad) { (form.querySelector('.invalid') || {}).focus && form.querySelector('.invalid').focus(); return; }

      var btn = form.querySelector('#submitBtn');
      busy(btn, true, 'Signing in…');
      email = legacy(email);
      var u = SW.state.users.filter(function (x) { return x.email.toLowerCase() === email.toLowerCase(); })[0];
      connectBackend(email, pw).then(function (bu) {
        if ((!u || u.password !== pw) && bu) {
          /* Account exists on the backend (e.g. registered earlier) — mirror it into the console session. */
          u = { id: bu.id, name: bu.name, email: bu.email, password: pw, role: ROLE[bu.role] || 'Viewer', seeded: false };
          SW.state.users.push(u);
        }
        if (!u || u.password !== pw) {
          busy(btn, false);
          var fe = form.querySelector('.form-error');
          fe.hidden = false;
          fe.textContent = 'Invalid credentials. Check the email and password, or use a seeded account below.';
          showErr(form, 'password', 'Invalid credentials');
          form.password.focus();
          return;
        }
        login(u);
      });
    });
    apiStateLine(root);
  } });

  /* ================= Signup ================= */
  function strength(pw) {
    var score = 0;
    if (pw.length >= 12) score += 2; else if (pw.length >= 8) score += 1;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
    if (/\d/.test(pw)) score += 1;
    if (/[^A-Za-z0-9]/.test(pw)) score += 1;
    if (pw.length >= 16) score += 1;
    var labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
    var pct = Math.min(100, Math.round((score / 6) * 100));
    return { score: score, label: labels[Math.min(score, 5)], pct: pct };
  }

  SW.route('signup', { auth: false, render: function (root) {
    root.innerHTML = shellWrap(
      '<div class="auth-card">' +
        '<h1>Create account</h1>' +
        '<p class="auth-sub">Creates a new Sentrix organisation with you as its administrator. When the Sentrix API is offline the account exists in this browser tab only.</p>' +
        '<form id="signupForm" novalidate>' +
          '<div class="form-error" role="alert" hidden></div>' +
          field({ id: 'name', label: 'Full name', ph: 'Jordan Vega', icon: 'user', auto: 'name', wide: true }) +
          field({ id: 'email', label: 'Work email', type: 'email', ph: 'you@company.com', icon: 'mail', auto: 'username', wide: true }) +
          field({ id: 'org', label: 'Organisation', ph: 'Acme Security Operations', icon: 'shield', auto: 'organization', wide: true, hint: 'Your data is isolated to this organisation (tenant).' }) +
          field({ id: 'password', label: 'Password', type: 'password', ph: 'At least 12 characters', icon: 'lock', toggle: true, auto: 'new-password', wide: true, hint: 'Minimum 12 characters. Mix upper, lower, a digit and a symbol for a stronger score.' }) +
          '<div class="strength" aria-live="polite"><div class="s-bar"><i id="sBar" style="width:0%"></i></div><span id="sLabel" class="faint">Password strength</span></div>' +
          field({ id: 'confirm', label: 'Confirm password', type: 'password', ph: 'Re-enter password', icon: 'lock', toggle: true, auto: 'new-password', wide: true }) +
          '<button class="btn btn-primary btn-block" type="submit" id="createBtn">Create account and sign in' + SW.icon('arrow', 16) + '</button>' +
        '</form>' +
        '<p class="auth-foot"><a href="#/login">← Back to sign in</a></p>' +
      '</div>');

    var form = root.querySelector('#signupForm');
    wireToggles(root);
    var bar = root.querySelector('#sBar'), lab = root.querySelector('#sLabel');
    form.password.addEventListener('input', function () {
      var st = strength(form.password.value);
      bar.style.width = st.pct + '%';
      bar.className = st.score <= 1 ? 'weak' : st.score <= 3 ? 'fair' : st.score <= 4 ? 'good' : 'strong';
      lab.textContent = form.password.value ? st.label + ' · ' + form.password.value.length + ' characters' : 'Password strength';
    });

    apiStateLine(root);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearErrs(form);
      var name = form.name.value.trim(), email = form.email.value.trim(),
          org = form.org.value.trim(), pw = form.password.value, cf = form.confirm.value;
      var bad = false;
      if (name.length < 2) { showErr(form, 'name', 'Enter your full name.'); bad = true; }
      if (!emailOk(email)) { showErr(form, 'email', 'Enter a valid email address, e.g. you@company.com'); bad = true; }
      else if (SW.state.users.some(function (u) { return u.email.toLowerCase() === email.toLowerCase(); })) {
        showErr(form, 'email', 'That email is already registered in this session.'); bad = true;
      }
      if (org && org.length < 2) { showErr(form, 'org', 'Organisation name is too short.'); bad = true; }
      if (pw.length < 12) { showErr(form, 'password', 'Password must be at least 12 characters (you entered ' + pw.length + ').'); bad = true; }
      if (!cf) { showErr(form, 'confirm', 'Re-enter the password to confirm.'); bad = true; }
      else if (pw !== cf) { showErr(form, 'confirm', 'Passwords do not match.'); bad = true; }
      if (bad) { var first = form.querySelector('.invalid'); if (first) first.focus(); return; }

      var btn = form.querySelector('#createBtn');
      busy(btn, true, 'Creating account…');
      var org2 = org || (name + "'s SOC");
      var reg = SW.api ? SW.api.register(name, email, pw, org2) : Promise.reject(new Error('API client missing'));
      reg.then(function (bu) {
        creds = { email: email, pw: pw };
        return { id: bu.id, name: bu.name, email: bu.email, password: pw, role: ROLE[bu.role] || 'Admin', seeded: false };
      }, function (err) {
        if (err && err.status && err.status !== 0) {
          busy(btn, false);
          var fe = form.querySelector('.form-error');
          fe.hidden = false; fe.textContent = 'Registration failed: ' + err.message;
          return null;
        }
        return { id: SW.uid('u'), name: name, email: email, password: pw, role: 'Admin', seeded: false };
      }).then(function (u) {
        if (!u) return;
        SW.state.users.push(u);
        login(u);
      });
    });
  } });
})();
