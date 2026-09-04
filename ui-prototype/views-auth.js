/* SecureWatch AI — authentication views (client-side only, in-memory session). */
(function () {
  'use strict';
  var SW = window.SW;

  var LOGO = '<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-label="SecureWatch AI logo">' +
    '<path d="M12 2.6l8 3v6.1c0 5.2-3.4 8.7-8 9.9-4.6-1.2-8-4.7-8-9.9V5.6z"/><circle cx="12" cy="11.4" r="2.8"/><path d="M12 5.9v2.7M12 14.2v2.9"/></svg>';

  function shellWrap(inner) {
    return '' +
      '<div class="auth-wrap">' +
        '<section class="auth-aside">' +
          '<div class="auth-brand">' + LOGO +
            '<div><div class="brand-name" style="font-size:17px">SecureWatch AI</div><div class="brand-sub">XDR Console · Interactive demo</div></div>' +
          '</div>' +
          '<h2 class="auth-tagline">Endpoint detection triage with explainable, source-cited analysis.</h2>' +
          '<ul class="auth-points">' +
            '<li>' + SW.icon('check', 16) + '<span><b>Real client-side RAG.</b> Upload .txt, .md, .pdf or .docx and the browser parses, chunks and indexes it with TF-IDF for genuine retrieval.</span></li>' +
            '<li>' + SW.icon('check', 16) + '<span><b>Deterministic detection rules.</b> Ten defensive rules with MITRE ATT&amp;CK ids and severity floors drive every assessment.</span></li>' +
            '<li>' + SW.icon('check', 16) + '<span><b>Investigation only.</b> No response or remediation actions exist anywhere in this demo.</span></li>' +
          '</ul>' +
          '<div class="auth-note" role="note">' + SW.icon('warn', 18) +
            '<p><b>Synthetic demo.</b> Every host, alert, document and score is fabricated. Authentication runs entirely in this page; browser storage is not used, so the session resets on reload.</p></div>' +
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

  function login(user) {
    SW.state.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    SW.destroyCharts();
    document.getElementById('root').innerHTML = '';
    SW.go('dashboard');
    SW.toast('Signed in as ' + user.name, user.role + ' · ' + user.email, 'ok');
  }
  SW.loginAs = login;

  function forgotModal() {
    SW.modal({
      title: 'Password reset is disabled in this demo',
      body: '<p class="muted">There is no server, mail service or user database behind this page — everything runs in the browser tab, so a reset link cannot be sent.</p>' +
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
          field({ id: 'email', label: 'Work email', type: 'email', ph: 'analyst@securewatch.local', icon: 'mail', auto: 'username', wide: true }) +
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
      setTimeout(function () {
        login(SW.state.users.filter(function (u) { return u.email === 'analyst@securewatch.local'; })[0]);
      }, 420);
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
      setTimeout(function () {
        var u = SW.state.users.filter(function (x) { return x.email.toLowerCase() === email.toLowerCase(); })[0];
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
      }, 520);
    });
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
        '<p class="auth-sub">Accounts are created in this browser tab only. Nothing is sent anywhere and nothing is stored.</p>' +
        '<form id="signupForm" novalidate>' +
          '<div class="form-error" role="alert" hidden></div>' +
          field({ id: 'name', label: 'Full name', ph: 'Jordan Vega', icon: 'user', auto: 'name', wide: true }) +
          field({ id: 'email', label: 'Work email', type: 'email', ph: 'you@securewatch.local', icon: 'mail', auto: 'username', wide: true }) +
          field({ id: 'role', label: 'Role', select: true, options: [['Analyst', 'Analyst — triage, upload, run analysis', true], ['Viewer', 'Viewer — read-only access'], ['Admin', 'Admin — everything plus user management']], wide: true }) +
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

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      clearErrs(form);
      var name = form.name.value.trim(), email = form.email.value.trim(),
          role = form.role.value, pw = form.password.value, cf = form.confirm.value;
      var bad = false;
      if (name.length < 2) { showErr(form, 'name', 'Enter your full name.'); bad = true; }
      if (!emailOk(email)) { showErr(form, 'email', 'Enter a valid email address, e.g. you@securewatch.local'); bad = true; }
      else if (SW.state.users.some(function (u) { return u.email.toLowerCase() === email.toLowerCase(); })) {
        showErr(form, 'email', 'That email is already registered in this session.'); bad = true;
      }
      if (pw.length < 12) { showErr(form, 'password', 'Password must be at least 12 characters (you entered ' + pw.length + ').'); bad = true; }
      if (!cf) { showErr(form, 'confirm', 'Re-enter the password to confirm.'); bad = true; }
      else if (pw !== cf) { showErr(form, 'confirm', 'Passwords do not match.'); bad = true; }
      if (bad) { var first = form.querySelector('.invalid'); if (first) first.focus(); return; }

      var btn = form.querySelector('#createBtn');
      busy(btn, true, 'Creating account…');
      setTimeout(function () {
        var u = { id: SW.uid('u'), name: name, email: email, password: pw, role: role, seeded: false };
        SW.state.users.push(u);
        login(u);
      }, 560);
    });
  } });
})();
