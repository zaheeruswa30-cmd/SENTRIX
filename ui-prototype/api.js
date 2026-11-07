/* Sentrix — backend API client.
   The access token lives only in memory (SW.state.api.token); nothing is written to browser storage.
   Base URL: same origin when the UI is served by the Sentrix API (http://localhost:8000), otherwise
   http://localhost:8000 (e.g. VS Code Live Server on :5500 or opening index.html from disk). */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var api = (SW.api = {});
  var FALLBACK = 'http://localhost:8000';

  SW.state = SW.state || {};
  var st = { token: null, user: null, status: 'unknown', base: null, meta: null };
  api.state = st;

  function candidates() {
    var list = [];
    if (/^https?:$/.test(location.protocol)) list.push(location.origin);
    if (list.indexOf(FALLBACK) < 0) list.push(FALLBACK);
    return list;
  }

  var probing = null;
  api.probe = function (force) {
    if (probing && !force) return probing;
    probing = (function next(i, list) {
      if (i >= list.length) { st.status = 'offline'; st.base = null; return Promise.resolve(false); }
      var ctrl = window.AbortController ? new AbortController() : null;
      var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 2500);
      return fetch(list[i] + '/api/healthz', { signal: ctrl ? ctrl.signal : undefined, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; })
        .then(function (j) {
          clearTimeout(timer);
          if (j && j.status === 'ok') { st.base = list[i]; st.status = 'online'; return true; }
          return next(i + 1, list);
        });
    })(0, candidates());
    return probing;
  };

  api.online = function () { return st.status === 'online' && !!st.base; };
  api.authed = function () { return api.online() && !!st.token; };

  function ApiError(status, message, body) { this.status = status; this.message = message; this.body = body; }
  ApiError.prototype = Object.create(Error.prototype);
  api.ApiError = ApiError;

  api.req = function (method, path, body, opts) {
    opts = opts || {};
    return api.probe().then(function (ok) {
      if (!ok) throw new ApiError(0, 'The Sentrix API is not reachable. Start it with: uvicorn backend.app.main:app --reload');
      var headers = {};
      if (st.token && !opts.noAuth) headers.Authorization = 'Bearer ' + st.token;
      var init = { method: method, headers: headers, cache: 'no-store' };
      if (body instanceof FormData) init.body = body;
      else if (body !== undefined && body !== null) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
      return fetch(st.base + '/api/v1' + path, init).then(function (r) {
        if (opts.blob && r.ok) return r.blob().then(function (b) { return { blob: b, headers: r.headers }; });
        if (r.status === 204) return null;
        return r.text().then(function (t) {
          var j = null;
          try { j = t ? JSON.parse(t) : null; } catch (e) { j = { detail: t }; }
          if (!r.ok) {
            var msg = (j && j.detail) ? (typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail)) : ('HTTP ' + r.status);
            if (r.status === 401 && !opts.noAuth) { st.token = null; }
            throw new ApiError(r.status, msg, j);
          }
          return j;
        });
      }, function () {
        st.status = 'offline';
        throw new ApiError(0, 'Network error contacting the Sentrix API.');
      });
    });
  };
  api.get = function (p, o) { return api.req('GET', p, null, o); };
  api.post = function (p, b, o) { return api.req('POST', p, b === undefined ? {} : b, o); };
  api.patch = function (p, b) { return api.req('PATCH', p, b); };
  api.del = function (p) { return api.req('DELETE', p); };

  function setSession(j) {
    st.token = j.access_token;
    st.user = j.user;
    document.dispatchEvent(new CustomEvent('sw:api-session', { detail: j.user }));
    return j.user;
  }
  api.login = function (email, password) {
    return api.req('POST', '/auth/login', { email: email, password: password }, { noAuth: true }).then(setSession);
  };
  api.register = function (name, email, password, organisation) {
    return api.req('POST', '/auth/register', { name: name, email: email, password: password, organisation: organisation },
      { noAuth: true }).then(setSession);
  };
  api.logout = function () { st.token = null; st.user = null; };

  /* Authenticated file download (PDF reports). */
  api.download = function (path, fallbackName) {
    return api.req('GET', path, null, { blob: true }).then(function (res) {
      var cd = res.headers.get('Content-Disposition') || '';
      var m = /filename="?([^";]+)"?/.exec(cd);
      var a = document.createElement('a');
      var url = URL.createObjectURL(res.blob);
      a.href = url; a.download = (m && m[1]) || fallbackName || 'sentrix-report.pdf';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
      return a.download;
    });
  };

  /* Shared UI for "backend not connected / not signed in" states — never shows fake data. */
  api.unavailableHTML = function (err) {
    var offline = !api.online();
    return '<div class="card api-offline" role="status">' +
      '<div class="card-head"><h3>' + (offline ? 'Sentrix API not connected' : 'Backend session required') + '</h3>' +
      '<span class="st st-warn">' + (offline ? 'offline' : 'signed out') + '</span></div>' +
      '<p class="muted">' + (offline
        ? 'Email Identity Intelligence runs real DNS, SPF, DKIM, DMARC and ownership checks on the Sentrix backend. Start the API from the project root, then reload this page:'
        : 'Your console session is not linked to a backend account. Sign out and sign in again with a Sentrix account (for example analyst@sentrix.local).') + '</p>' +
      (offline ? '<div class="pre" style="margin-top:12px">python -m venv .venv\n. .venv/bin/activate        # Windows: .venv\\Scripts\\activate\npip install -r requirements.txt\nuvicorn backend.app.main:app --reload\n# then open http://localhost:8000</div>' : '') +
      (err && err.message ? '<p class="faint" style="margin-top:10px">Details: ' + SW.esc(err.message) + '</p>' : '') +
      '<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn btn-primary btn-sm" data-api-retry>Retry connection</button></div></div>';
  };
  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('[data-api-retry]')) {
      api.probe(true).then(function () {
        if (api.online() && !st.token && SW.reconnectBackend) return SW.reconnectBackend();
      }).then(function () { if (SW.render) SW.render(); });
    }
  });

  api.probe();
})();
