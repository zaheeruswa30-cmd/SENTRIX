/* SecureWatch AI — SPA core: in-memory store, hash router, app shell, UI primitives.
   NO browser storage of any kind is used anywhere (those APIs are unavailable in the
   preview iframe). All state lives in the SW.state object below and is intentionally
   lost on reload. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});

  var REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  SW.reduced = REDUCED;

  /* ================= In-memory store ================= */
  SW.state = {
    user: null,
    users: SW.seed.users.map(function (u) { return Object.assign({}, u); }),
    endpoints: SW.seed.endpoints.map(function (e) { return Object.assign({}, e); }),
    events: SW.seed.events.map(function (e) { return Object.assign({}, e); }),
    incidents: SW.seed.incidents.map(function (i) { return Object.assign({}, i); }),
    docs: [],          // {id,name,ext,kind,sizeBytes,hash,status,step,progress,chunkIds,pages,addedAt,error}
    chunks: [],        // {id,docId,docName,page,section,text,vec,tokens}
    runs: [],          // agent run records
    chat: [],          // assistant messages
    navCollapsed: window.innerWidth < 1280,
    liveFeed: true,
    liveIdx: 0,
    toastCount: 0
  };

  SW.uid = function (p) { return (p || 'id') + '-' + Math.random().toString(36).slice(2, 9); };

  /* ================= Icons ================= */
  var ico = {
    dash: '<path d="M3 12h7V3H3zM14 21h7v-9h-7zM14 8h7V3h-7zM3 21h7v-5H3z"/>',
    endpoints: '<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
    events: '<path d="M4 5h16M4 12h10M4 19h7"/><circle cx="18" cy="17" r="3"/>',
    incident: '<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
    ai: '<path d="M12 3v3M12 18v3M4.2 7.5l2.6 1.5M17.2 15l2.6 1.5M4.2 16.5l2.6-1.5M17.2 9l2.6-1.5"/><circle cx="12" cy="12" r="4"/>',
    rag: '<path d="M4 6a2 2 0 012-2h12a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2z"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    kb: '<path d="M4 5v14a2 2 0 002 2h13V3H6a2 2 0 00-2 2z"/><path d="M8 3v18"/>',
    reports: '<path d="M6 3h9l5 5v13a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z"/><path d="M14 3v6h6M9 14h6M9 17h4"/>',
    chat: '<path d="M21 12a8 8 0 01-8 8H8l-4 3v-5.5A8 8 0 1121 12z"/><path d="M8.5 11h7M8.5 14.5h4"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-2.9 1.2V21a2 2 0 11-4 0v-.1A1.7 1.7 0 007 19.4a1.7 1.7 0 00-1.9.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1A1.7 1.7 0 002.6 15a2 2 0 010-4 1.7 1.7 0 001.5-2.4 1.7 1.7 0 00-.4-.5l-.1-.1a2 2 0 112.8-2.8l.1.1A1.7 1.7 0 009 4.6 2 2 0 0111 3a2 2 0 012 2v.1a1.7 1.7 0 002.9 1.2l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00.3 1.9 2 2 0 010 4z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
    chevron: '<path d="M15 18l-6-6 6-6"/>',
    chevdown: '<path d="M6 9l6 6 6-6"/>',
    warn: '<path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L14.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    doc: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/>',
    trash: '<path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2M6 7l1 13h10l1-13"/>',
    upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>',
    bot: '<rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M9 12h.01M15 12h.01M9.5 16h5"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/>',
    users: '<circle cx="9" cy="8" r="3.4"/><path d="M2.5 21c0-3.6 3-5.6 6.5-5.6s6.5 2 6.5 5.6"/><path d="M16.5 4.6a3.4 3.4 0 010 6.8M18 15.6c2.3.5 3.9 2.3 3.9 5.4"/>',
    logout: '<path d="M10 17l-5-5 5-5"/><path d="M5 12h9M14 4h4a2 2 0 012 2v12a2 2 0 01-2 2h-4"/>',
    swap: '<path d="M4 8h13l-3-3M20 16H7l3 3"/>',
    eye: '<path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6-10-6-10-6z"/><circle cx="12" cy="12" r="2.8"/>',
    eyeoff: '<path d="M4 4l16 16"/><path d="M9.6 5.6A9.9 9.9 0 0112 5.4c6.4 0 10 6 10 6a17 17 0 01-3 3.6M6.3 7.9A17 17 0 002 11.4s3.6 6 10 6a9.6 9.6 0 003.4-.6"/>',
    play: '<path d="M7 4l13 8-13 8z"/>',
    export: '<path d="M12 3v12M8 11l4 4 4-4"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    check: '<path d="M5 12.5l5 5L20 7"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 6.5L12 13l8.5-6.5"/>',
    shield: '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9.6C7.4 20.4 4 17 4 12V6z"/>',
    win: '<path d="M3 5.5l8-1.1v7.1H3zM13 4.1L21 3v8.5h-8zM3 12.5h8v7.1l-8-1.1zM13 12.5h8V21l-8-1.1z"/>',
    linux: '<path d="M9 4a3 3 0 016 0v3.5c0 1 .6 1.8 1.3 2.7 1 1.3 1.7 2.6 1.7 4.3 0 3.2-2.7 5.5-6 5.5s-6-2.3-6-5.5c0-1.7.7-3 1.7-4.3C8.4 9.3 9 8.5 9 7.5z"/><path d="M10.2 8.3h3.6"/>',
    mac: '<path d="M16 3c-1.6.2-3 1.5-3.2 3 1.6.1 3.2-1.4 3.2-3z"/><path d="M19.5 16.4c-.5 1.2-1.4 3-2.6 3.5-1 .5-1.7 0-2.9 0s-2 .5-2.9 0c-1.3-.6-2.4-2.7-3-4.5-.9-2.7-.4-6 1.5-7.4 1-.8 2.3-.8 3.3-.3.9.5 1.6.5 2.5 0 1-.5 2.4-.6 3.4.3-1.9 1.2-2.3 4.3-1.3 6.3.5 1 1.3 1.7 2 2.1z"/>'
  };
  SW.icon = function (name, size) {
    return '<svg width="' + (size || 18) + '" height="' + (size || 18) + '" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      (ico[name] || '') + '</svg>';
  };
  SW.osIcon = function (os) {
    var s = (os || '').toLowerCase();
    return s.indexOf('mac') >= 0 ? 'mac' : (s.indexOf('windows') >= 0 ? 'win' : 'linux');
  };

  /* ================= Helpers ================= */
  SW.esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  SW.badge = function (level) {
    var map = {
      CRITICAL: ['critical', 'sh-octagon'], HIGH: ['high', 'sh-triangle'], MEDIUM: ['medium', 'sh-diamond'],
      LOW: ['low', 'sh-circle'], INFO: ['info', 'sh-circle'], RESOLVED: ['info', 'sh-circle'],
      OFFLINE: ['offline', 'sh-ring'], UNKNOWN: ['offline', 'sh-ring']
    };
    var m = map[level] || map.UNKNOWN;
    return '<span class="badge ' + m[0] + '"><i class="shape ' + m[1] + '" style="background:currentColor"></i>' + level + '</span>';
  };
  SW.sevOf = function (score) {
    return score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  };
  SW.ring = function (score, size) {
    var s = size || 46, r = (s - 6) / 2, c = 2 * Math.PI * r;
    var col = score === 0 ? '#64748B' : score >= 80 ? '#34D399' : score >= 60 ? '#FBBF24' : score >= 40 ? '#FB923C' : '#FB7185';
    return '<svg class="ring" width="' + s + '" height="' + s + '" viewBox="0 0 ' + s + ' ' + s + '" role="img" aria-label="Security health score ' + score + ' of 100">' +
      '<circle cx="' + s / 2 + '" cy="' + s / 2 + '" r="' + r + '" fill="none" stroke="#151E2E" stroke-width="4"/>' +
      '<circle cx="' + s / 2 + '" cy="' + s / 2 + '" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="4" stroke-linecap="round" ' +
      'stroke-dasharray="' + c + '" stroke-dashoffset="' + c * (1 - score / 100) + '" transform="rotate(-90 ' + s / 2 + ' ' + s / 2 + ')"/>' +
      '<text x="50%" y="50%" text-anchor="middle" dy="4" fill="#E6EDF7" font-family="JetBrains Mono, monospace" font-size="13">' + (score === 0 ? '—' : score) + '</text></svg>';
  };
  SW.spark = function (data, color) {
    var w = 120, h = 28, max = Math.max.apply(null, data), min = Math.min.apply(null, data);
    var d = data.map(function (v, i) {
      var x = i * (w / (data.length - 1)), y = h - 2 - ((v - min) / (max - min || 1)) * (h - 6);
      return (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1);
    }).join(' ');
    return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" aria-hidden="true">' +
      '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>';
  };
  SW.fmtTime = function (d) {
    var t = new Date(d);
    return [t.getUTCHours(), t.getUTCMinutes(), t.getUTCSeconds()].map(function (n) {
      return String(n).padStart(2, '0');
    }).join(':');
  };
  SW.fmtDate = function (d) {
    var t = new Date(d);
    return t.toISOString().slice(0, 10) + ' ' + SW.fmtTime(t) + ' UTC';
  };
  SW.bytes = function (n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  };
  SW.ago = function (d) {
    var s = Math.max(0, Math.round((Date.now() - new Date(d).getTime()) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    return Math.round(s / 3600) + 'h ago';
  };

  /* ================= Toast ================= */
  SW.toast = function (title, body, kind) {
    var host = document.getElementById('toastHost');
    if (!host) return;
    var t = document.createElement('div');
    t.className = 'toast' + (kind ? ' toast-' + kind : '');
    t.setAttribute('role', 'status');
    t.innerHTML = '<b>' + SW.esc(title) + '</b>' + (body ? '<p>' + SW.esc(body) + '</p>' : '');
    host.appendChild(t);
    requestAnimationFrame(function () { t.classList.add('show'); });
    setTimeout(function () {
      t.classList.remove('show');
      setTimeout(function () { t.remove(); }, 260);
    }, 4200);
  };

  /* ================= Modal ================= */
  var lastFocus = null;
  SW.modal = function (opts) {
    SW.closeModal();
    lastFocus = document.activeElement;
    var host = document.getElementById('modalHost');
    var wrap = document.createElement('div');
    wrap.className = 'modal-backdrop';
    wrap.innerHTML = '<div class="modal" role="dialog" aria-modal="true" aria-label="' + SW.esc(opts.title) + '">' +
      '<div class="modal-head"><h3>' + SW.esc(opts.title) + '</h3>' +
      '<button class="icon-btn" data-close aria-label="Close dialog">' + SW.icon('x', 18) + '</button></div>' +
      '<div class="modal-body">' + (opts.body || '') + '</div>' +
      (opts.footer === null ? '' : '<div class="modal-foot">' + (opts.footer || '<button class="btn btn-primary" data-close>Got it</button>') + '</div>') +
      '</div>';
    host.appendChild(wrap);
    wrap.addEventListener('click', function (e) {
      if (e.target === wrap || e.target.closest('[data-close]')) SW.closeModal();
    });
    var f = wrap.querySelector('button, a, input, select, textarea');
    if (f) f.focus();
    if (opts.onMount) opts.onMount(wrap);
    return wrap;
  };
  SW.closeModal = function () {
    var host = document.getElementById('modalHost');
    if (host && host.firstChild) {
      host.innerHTML = '';
      if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) {} }
    }
  };
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') SW.closeModal();
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (SW.state.user) SW.openCommandPalette();
    }
  });

  /* ================= Charts ================= */
  SW.charts = [];
  SW.chart = function (canvas, cfg) {
    if (!window.Chart || !canvas) return null;
    var c = new Chart(canvas, cfg);
    SW.charts.push(c);
    return c;
  };
  SW.destroyCharts = function () {
    SW.charts.forEach(function (c) { try { c.destroy(); } catch (e) {} });
    SW.charts = [];
  };
  SW.axis = function (extra) {
    return Object.assign({
      grid: { color: 'rgba(148,163,184,0.08)', drawTicks: false },
      border: { display: false },
      ticks: { color: '#63728A', padding: 8, font: { size: 12 } }
    }, extra || {});
  };
  function chartDefaults() {
    if (!window.Chart) return;
    Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.color = '#63728A';
    Chart.defaults.animation.duration = REDUCED ? 0 : 700;
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.plugins.tooltip.backgroundColor = '#151E2E';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(148,163,184,0.22)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = '#E6EDF7';
    Chart.defaults.plugins.tooltip.bodyColor = '#9AA9BF';
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.maintainAspectRatio = false;
  }

  /* ================= RBAC ================= */
  var CAPS = {
    Admin: { upload: true, delete: true, run: true, manageUsers: true, advanceIncident: true },
    Analyst: { upload: true, delete: true, run: true, manageUsers: false, advanceIncident: true },
    Viewer: { upload: false, delete: false, run: false, manageUsers: false, advanceIncident: false }
  };
  SW.can = function (cap) {
    var u = SW.state.user;
    if (!u) return false;
    return !!(CAPS[u.role] && CAPS[u.role][cap]);
  };
  SW.denyReason = function (cap) {
    var labels = {
      upload: 'Uploading documents', delete: 'Deleting documents', run: 'Running agent analysis',
      advanceIncident: 'Advancing incident stages'
    };
    return (labels[cap] || 'This action') + ' requires the Analyst or Admin role. You are signed in as Viewer.';
  };
  /* Renders a button that is genuinely disabled with a visible reason when the role lacks the cap. */
  SW.gate = function (cap, html, attrs) {
    if (SW.can(cap)) return html;
    var reason = SW.denyReason(cap);
    return '<span class="gate" data-tip="' + SW.esc(reason) + '" tabindex="0" role="note" aria-label="' + SW.esc(reason) + '">' +
      html.replace('<button', '<button disabled aria-disabled="true"') + '</span>';
  };

  /* ================= Router ================= */
  SW.routes = {};   // name -> { render(host, params), auth, shell }
  SW.route = function (name, def) { SW.routes[name] = def; };

  function parseHash() {
    var h = (location.hash || '').replace(/^#\/?/, '');
    var parts = h.split('/').filter(Boolean);
    return { name: parts[0] || (SW.state.user ? 'dashboard' : 'login'), param: parts[1] || null, raw: h };
  }
  SW.go = function (path) {
    var target = '#/' + String(path).replace(/^#?\/?/, '');
    if (location.hash === target) render();
    else location.hash = target;
  };
  SW.current = function () { return parseHash(); };

  var NAV = [
    { group: 'Monitor', items: [
      { id: 'dashboard', label: 'Dashboard', icon: 'dash' },
      { id: 'endpoints', label: 'Endpoints', icon: 'endpoints' },
      { id: 'events', label: 'Security Events', icon: 'events' },
      { id: 'incidents', label: 'Incidents', icon: 'incident' }
    ] },
    { group: 'Intelligence', items: [
      { id: 'ai-center', label: 'AI Security Center', icon: 'ai' },
      { id: 'rag', label: 'RAG Intelligence', icon: 'rag' },
      { id: 'knowledge-base', label: 'Knowledge Base', icon: 'kb' }
    ] },
    { group: 'Workspace', items: [
      { id: 'assistant', label: 'Assistant', icon: 'chat' },
      { id: 'reports', label: 'Reports', icon: 'reports' },
      { id: 'settings', label: 'Settings', icon: 'settings' }
    ] }
  ];
  var PARENT = { 'endpoint': 'endpoints', 'incident': 'incidents', 'event': 'events' };

  function shellHTML(active) {
    var u = SW.state.user;
    var initials = u.name.split(/\s+/).map(function (p) { return p[0]; }).join('').slice(0, 2).toUpperCase();
    return '' +
      '<aside class="sidebar" id="sidebar">' +
        '<div class="brand">' +
          '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-label="SecureWatch AI logo">' +
          '<path d="M12 2.6l8 3v6.1c0 5.2-3.4 8.7-8 9.9-4.6-1.2-8-4.7-8-9.9V5.6z"/><circle cx="12" cy="11.4" r="2.8"/><path d="M12 5.9v2.7M12 14.2v2.9"/></svg>' +
          '<div class="brand-text"><div class="brand-name">SecureWatch AI</div><div class="brand-sub">XDR Console · Demo</div></div>' +
        '</div>' +
        '<nav class="nav" aria-label="Primary">' +
          NAV.map(function (g) {
            return '<div class="nav-section eyebrow">' + g.group + '</div>' + g.items.map(function (n) {
              var on = n.id === active;
              return '<a class="nav-item' + (on ? ' active' : '') + '" href="#/' + n.id + '" data-tip="' + n.label + '"' +
                (on ? ' aria-current="page"' : '') + '>' + SW.icon(n.icon) + '<span class="label">' + n.label + '</span></a>';
            }).join('');
          }).join('') +
        '</nav>' +
        '<div class="nav-foot"><button class="collapse-btn" id="collapseBtn" aria-label="Toggle sidebar" aria-expanded="' + (!SW.state.navCollapsed) + '">' +
          SW.icon('chevron') + '<span class="label">Collapse sidebar</span></button></div>' +
      '</aside>' +
      '<div class="main">' +
        '<header class="topbar">' +
          '<div class="search"><button class="search-open" id="paletteBtn" aria-label="Open global search">' + SW.icon('search', 16) + '</button>' +
            '<input type="search" id="topSearch" placeholder="Search endpoints, events, documents…" aria-label="Global search" autocomplete="off">' +
            '<span class="kbd">⌘K</span></div>' +
          '<div class="topbar-spacer"></div>' +
          '<span class="ai-chip" title="Honest labelling of the analysis engine">' + SW.icon('ai', 14) +
            'Simulated analysis engine — deterministic rules + client-side retrieval, no LLM</span>' +
          '<span class="demo-badge"><i class="dot"></i>DEMO DATA</span>' +
          '<span class="role-chip role-' + u.role.toLowerCase() + '">' + SW.icon('shield', 13) + u.role + '</span>' +
          '<div class="usermenu-wrap">' +
            '<button class="usermenu" id="userBtn" aria-haspopup="menu" aria-expanded="false">' +
              '<span class="avatar">' + initials + '</span>' +
              '<span class="who"><b>' + SW.esc(u.name) + '</b><span>' + SW.esc(u.role) + '</span></span>' +
              SW.icon('chevdown', 14) +
            '</button>' +
            '<div class="dropdown" id="userMenu" role="menu" hidden>' +
              '<div class="dd-head"><b>' + SW.esc(u.name) + '</b><span>' + SW.esc(u.email) + '</span>' +
                '<span class="role-chip role-' + u.role.toLowerCase() + '" style="margin-top:8px">' + SW.icon('shield', 13) + u.role + '</span></div>' +
              '<button class="dd-item" role="menuitem" data-act="profile">' + SW.icon('user', 16) + 'Account details</button>' +
              '<button class="dd-item" role="menuitem" data-act="switch">' + SW.icon('swap', 16) + 'Switch account</button>' +
              '<button class="dd-item danger" role="menuitem" data-act="signout">' + SW.icon('logout', 16) + 'Sign out</button>' +
            '</div>' +
          '</div>' +
        '</header>' +
        '<main class="content" id="view" tabindex="-1"></main>' +
      '</div>';
  }

  function mountShell(active) {
    var root = document.getElementById('root');
    if (!root.querySelector('.sidebar')) {
      root.className = 'app';
      root.innerHTML = shellHTML(active);
      wireShell();
    } else {
      root.querySelectorAll('.nav-item').forEach(function (a) {
        var on = a.getAttribute('href') === '#/' + active;
        a.classList.toggle('active', on);
        if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
      });
    }
    document.body.classList.toggle('nav-collapsed', SW.state.navCollapsed);
    return document.getElementById('view');
  }
  SW.remountShell = function () {
    var root = document.getElementById('root');
    root.innerHTML = '';
    render();
  };

  function wireShell() {
    var cb = document.getElementById('collapseBtn');
    cb.addEventListener('click', function () {
      SW.state.navCollapsed = !SW.state.navCollapsed;
      document.body.classList.toggle('nav-collapsed', SW.state.navCollapsed);
      cb.setAttribute('aria-expanded', String(!SW.state.navCollapsed));
      setTimeout(function () { SW.charts.forEach(function (c) { try { c.resize(); } catch (e) {} }); }, 240);
    });
    var ub = document.getElementById('userBtn'), um = document.getElementById('userMenu');
    ub.addEventListener('click', function (e) {
      e.stopPropagation();
      var open = um.hidden;
      um.hidden = !open;
      ub.setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('click', function () { if (um && !um.hidden) { um.hidden = true; ub.setAttribute('aria-expanded', 'false'); } });
    um.addEventListener('click', function (e) {
      var b = e.target.closest('[data-act]'); if (!b) return;
      um.hidden = true;
      var act = b.dataset.act;
      if (act === 'signout') SW.signOut();
      else if (act === 'switch') SW.switchAccount();
      else if (act === 'profile') {
        var u = SW.state.user;
        SW.modal({ title: 'Account details', body:
          '<dl class="kv"><dt>Name</dt><dd>' + SW.esc(u.name) + '</dd><dt>Email</dt><dd>' + SW.esc(u.email) + '</dd>' +
          '<dt>Role</dt><dd>' + u.role + '</dd><dt>Session</dt><dd>in-memory only</dd></dl>' +
          '<p class="faint" style="margin-top:12px">This demo authenticates entirely in the browser. No credentials leave the page and no browser storage is used, so the session ends on reload.</p>' });
      }
    });
    var ts = document.getElementById('topSearch');
    ts.addEventListener('focus', function () { SW.openCommandPalette(ts.value); ts.blur(); });
    document.getElementById('paletteBtn').addEventListener('click', function () { SW.openCommandPalette(); });
  }

  SW.signOut = function () {
    SW.state.user = null;
    SW.state.chat = [];
    SW.destroyCharts();
    document.getElementById('root').innerHTML = '';
    SW.go('login');
    SW.toast('Signed out', 'Session state cleared from memory.');
  };
  SW.switchAccount = function () {
    SW.state.user = null;
    SW.destroyCharts();
    document.getElementById('root').innerHTML = '';
    SW.go('login');
    SW.toast('Switch account', 'Pick another seeded account or create a new one.');
  };

  /* ================= Global search (⌘K) ================= */
  SW.openCommandPalette = function (initial) {
    var m = SW.modal({
      title: 'Global search', footer: null,
      body: '<div class="searchbox">' + SW.icon('search', 16) +
        '<input id="cmdInput" type="search" placeholder="Search events, endpoints, incidents, documents…" aria-label="Global search input" value="' + SW.esc(initial || '') + '"></div>' +
        '<div id="cmdResults" class="cmd-results" role="listbox" aria-label="Search results"></div>'
    });
    var input = m.querySelector('#cmdInput'), out = m.querySelector('#cmdResults');
    function run() {
      var q = input.value.trim().toLowerCase();
      if (!q) { out.innerHTML = '<div class="empty-mini">Type to search across the in-memory dataset.</div>'; return; }
      var res = [];
      SW.state.endpoints.forEach(function (e) {
        if ((e.host + ' ' + e.os + ' ' + e.ip + ' ' + e.group).toLowerCase().indexOf(q) >= 0)
          res.push({ k: 'Endpoint', t: e.host, s: e.os + ' · risk ' + e.risk, href: '#/endpoint/' + e.id });
      });
      SW.state.events.forEach(function (e) {
        if ((e.title + ' ' + e.endpoint + ' ' + e.type + ' ' + e.id).toLowerCase().indexOf(q) >= 0)
          res.push({ k: 'Event', t: e.id + ' · ' + e.title, s: e.severity + ' · ' + e.endpoint, href: '#/event/' + e.id });
      });
      SW.state.incidents.forEach(function (i) {
        if ((i.id + ' ' + i.title).toLowerCase().indexOf(q) >= 0)
          res.push({ k: 'Incident', t: i.id + ' · ' + i.title, s: i.severity + ' · stage ' + (i.stage + 1), href: '#/incident/' + i.id });
      });
      SW.state.docs.forEach(function (d) {
        if (d.name.toLowerCase().indexOf(q) >= 0)
          res.push({ k: 'Document', t: d.name, s: (d.chunkIds || []).length + ' chunks · ' + d.status, href: '#/knowledge-base' });
      });
      res = res.slice(0, 12);
      out.innerHTML = res.length ? res.map(function (r) {
        return '<a class="cmd-row" role="option" href="' + r.href + '"><span class="cmd-kind">' + r.k + '</span>' +
          '<span class="cmd-main"><b>' + SW.esc(r.t) + '</b><span>' + SW.esc(r.s) + '</span></span>' + SW.icon('arrow', 15) + '</a>';
      }).join('') : '<div class="empty-mini">No matches in events, endpoints, incidents or documents.</div>';
      out.querySelectorAll('a').forEach(function (a) {
        a.addEventListener('click', function () { setTimeout(SW.closeModal, 10); });
      });
    }
    input.addEventListener('input', run);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { var first = out.querySelector('a'); if (first) first.click(); }
    });
    run();
  };

  /* ================= Live alert simulation ================= */
  SW.pushLiveAlert = function () {
    var tpl = SW.seed.liveAlerts[SW.state.liveIdx++ % SW.seed.liveAlerts.length];
    var ev = Object.assign({}, tpl, {
      id: 'EVT-' + (4200 + SW.state.liveIdx), ts: new Date(), status: 'New',
      fields: Object.assign({}, tpl.fields), live: true
    });
    SW.state.events.unshift(ev);
    var live = document.getElementById('ariaLive');
    if (live) live.textContent = 'New ' + ev.severity + ' alert on ' + ev.endpoint + ': ' + ev.title;
    document.dispatchEvent(new CustomEvent('sw:newevent', { detail: ev }));
    SW.toast('New ' + ev.severity + ' alert', ev.endpoint + ' · ' + ev.title, ev.severity === 'CRITICAL' ? 'crit' : 'warn');
    return ev;
  };

  /* ================= Skeleton + reveal ================= */
  SW.revealAll = function (host) {
    var items = (host || document).querySelectorAll('.reveal:not(.in)');
    items.forEach(function (el, i) {
      setTimeout(function () { el.classList.add('in'); }, REDUCED ? 0 : Math.min(i, 7) * 40);
    });
  };
  SW.skeleton = function (host, html, build) {
    host.innerHTML = html;
    var delay = REDUCED ? 0 : 420;
    setTimeout(function () { build(); SW.revealAll(host); }, delay);
  };

  /* ================= Render loop ================= */
  /* Scoped DOM-event subscription: auto-detaches as soon as another view renders,
     so stale handlers can never query nodes that have been replaced. */
  SW.renderSeq = 0;
  SW.listen = function (evt, fn) {
    var seq = SW.renderSeq;
    function h(e) {
      if (seq !== SW.renderSeq) { document.removeEventListener(evt, h); return; }
      fn(e);
    }
    document.addEventListener(evt, h);
    return h;
  };

  function render() {
    SW.renderSeq++;
    var r = parseHash();
    var name = r.name;
    var def = SW.routes[name];
    if (!def) { SW.go(SW.state.user ? 'dashboard' : 'login'); return; }
    if (def.auth !== false && !SW.state.user) { SW.go('login'); return; }
    if (def.auth === false && SW.state.user && (name === 'login' || name === 'signup')) { SW.go('dashboard'); return; }

    SW.destroyCharts();
    SW.closeModal();

    if (def.auth === false) {
      var root = document.getElementById('root');
      root.className = 'auth-root';
      root.innerHTML = '';
      def.render(root, r.param);
      return;
    }
    var host = mountShell(PARENT[name] || name);
    host.innerHTML = '';
    host.scrollTop = 0;
    window.scrollTo(0, 0);
    document.title = (def.title || 'SecureWatch AI') + ' · SecureWatch AI (Demo)';
    def.render(host, r.param);
  }
  SW.render = render;

  window.addEventListener('hashchange', render);
  document.addEventListener('DOMContentLoaded', function () {
    chartDefaults();
    SW.initRag();     // builds the seeded document index
    render();
    setInterval(function () {
      if (SW.state.user && SW.state.liveFeed) SW.pushLiveAlert();
    }, 22000);
  });
})();
