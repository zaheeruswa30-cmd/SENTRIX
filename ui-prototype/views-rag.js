/* SecureWatch AI — RAG Intelligence Center and Knowledge Base views. */
(function () {
  'use strict';
  var SW = window.SW;
  var rag = SW.rag;

  /* ---------- shared components ---------- */
  function stepperHTML(step, status) {
    return '<div class="stepper">' + rag.STAGES.map(function (s, i) {
      var cls = status === 'Failed' && i === step ? 'failed' : i < step ? 'done' : i === step ? 'active' : '';
      return '<span class="step ' + cls + '"><i></i>' + s + '</span>';
    }).join('') + '</div>';
  }
  function docRowHTML(d) {
    var pct = d.progress || 0;
    var statusCls = d.status === 'Ready' ? 'info' : d.status === 'Failed' ? 'critical' : 'low';
    return '<div class="doc-row" data-doc="' + d.id + '">' +
      '<span class="doc-icon">' + SW.icon('doc', 16) + '</span>' +
      '<span class="doc-main">' +
        '<span class="doc-name">' + SW.esc(d.name) +
          (d.kind === 'demo' ? ' <span class="tag-demo">demo doc</span>' : '') + '</span>' +
        '<span class="doc-meta">' + SW.bytes(d.sizeBytes) + ' · ' + (d.pages || 1) + ' page(s) · ' +
          d.chunkIds.length + ' chunks · ' + (d.hash ? 'sha256 ' + d.hash.slice(0, 10) : 'hashing…') + '</span>' +
        (d.status !== 'Ready' && d.status !== 'Failed'
          ? '<span class="doc-prog"><span class="bar"><i style="width:' + pct + '%"></i></span><span class="mono faint">' + d.status + ' ' + pct + '%</span></span>' : '') +
        (d.error ? '<span class="doc-err">' + SW.esc(d.error) + '</span>' : '') +
      '</span>' +
      '<span class="badge ' + statusCls + '"><i class="shape ' + (d.status === 'Ready' ? 'sh-circle' : d.status === 'Failed' ? 'sh-octagon' : 'sh-diamond') + '" style="background:currentColor"></i>' + d.status.toUpperCase() + '</span>' +
      '<button class="btn btn-ghost btn-sm" data-inspect="' + d.id + '">Chunks</button>' +
      SW.gate('delete', '<button class="icon-btn" data-del="' + d.id + '" aria-label="Delete ' + SW.esc(d.name) + '">' + SW.icon('trash', 16) + '</button>') +
      '</div>';
  }
  function inspectDoc(id) {
    var d = SW.state.docs.filter(function (x) { return x.id === id; })[0];
    if (!d) return;
    var chunks = SW.state.chunks.filter(function (c) { return c.docId === id; });
    SW.modal({
      title: d.name + ' · ' + chunks.length + ' chunks',
      body: '<div class="chip-row" style="margin-bottom:12px"><span class="chip-mono">.' + d.ext + '</span>' +
        '<span class="chip-mono">' + SW.bytes(d.sizeBytes) + '</span>' +
        '<span class="chip-mono">' + (d.chars || 0) + ' chars extracted</span>' +
        '<span class="chip-mono">' + (d.pages || 1) + ' page(s)</span>' +
        '<span class="chip-mono">' + rag.CHUNK_CHARS + '-char chunks / ' + rag.OVERLAP + ' overlap</span></div>' +
        '<div class="chunk-list">' + (chunks.length ? chunks.map(function (c) {
          return '<details class="chunk"><summary><b class="mono">' + c.id + '</b>' +
            '<span class="faint"> p.' + c.page + (c.section ? ' · § ' + SW.esc(c.section) : '') + ' · ' + c.tokens.length + ' tokens</span></summary>' +
            '<div class="pre pre-wrap">' + SW.esc(c.text) + '</div></details>';
        }).join('') : '<p class="muted">This document produced no chunks.</p>') + '</div>' +
        '<p class="faint" style="margin-top:12px">' + rag.EMBED_LABEL + '</p>'
    });
  }
  function resultHTML(r) {
    var c = r.chunk;
    var snippet = rag.body(c).slice(0, 320);
    return '<div class="kb-result"><div class="kb-top">' +
      '<button class="source-chip" data-chunk="' + c.id + '" data-score="' + r.score + '">' + SW.icon('doc', 13) +
        SW.esc(c.docName) + ' · p.' + c.page + '<span class="sim">' + r.score.toFixed(3) + '</span></button>' +
      (c.section ? '<span class="chip-mono">§ ' + SW.esc(c.section) + '</span>' : '') +
      '<span class="chip-mono">' + c.id + '</span></div>' +
      '<div class="sim-bar"><i style="width:' + Math.min(100, Math.round(r.score * 100 / 0.7)) + '%"></i></div>' +
      '<p class="kb-snip">' + rag.highlight(snippet, r.terms) + '…</p>' +
      '<details class="kb-full"><summary>Show full chunk</summary><div class="pre pre-wrap">' + SW.esc(c.text) + '</div></details></div>';
  }

  function wireSearch(host, inputSel, outSel, statSel) {
    var input = host.querySelector(inputSel), out = host.querySelector(outSel);
    function run() {
      var q = input.value.trim();
      if (!q) {
        out.innerHTML = '<p class="muted">Type a question or keywords. Retrieval runs cosine similarity over every indexed chunk of your own documents.</p>';
        if (statSel) host.querySelector(statSel).textContent = '';
        return;
      }
      var t0 = performance.now();
      var res = rag.search(q, 5);
      var ms = (performance.now() - t0).toFixed(1);
      if (statSel) host.querySelector(statSel).textContent = res.length + ' of ' + SW.state.chunks.length + ' chunks above the ' + rag.SCORE_FLOOR + ' score floor · ' + ms + ' ms';
      out.innerHTML = res.length ? res.map(resultHTML).join('')
        : SW.emptyState('No supporting documentation found in the knowledge base',
            'Nothing scored above the similarity floor for “' + q + '”. Upload a relevant document or try different terms.');
    }
    input.addEventListener('input', run);
    out.addEventListener('click', function (e) {
      var c = e.target.closest('[data-chunk]');
      if (c) rag.openChunk(c.dataset.chunk, parseFloat(c.dataset.score));
    });
    run();
    return run;
  }

  function wireDocList(host, redraw) {
    host.addEventListener('click', function (e) {
      var ins = e.target.closest('[data-inspect]');
      if (ins) { inspectDoc(ins.dataset.inspect); return; }
      var del = e.target.closest('[data-del]');
      if (del && !del.disabled) {
        var d = SW.state.docs.filter(function (x) { return x.id === del.dataset.del; })[0];
        if (!d) return;
        SW.modal({
          title: 'Delete document?',
          body: '<p class="muted">“' + SW.esc(d.name) + '” and its ' + d.chunkIds.length +
            ' indexed chunks will be removed from the in-memory vector index. Counters and retrieval results update immediately.</p>',
          footer: '<button class="btn btn-ghost" data-close>Cancel</button>' +
            '<button class="btn btn-danger" id="confirmDel">Delete document</button>',
          onMount: function (m) {
            m.querySelector('#confirmDel').addEventListener('click', function () {
              rag.deleteDoc(d.id); SW.closeModal(); redraw();
            });
          }
        });
      }
    });
  }

  function wireDropzone(host, redraw) {
    var dz = host.querySelector('#dropzone');
    var input = host.querySelector('#fileInput');
    if (!dz || !input) return;
    if (!SW.can('upload')) return;
    ['dragenter', 'dragover'].forEach(function (t) {
      dz.addEventListener(t, function (e) { e.preventDefault(); dz.classList.add('hot'); });
    });
    ['dragleave', 'dragend'].forEach(function (t) {
      dz.addEventListener(t, function () { dz.classList.remove('hot'); });
    });
    dz.addEventListener('drop', function (e) {
      e.preventDefault(); dz.classList.remove('hot');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) rag.ingestFiles(e.dataTransfer.files);
    });
    dz.addEventListener('click', function (e) {
      if (e.target.closest('#browseBtn') || e.target === dz || e.target.closest('.dz-text')) input.click();
    });
    dz.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    input.addEventListener('change', function () {
      if (input.files && input.files.length) rag.ingestFiles(input.files);
      input.value = '';
    });
  }

  function dropzoneHTML() {
    var can = SW.can('upload');
    return '<div class="dropzone' + (can ? '' : ' disabled') + '" id="dropzone"' + (can ? ' tabindex="0" role="button" aria-label="Upload documents: drop files or press Enter to browse"' : '') + '>' +
      '<div class="dz-text">' + SW.icon('upload', 26) +
        '<h3>' + (can ? 'Drop documents here' : 'Uploading is disabled for the Viewer role') + '</h3>' +
        '<p>' + (can
          ? '.txt · .md · .pdf · .docx — max 25 MB. Files are parsed, chunked and indexed entirely in this browser tab; nothing is uploaded anywhere.'
          : SW.denyReason('upload')) + '</p>' +
        (can ? '<button class="btn btn-primary" id="browseBtn" type="button">' + SW.icon('doc', 15) + 'Browse files</button>' : '') +
      '</div>' +
      '<input type="file" id="fileInput" multiple accept=".txt,.md,.pdf,.docx,text/plain,text/markdown,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" hidden>' +
      '</div>';
  }

  /* ================= RAG Intelligence Center ================= */
  SW.route('rag', { title: 'RAG Intelligence', render: function (host) {
    var st = rag.stats();
    host.innerHTML = SW.head('RAG Intelligence Center',
      'Real client-side ingestion and retrieval — parsing, chunking, TF-IDF vectors and cosine search all run in this tab',
      '<span class="prov-tag prov-rag"><i></i>' + rag.EMBED_LABEL + '</span>') +
      '<div class="grid g4 mb" id="ragStats"></div>' +
      '<div class="grid g-1-2 mb">' +
        '<div class="card panel" style="min-width:0"><div class="card-head"><div><h3>Ingest documents</h3>' +
          '<div class="faint">SHA-256 duplicate check · extension allowlist · 25 MB cap</div></div></div>' +
          dropzoneHTML() +
          '<div id="activeStepper" style="margin-top:6px"></div>' +
          '<div class="hr"></div>' +
          '<div class="rag-diagram">' +
            ['Upload', 'Extract', 'Chunk', 'TF-IDF', 'Index', 'Retrieve'].map(function (b, i, arr) {
              return '<div class="rag-box"><b>' + b + '</b><span>' + ['File API', 'FileReader / pdf.js / JSZip', '800c/100o', 'idf + L2', 'in-memory', 'cosine'][i] + '</span></div>' +
                (i < arr.length - 1 ? '<span class="rag-arrow">' + SW.icon('arrow', 14) + '</span>' : '');
            }).join('') +
          '</div></div>' +
        '<div class="card panel" style="min-width:0"><div class="card-head"><div><h3>Ask the knowledge base</h3>' +
          '<div class="faint" id="kbStat"></div></div><span class="prov-tag prov-rag"><i></i>Top 5 chunks</span></div>' +
          '<div class="searchbox">' + SW.icon('search', 16) +
            '<input id="kbQuery" type="search" placeholder="e.g. encoded PowerShell policy, LSASS guidance, unsigned binary in Temp" aria-label="Search the knowledge base"></div>' +
          '<div id="kbOut" class="kb-out"></div></div>' +
      '</div>' +
      '<div class="card panel"><div class="card-head"><div><h3>Documents (<span id="docCount">' + st.docs + '</span>)</h3>' +
        '<div class="faint">Search, sort, inspect chunks or delete — every counter is computed live</div></div>' +
        '<div class="head-actions"><div class="searchbox" style="width:210px">' + SW.icon('search', 16) +
          '<input id="docSearch" type="search" placeholder="Filter documents…" aria-label="Filter documents"></div>' +
        '<select id="docSort" aria-label="Sort documents"><option value="added">Sort: newest</option><option value="name">Sort: name</option>' +
          '<option value="chunks">Sort: chunks ↓</option><option value="size">Sort: size ↓</option></select></div></div>' +
        '<div id="docList"></div></div>';

    var q = '', sort = 'added';
    function drawStats() {
      var s = rag.stats();
      host.querySelector('#ragStats').innerHTML = [
        ['Indexed documents', s.docs, s.ready + ' ready'],
        ['Vector chunks', s.chunks, rag.CHUNK_CHARS + '-char target'],
        ['Vocabulary terms', s.terms, 'idf computed across chunks'],
        ['Corpus size', SW.bytes(s.bytes), 'held in memory only']
      ].map(function (k) {
        return '<div class="kpi"><div class="k-label">' + k[0] + '</div><div class="k-value" style="font-size:28px">' + k[1] + '</div>' +
          '<div class="k-foot"><span>' + k[2] + '</span></div></div>';
      }).join('');
      var dc = host.querySelector('#docCount'); if (dc) dc.textContent = s.docs;
    }
    function drawDocs() {
      var list = SW.state.docs.filter(function (d) { return !q || d.name.toLowerCase().indexOf(q) >= 0; });
      list = list.slice().sort(function (a, b) {
        if (sort === 'name') return a.name.localeCompare(b.name);
        if (sort === 'chunks') return b.chunkIds.length - a.chunkIds.length;
        if (sort === 'size') return b.sizeBytes - a.sizeBytes;
        return new Date(b.addedAt) - new Date(a.addedAt);
      });
      host.querySelector('#docList').innerHTML = list.length ? list.map(docRowHTML).join('')
        : SW.emptyState('No documents match', q ? 'Nothing matches “' + q + '”.' : 'Upload a .txt, .md, .pdf or .docx file to build the index.');
      var active = SW.state.docs.filter(function (d) { return d.status !== 'Ready' && d.status !== 'Failed'; })[0];
      host.querySelector('#activeStepper').innerHTML = active
        ? '<div class="active-doc"><span class="mono">' + SW.esc(active.name) + '</span>' + stepperHTML(active.step, active.status) +
          '<div class="bar" style="margin-top:8px"><i style="width:' + active.progress + '%"></i></div></div>'
        : stepperHTML(SW.state.docs.length ? 6 : 0, 'Ready');
    }
    function redraw() { drawStats(); drawDocs(); if (runSearch) runSearch(); }
    host.querySelector('#docSearch').addEventListener('input', function () { q = this.value.trim().toLowerCase(); drawDocs(); });
    host.querySelector('#docSort').addEventListener('change', function () { sort = this.value; drawDocs(); });
    var runSearch = wireSearch(host, '#kbQuery', '#kbOut', '#kbStat');
    wireDocList(host, redraw);
    wireDropzone(host, redraw);
    redraw();

    SW.listen('sw:docupdate', function () {
      if (host.querySelector('#docList')) { drawStats(); drawDocs(); }
    });
  } });

  /* ================= Knowledge Base ================= */
  SW.route('knowledge-base', { title: 'Knowledge Base', render: function (host) {
    var st = rag.stats();
    host.innerHTML = SW.head('Knowledge Base',
      st.docs + ' documents · ' + st.chunks + ' chunks · retrieval returns real passages from documents you indexed in this session',
      '<span class="prov-tag prov-rag"><i></i>' + rag.EMBED_LABEL + '</span>' +
      '<a class="btn btn-ghost" href="#/rag">Upload documents</a>') +
      '<div class="card panel mb"><div class="card-head"><div><h3>Search indexed documents</h3>' +
        '<div class="faint" id="kbStat2"></div></div></div>' +
        '<div class="searchbox big">' + SW.icon('search', 18) +
        '<input id="kbQuery2" type="search" placeholder="Search your indexed documents…" aria-label="Search knowledge base"></div>' +
        '<div id="kbOut2" class="kb-out"></div></div>' +
      '<div class="card panel"><div class="card-head"><div><h3>Indexed documents</h3>' +
        '<div class="faint">Click “Chunks” to inspect exactly what was extracted and indexed</div></div></div>' +
        '<div id="docList2"></div></div>';

    function drawDocs() {
      host.querySelector('#docList2').innerHTML = SW.state.docs.length
        ? SW.state.docs.map(docRowHTML).join('')
        : SW.emptyState('The index is empty', 'Go to RAG Intelligence and upload a document to make retrieval possible.',
            '<a class="btn btn-primary" href="#/rag">Open RAG Intelligence</a>');
    }
    var runSearch = wireSearch(host, '#kbQuery2', '#kbOut2', '#kbStat2');
    wireDocList(host, function () { drawDocs(); runSearch(); });
    drawDocs();
    host.querySelector('#kbQuery2').focus();
    SW.listen('sw:docupdate', function () { if (host.querySelector('#docList2')) drawDocs(); });
  } });
})();
