/* SecureWatch AI — real client-side RAG: File API ingest, real text extraction
   (FileReader / pdf.js / JSZip), real chunking, TF-IDF vectors and cosine retrieval.
   Honest label: the embedding is a client-side TF-IDF vector, not a neural model. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var rag = (SW.rag = {});

  rag.EMBED_LABEL = 'Demo embedding: client-side TF-IDF (no external model)';
  rag.STAGES = ['Uploading', 'Extracting', 'Chunking', 'Embedding', 'Indexed', 'Ready'];
  rag.MAX_BYTES = 25 * 1024 * 1024;
  rag.ALLOWED = ['txt', 'md', 'pdf', 'docx'];
  rag.CHUNK_CHARS = 800;
  rag.OVERLAP = 100;
  rag.SCORE_FLOOR = 0.06;

  var STOP = ('a an and are as at be been but by can cannot could did do does for from had has have if in into is it its ' +
    'may might must no not of on or should so than that the their then there these this those to was were what when which ' +
    'while who will with within would you your our we be being all any each other such same only own too very s t just').split(' ');
  var STOPSET = {};
  STOP.forEach(function (w) { STOPSET[w] = 1; });

  rag.tokenize = function (text) {
    var raw = String(text).toLowerCase().match(/[a-z0-9][a-z0-9_\-\.\\\/]*/g) || [];
    var out = [];
    for (var i = 0; i < raw.length; i++) {
      var t = raw[i].replace(/^[\.\-_]+|[\.\-_]+$/g, '');
      if (t.length < 2 || t.length > 40) continue;
      if (STOPSET[t]) continue;
      out.push(t);
      // also index the bare filename/base of dotted or path-y tokens (e.g. powershell.exe -> powershell)
      if (t.indexOf('.') > 0 || t.indexOf('\\') > 0 || t.indexOf('/') > 0) {
        t.split(/[\.\\\/]+/).forEach(function (p) {
          if (p.length >= 3 && !STOPSET[p]) out.push(p);
        });
      }
    }
    return out;
  };

  /* ---------------- Index maths ---------------- */
  function tfMap(tokens) {
    var m = {};
    tokens.forEach(function (t) { m[t] = (m[t] || 0) + 1; });
    return m;
  }
  rag.buildIndex = function () {
    var chunks = SW.state.chunks;
    var N = chunks.length;
    var df = {};
    chunks.forEach(function (c) {
      c.tf = c.tf || tfMap(c.tokens);
      Object.keys(c.tf).forEach(function (t) { df[t] = (df[t] || 0) + 1; });
    });
    var idf = {};
    Object.keys(df).forEach(function (t) { idf[t] = Math.log((N + 1) / (df[t] + 1)) + 1; });
    rag.idf = idf; rag.docCount = N;
    chunks.forEach(function (c) { c.vec = rag.vectorize(c.tf); });
  };
  rag.vectorize = function (tf) {
    var v = {}, norm = 0;
    Object.keys(tf).forEach(function (t) {
      var w = (1 + Math.log(tf[t])) * (rag.idf && rag.idf[t] !== undefined ? rag.idf[t] : 1);
      v[t] = w; norm += w * w;
    });
    norm = Math.sqrt(norm) || 1;
    Object.keys(v).forEach(function (t) { v[t] = v[t] / norm; });
    return v;
  };
  rag.cosine = function (a, b) {
    var s = 0, keys = Object.keys(a);
    if (keys.length > Object.keys(b).length) { var tmp = a; a = b; b = tmp; keys = Object.keys(a); }
    for (var i = 0; i < keys.length; i++) { var k = keys[i]; if (b[k] !== undefined) s += a[k] * b[k]; }
    return s;
  };
  rag.search = function (query, k, floor) {
    var tokens = rag.tokenize(query);
    if (!tokens.length || !SW.state.chunks.length) return [];
    var qv = rag.vectorize(tfMap(tokens));
    var f = floor === undefined ? rag.SCORE_FLOOR : floor;
    var scored = SW.state.chunks.map(function (c) {
      return { chunk: c, score: rag.cosine(qv, c.vec || {}) };
    }).filter(function (r) { return r.score > f; });
    scored.sort(function (a, b) { return b.score - a.score; });
    return scored.slice(0, k || 5).map(function (r) {
      r.terms = tokens.filter(function (t) { return (r.chunk.tf || {})[t]; });
      return r;
    });
  };

  /* ---------------- Chunking ---------------- */
  /* Splits a page/section of text into ~800-char chunks with 100-char overlap,
     preferring heading and paragraph boundaries. */
  rag.chunkText = function (text, docName, page, sectionHint) {
    var blocks = String(text).split(/\n{2,}|\n(?=#{1,6}\s)|\n(?=[A-Z][A-Z \-]{6,}$)/m)
      .map(function (b) { return b.trim(); }).filter(Boolean);
    var out = [], buf = '', section = sectionHint || '', bufSection = section;
    function flush() {
      if (!buf.trim()) return;
      out.push({ text: buf.trim(), section: bufSection });
      buf = buf.length > rag.OVERLAP ? buf.slice(-rag.OVERLAP) : buf;
      bufSection = section;
    }
    blocks.forEach(function (b) {
      var head = b.match(/^#{1,6}\s+(.+)$/m) || b.match(/^(\d+\.\s+[A-Z][^\n]{3,60})$/m) || b.match(/^([A-Z][A-Z \-]{5,60})$/m);
      if (head) { section = head[1].trim().slice(0, 60); if (!buf.trim()) bufSection = section; }
      if (buf.length + b.length + 2 > rag.CHUNK_CHARS && buf.trim()) flush();
      if (b.length > rag.CHUNK_CHARS) {
        // hard-split an oversized paragraph on sentence boundaries
        var sentences = b.split(/(?<=[.!?])\s+/);
        sentences.forEach(function (s) {
          if (buf.length + s.length + 1 > rag.CHUNK_CHARS && buf.trim()) flush();
          buf += (buf ? ' ' : '') + s;
        });
      } else {
        buf += (buf ? '\n\n' : '') + b;
      }
    });
    if (buf.trim()) out.push({ text: buf.trim(), section: bufSection });
    return out.map(function (c) {
      var crumb = '[doc: ' + docName + (page ? ' · p.' + page : '') + ']';
      return { text: crumb + ' ' + c.text, section: c.section, page: page || 1, crumb: crumb };
    });
  };

  /* ---------------- Hashing (real SHA-256 over the ArrayBuffer) ---------------- */
  rag.hash = function (buf) {
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
      return crypto.subtle.digest('SHA-256', buf).then(function (d) {
        return Array.from(new Uint8Array(d)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      });
    }
    // Deterministic non-cryptographic fallback if SubtleCrypto is unavailable.
    var view = new Uint8Array(buf), h1 = 0x811c9dc5, h2 = 0x01000193;
    for (var i = 0; i < view.length; i++) { h1 = (h1 ^ view[i]) * 16777619 >>> 0; h2 = (h2 + view[i] * 31) >>> 0; }
    return Promise.resolve('fnv-' + h1.toString(16) + h2.toString(16) + '-' + view.length);
  };

  /* ---------------- CDN loaders (graceful failure) ---------------- */
  var loaded = {};
  function loadScript(url, key) {
    if (loaded[key]) return loaded[key];
    loaded[key] = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = url; s.async = true;
      s.onload = function () { resolve(true); };
      s.onerror = function () { loaded[key] = null; reject(new Error('Could not load ' + key + ' from CDN')); };
      document.head.appendChild(s);
    });
    return loaded[key];
  }

  /* ---------------- Extraction ---------------- */
  function readText(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () { resolve(String(fr.result)); };
      fr.onerror = function () { reject(new Error('FileReader could not read this file')); };
      fr.readAsText(file);
    });
  }
  function extractPdf(buf, onPage) {
    return loadScript('https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js', 'pdfjs')
      .then(function () {
        var lib = window.pdfjsLib;
        if (!lib) throw new Error('pdf.js loaded but pdfjsLib was not exposed');
        lib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
        return lib.getDocument({ data: buf }).promise;
      })
      .then(function (pdf) {
        var pages = [];
        function nextPage(i) {
          if (i > pdf.numPages) return pages;
          return pdf.getPage(i).then(function (p) { return p.getTextContent(); }).then(function (tc) {
            pages.push(tc.items.map(function (it) { return it.str; }).join(' ').replace(/\s{2,}/g, ' '));
            if (onPage) onPage(i, pdf.numPages);
            return nextPage(i + 1);
          });
        }
        return nextPage(1);
      });
  }
  function extractDocx(buf) {
    return loadScript('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js', 'jszip')
      .then(function () {
        if (!window.JSZip) throw new Error('JSZip loaded but was not exposed');
        return window.JSZip.loadAsync(buf);
      })
      .then(function (zip) {
        var f = zip.file('word/document.xml');
        if (!f) throw new Error('word/document.xml missing — not a valid .docx');
        return f.async('string');
      })
      .then(function (xml) {
        var paras = xml.split(/<\/w:p>/).map(function (p) {
          var txt = (p.match(/<w:t[^>]*>([\s\S]*?)<\/w:t>/g) || []).map(function (t) {
            return t.replace(/<[^>]+>/g, '');
          }).join('');
          var isHeading = /w:val="Heading/i.test(p);
          txt = txt.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
          return txt.trim() ? (isHeading ? '## ' + txt.trim() : txt.trim()) : '';
        }).filter(Boolean);
        if (!paras.length) throw new Error('No paragraph text found in the .docx');
        return [paras.join('\n\n')];
      });
  }

  /* ---------------- Ingest ---------------- */
  rag.stats = function () {
    var ready = SW.state.docs.filter(function (d) { return d.status === 'Ready'; });
    return {
      docs: SW.state.docs.length,
      ready: ready.length,
      chunks: SW.state.chunks.length,
      terms: rag.idf ? Object.keys(rag.idf).length : 0,
      bytes: SW.state.docs.reduce(function (a, d) { return a + (d.sizeBytes || 0); }, 0)
    };
  };

  function emit(doc) {
    document.dispatchEvent(new CustomEvent('sw:docupdate', { detail: doc }));
  }
  function fail(doc, msg) {
    doc.status = 'Failed'; doc.error = msg; doc.progress = 100; doc.step = doc.step || 1;
    emit(doc);
    SW.toast('Ingest failed: ' + doc.name, msg, 'crit');
  }
  function tick(ms) { return new Promise(function (r) { setTimeout(r, SW.reduced ? 0 : ms); }); }

  /* Ingests one real File through the full pipeline. Returns a promise for the doc record. */
  rag.ingestFile = function (file) {
    var ext = (file.name.split('.').pop() || '').toLowerCase();
    var doc = {
      id: SW.uid('doc'), name: file.name, ext: ext, kind: 'user', sizeBytes: file.size,
      status: 'Uploading', step: 0, progress: 4, chunkIds: [], pages: 0, addedAt: new Date(), error: ''
    };

    if (rag.ALLOWED.indexOf(ext) < 0) {
      SW.toast('Rejected: ' + file.name, 'Unsupported file type ".' + ext + '". Allowed: .txt, .md, .pdf, .docx', 'crit');
      return Promise.resolve(null);
    }
    if (file.size > rag.MAX_BYTES) {
      SW.toast('Rejected: ' + file.name, 'File is ' + SW.bytes(file.size) + ' — the 25 MB limit applies to every upload.', 'crit');
      return Promise.resolve(null);
    }
    if (file.size === 0) {
      SW.toast('Rejected: ' + file.name, 'File is empty (0 bytes).', 'crit');
      return Promise.resolve(null);
    }

    SW.state.docs.unshift(doc);
    emit(doc);

    return file.arrayBuffer().then(function (buf) {
      doc.progress = 18; emit(doc);
      return rag.hash(buf).then(function (hash) {
        var dupe = SW.state.docs.filter(function (d) { return d !== doc && d.hash === hash; })[0];
        if (dupe) {
          SW.state.docs = SW.state.docs.filter(function (d) { return d !== doc; });
          document.dispatchEvent(new CustomEvent('sw:docupdate', { detail: null }));
          SW.toast('Duplicate rejected', file.name + ' has the same SHA-256 as "' + dupe.name + '" (' + hash.slice(0, 12) + '…)', 'warn');
          return null;
        }
        doc.hash = hash; doc.progress = 28; emit(doc);
        return tick(140).then(function () {
          doc.status = 'Extracting'; doc.step = 1; doc.progress = 34; emit(doc);
          if (ext === 'txt' || ext === 'md') {
            return readText(file).then(function (t) { return [t]; });
          }
          if (ext === 'pdf') {
            return extractPdf(buf, function (i, total) {
              doc.progress = 34 + Math.round((i / total) * 22);
              doc.pages = total; emit(doc);
            });
          }
          return extractDocx(buf);
        }).then(function (pages) {
          var total = pages.join('').trim();
          if (!total) throw new Error('No extractable text found in this file');
          doc.pages = pages.length;
          doc.chars = total.length;
          doc.progress = 58; doc.status = 'Chunking'; doc.step = 2; emit(doc);
          return tick(160).then(function () {
            var recs = [];
            pages.forEach(function (pageText, i) {
              rag.chunkText(pageText, doc.name, pages.length > 1 ? i + 1 : 1).forEach(function (c) {
                recs.push(c);
              });
            });
            if (!recs.length) throw new Error('Chunking produced no usable text');
            doc.progress = 68; doc.status = 'Embedding'; doc.step = 3; emit(doc);
            return tick(160).then(function () {
              recs.forEach(function (c, i) {
                var id = doc.id + '#c' + (i + 1);
                var tokens = rag.tokenize(c.text);
                SW.state.chunks.push({
                  id: id, docId: doc.id, docName: doc.name, page: c.page,
                  section: c.section || '', text: c.text, crumb: c.crumb || '', tokens: tokens, kind: doc.kind
                });
                doc.chunkIds.push(id);
                doc.progress = 68 + Math.round(((i + 1) / recs.length) * 20);
              });
              emit(doc);
              rag.buildIndex();
              doc.status = 'Indexed'; doc.step = 4; doc.progress = 94; emit(doc);
              return tick(140);
            });
          });
        }).then(function () {
          if (doc.status === 'Failed') return null;
          doc.status = 'Ready'; doc.step = 5; doc.progress = 100; emit(doc);
          SW.toast('Indexed ' + doc.name, doc.chunkIds.length + ' chunks · ' + (doc.pages || 1) + ' page(s) · retrievable now', 'ok');
          return doc;
        });
      });
    }).catch(function (err) {
      fail(doc, err && err.message ? err.message : 'Unknown extraction error');
      return null;
    });
  };

  rag.ingestFiles = function (fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    return files.reduce(function (p, f) {
      return p.then(function () { return rag.ingestFile(f); });
    }, Promise.resolve());
  };

  rag.deleteDoc = function (docId) {
    var doc = SW.state.docs.filter(function (d) { return d.id === docId; })[0];
    if (!doc) return;
    SW.state.docs = SW.state.docs.filter(function (d) { return d.id !== docId; });
    SW.state.chunks = SW.state.chunks.filter(function (c) { return c.docId !== docId; });
    rag.buildIndex();
    document.dispatchEvent(new CustomEvent('sw:docupdate', { detail: null }));
    SW.toast('Document removed', doc.name + ' and its ' + doc.chunkIds.length + ' chunks were deleted from the index.');
  };

  rag.chunkById = function (id) {
    return SW.state.chunks.filter(function (c) { return c.id === id; })[0] || null;
  };
  rag.openChunk = function (id, score) {
    var c = rag.chunkById(id);
    if (!c) { SW.toast('Chunk unavailable', 'That chunk is no longer in the index.'); return; }
    SW.modal({
      title: c.docName + (c.page ? ' · page ' + c.page : ''),
      body: '<div class="chip-row" style="margin-bottom:12px">' +
        '<span class="prov-tag prov-rag"><i></i>Retrieved document</span>' +
        '<span class="chip-mono">' + SW.esc(c.id) + '</span>' +
        (score !== undefined ? '<span class="chip-mono">similarity ' + score.toFixed(3) + '</span>' : '') +
        (c.section ? '<span class="chip-mono">§ ' + SW.esc(c.section) + '</span>' : '') + '</div>' +
        '<div class="pre pre-wrap">' + SW.esc(c.text) + '</div>' +
        '<p class="faint" style="margin-top:12px">' + rag.EMBED_LABEL + ' · ' + c.tokens.length + ' indexed tokens.</p>'
    });
  };
  /* Highlights matched query terms inside a chunk snippet. */
  /* Chunk text without the leading provenance breadcrumb — for quoting in prose. */
  rag.body = function (c) {
    return String((c && c.text) || '').replace(/^\[doc:[^\]]*\]\s*/, '').trim();
  };

  rag.highlight = function (text, terms) {
    var out = SW.esc(text);
    (terms || []).slice(0, 12).forEach(function (t) {
      if (t.length < 3) return;
      var re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
      out = out.replace(re, '<mark>$1</mark>');
    });
    return out;
  };

  /* ---------------- Seeded demo documents ---------------- */
  SW.initRag = function () {
    if (SW.state.docs.length) return;
    SW.seed.docs.forEach(function (d) {
      var doc = {
        id: SW.uid('doc'), name: d.name, ext: d.ext, kind: 'demo', sizeBytes: d.text.length,
        status: 'Ready', step: 5, progress: 100, chunkIds: [], pages: 1, chars: d.text.length,
        addedAt: new Date(Date.now() - 3600000), hash: 'seed-' + d.name, error: ''
      };
      rag.chunkText(d.text, d.name, 1).forEach(function (c, i) {
        var id = doc.id + '#c' + (i + 1);
        SW.state.chunks.push({
          id: id, docId: doc.id, docName: doc.name, page: c.page, section: c.section || '',
          text: c.text, crumb: c.crumb || '', tokens: rag.tokenize(c.text), kind: 'demo'
        });
        doc.chunkIds.push(id);
      });
      SW.state.docs.push(doc);
    });
    rag.buildIndex();
  };
})();
