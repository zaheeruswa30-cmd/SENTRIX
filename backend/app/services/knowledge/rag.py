"""Tenant-scoped knowledge base for RAG: markdown-aware chunking + BM25 lexical retrieval.

Retrieval always filters by ``tenant_id`` so one tenant can never read another tenant's chunks.
A vector store (Qdrant, see requirements-ml.txt) can be added behind ``search`` later without
changing callers.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import Document, DocumentChunk

SEED_DIR = Path(__file__).resolve().parents[2] / "knowledge_seed"
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_\-]*")
_STOP = set("""a an the and or of to in on for is are was were be been it its this that with as by at from
not no can does do any into than then so if what which who how why when there their these those""".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


def chunk_markdown(text: str, max_words: int = 180) -> list[tuple[str, str]]:
    """Split on headings, then on paragraphs to keep chunks short. Returns (section, text)."""
    title, section, buf, out = "", "", [], []

    def flush():
        body = "\n".join(buf).strip()
        if body:
            words = body.split()
            for i in range(0, len(words), max_words):
                out.append(((f"{title} › {section}" if section and title else section or title)[:300],
                            " ".join(words[i:i + max_words])))
        buf.clear()

    for line in text.splitlines():
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            flush()
            if len(m.group(1)) == 1:
                title, section = m.group(2).strip(), ""
            else:
                section = m.group(2).strip()
        else:
            buf.append(line)
    flush()
    return out


def add_document(db: Session, *, tenant_id: str, title: str, text: str, doc_type: str = "other",
                 source: str = "upload", ref_type: str | None = None, ref_id: str | None = None,
                 created_by: str | None = None, replace_ref: bool = False) -> Document:
    sha = hashlib.sha256(text.encode()).hexdigest()
    if replace_ref and ref_type and ref_id:
        for old in db.scalars(select(Document).where(Document.tenant_id == tenant_id, Document.ref_type == ref_type,
                                                     Document.ref_id == ref_id)):
            db.delete(old)
        db.flush()
    existing = db.scalar(select(Document).where(Document.tenant_id == tenant_id, Document.sha256 == sha))
    if existing:
        return existing
    doc = Document(tenant_id=tenant_id, title=title[:300], doc_type=doc_type, source=source, sha256=sha,
                   ref_type=ref_type, ref_id=ref_id, created_by=created_by, status="ready")
    db.add(doc)
    db.flush()
    chunks = chunk_markdown(text)
    for i, (section, body) in enumerate(chunks):
        db.add(DocumentChunk(tenant_id=tenant_id, document_id=doc.id, chunk_index=i, section=section, text=body,
                             token_count=len(tokenize(body))))
    doc.chunk_count = len(chunks)
    db.flush()
    return doc


def seed_tenant_knowledge(db: Session, tenant_id: str) -> int:
    n = 0
    for path in sorted(SEED_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = text.splitlines()[0].lstrip("# ").strip() if text else path.stem
        before = db.scalar(select(Document.id).where(Document.tenant_id == tenant_id,
                                                     Document.sha256 == hashlib.sha256(text.encode()).hexdigest()))
        if not before:
            add_document(db, tenant_id=tenant_id, title=title, text=text, doc_type="email_security",
                         source="sentrix_seed")
            n += 1
    return n


def search(db: Session, tenant_id: str, query: str, k: int = 5, doc_types: list[str] | None = None,
           ref_id: str | None = None) -> list[dict]:
    """BM25 over the tenant's chunks. Returns evidence-linked hits."""
    q = tokenize(query)
    if not q:
        return []
    stmt = select(DocumentChunk, Document).join(Document, Document.id == DocumentChunk.document_id).where(
        DocumentChunk.tenant_id == tenant_id, Document.tenant_id == tenant_id)
    if doc_types:
        stmt = stmt.where(Document.doc_type.in_(doc_types))
    rows = db.execute(stmt).all()
    if not rows:
        return []
    docs_tokens = [tokenize(c.section + " " + c.text) for c, _ in rows]
    N = len(rows)
    avgdl = sum(len(t) for t in docs_tokens) / N or 1
    df = Counter()
    for toks in docs_tokens:
        df.update(set(toks))
    k1, b = 1.4, 0.75
    scored = []
    for (chunk, doc), toks in zip(rows, docs_tokens):
        tf = Counter(toks)
        s = 0.0
        for term in set(q):
            if term not in tf:
                continue
            idf = math.log(1 + (N - df[term] + 0.5) / (df[term] + 0.5))
            s += idf * tf[term] * (k1 + 1) / (tf[term] + k1 * (1 - b + b * len(toks) / avgdl))
        if ref_id and doc.ref_id == ref_id:
            s *= 1.5
        if s > 0:
            scored.append((s, chunk, doc))
    scored.sort(key=lambda x: -x[0])
    return [{"chunk_id": c.id, "document_id": d.id, "document_title": d.title, "doc_type": d.doc_type,
             "section": c.section, "text": c.text, "score": round(s, 3), "ref_type": d.ref_type, "ref_id": d.ref_id,
             "citation": f"{d.title}" + (f" › {c.section.split(' › ')[-1]}" if c.section else "")}
            for s, c, d in scored[:k]]
