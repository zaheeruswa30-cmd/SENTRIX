"""Engine + session factory."""
from __future__ import annotations

import json
from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import get_settings

_settings = get_settings()
_is_sqlite = _settings.DATABASE_URL.startswith("sqlite")

engine = create_engine(
    _settings.DATABASE_URL,
    pool_pre_ping=True,
    future=True,
    json_serializer=lambda obj: json.dumps(obj, default=str),  # datetimes in JSON evidence
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_fk(dbapi_conn, _):  # enforce FK constraints on SQLite
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
