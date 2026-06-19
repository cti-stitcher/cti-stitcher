"""
Database engine and session management.
The SQLite file lives at data/cti-stitcher.db by default,
configurable via the DB_PATH environment variable.
"""

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from core.models import Base

# Default DB path: <repo root>/data/cti-stitcher.db
_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cti-stitcher.db"
DB_PATH = Path(os.getenv("DB_PATH", str(_DEFAULT_DB_PATH)))


def get_engine():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(
        f"sqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
        echo=False,
    )


engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=True, autocommit=False)


def init_db() -> None:
    """Create all tables if they don't exist, then apply incremental migrations."""
    Base.metadata.create_all(bind=engine)
    _migrate(engine)


def _migrate(engine) -> None:
    """
    Safe incremental migrations for SQLite.
    SQLite's ALTER TABLE supports ADD COLUMN only — no drop/rename.
    Each migration is idempotent: check PRAGMA table_info before applying.
    """
    with engine.connect() as conn:
        # v5: add procedure column to actor_techniques
        cols = {row[1] for row in conn.execute(
            __import__("sqlalchemy").text("PRAGMA table_info(actor_techniques)")
        )}
        if "procedure" not in cols:
            conn.execute(__import__("sqlalchemy").text(
                "ALTER TABLE actor_techniques ADD COLUMN procedure TEXT"
            ))
            conn.commit()
            print("[db] Migration applied: actor_techniques.procedure column added")


def get_session() -> Session:
    """
    Return a new database session.
    Caller is responsible for closing it (use as context manager).
    """
    return SessionLocal()
