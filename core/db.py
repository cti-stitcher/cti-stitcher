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
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    """
    Return a new database session.
    Caller is responsible for closing it (use as context manager).
    """
    return SessionLocal()
