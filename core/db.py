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
    sa = __import__("sqlalchemy")

    with engine.connect() as conn:
        # v5: add procedure column to actor_techniques
        cols = {row[1] for row in conn.execute(
            sa.text("PRAGMA table_info(actor_techniques)")
        )}
        if "procedure" not in cols:
            conn.execute(sa.text(
                "ALTER TABLE actor_techniques ADD COLUMN procedure TEXT"
            ))
            conn.commit()
            print("[db] Migration applied: actor_techniques.procedure column added")

        # v6: migrate d3fend_posture — replace boolean 'implemented' with string 'status'
        # SQLite can't drop columns, so we recreate the table when 'implemented' is still present.
        d3_cols = {row[1] for row in conn.execute(
            sa.text("PRAGMA table_info(d3fend_posture)")
        )}
        if "implemented" in d3_cols:
            # Recreate table without the old boolean column
            conn.execute(sa.text("""
                CREATE TABLE d3fend_posture_new (
                    id INTEGER PRIMARY KEY,
                    d3fend_technique_id INTEGER NOT NULL UNIQUE
                        REFERENCES d3fend_techniques(id),
                    status TEXT NOT NULL DEFAULT 'not_deployed'
                )
            """))
            # Carry forward existing posture — implemented=1 → deployed, else not_deployed
            existing_status = "'not_deployed'" if "status" not in d3_cols else \
                "CASE WHEN status IS NOT NULL AND status != 'not_deployed' THEN status " \
                "WHEN implemented = 1 THEN 'deployed' ELSE 'not_deployed' END"
            conn.execute(sa.text(f"""
                INSERT INTO d3fend_posture_new (id, d3fend_technique_id, status)
                SELECT id, d3fend_technique_id, {existing_status}
                FROM d3fend_posture
            """))
            conn.execute(sa.text("DROP TABLE d3fend_posture"))
            conn.execute(sa.text("ALTER TABLE d3fend_posture_new RENAME TO d3fend_posture"))
            conn.commit()
            print("[db] Migration applied: d3fend_posture recreated without 'implemented' column")


def get_session() -> Session:
    """
    Return a new database session.
    Caller is responsible for closing it (use as context manager).
    """
    return SessionLocal()
