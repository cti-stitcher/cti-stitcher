"""
BaseConnector — every data source implements this interface.

To add a new connector:
1. Create a new file in core/ingest/ (e.g. crowdstrike.py)
2. Subclass BaseConnector
3. Implement is_available() and run(session)
4. Register it in core/ingest/registry.py

The run() method is responsible for writing to the database directly
via the provided SQLAlchemy session. It should be idempotent — safe
to run multiple times without creating duplicates.
"""

import re
from abc import ABC, abstractmethod
from datetime import datetime

from sqlalchemy.orm import Session

from core.models import Alias, SyncLog


class BaseConnector(ABC):
    # Human-readable name shown in the UI and sync log
    name: str = "base"
    # Whether this connector requires credentials to run
    requires_auth: bool = False

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if this connector has everything it needs to run.
        For connectors that need an API key, check that the key is set.
        For connectors that are always available, return True.
        """
        ...

    @abstractmethod
    def run(self, session: Session) -> int:
        """
        Pull data from the source and write it to the database.
        Returns the number of records created or updated.
        Raise an exception on unrecoverable failure.
        """
        ...

    def sync(self, session: Session) -> SyncLog:
        """
        Wrapper that calls run() and writes a SyncLog entry regardless of outcome.
        Call this instead of run() directly.
        """
        log = SyncLog(connector=self.name, run_at=datetime.utcnow())
        try:
            if not self.is_available():
                log.status = "skipped"
                log.message = "Connector not configured (missing credentials)"
                log.records_updated = 0
            else:
                count = self.run(session)
                session.commit()
                log.status = "success"
                log.records_updated = count
        except Exception as exc:
            session.rollback()
            log.status = "failed"
            log.message = str(exc)
            log.records_updated = 0
            print(f"[{self.name}] ERROR: {exc}")

        session.add(log)
        session.commit()
        return log


def normalize_alias(name: str) -> str:
    """
    Normalize an actor name for consistent lookup.
    Lowercases, strips whitespace and common punctuation.
    Single source of truth — resolution.py imports this directly.
    """
    name = name.lower().strip()
    name = re.sub(r"[\s\-_\.]+", " ", name)   # collapse separators to single space
    name = re.sub(r"[^a-z0-9 ]", "", name)    # strip everything else
    return name.strip()


def find_actor_by_names(session: Session, names: list[str]) -> int | None:
    """
    Try to match any of the provided names to an existing actor via the alias
    table. Returns the actor DB id or None. Used by multiple connectors to
    avoid creating duplicate actor rows.
    """
    for name in names:
        norm = normalize_alias(name)
        alias_row = session.query(Alias).filter_by(alias_normalized=norm).first()
        if alias_row:
            return alias_row.actor_id
    return None


def truncate(text: str, max_len: int = 2000) -> str:
    """Trim text to max_len characters. Safe to call on None/empty strings."""
    return text[:max_len] if text else ""


# Rough sector keywords → normalized sector label.
# Used by attack.py (free-text description extraction) and misp_galaxy.py
# (structured cfr-target-category field). Single source of truth.
SECTOR_KEYWORDS: dict[str, str] = {
    "financial": "Financial Services",
    "banking": "Financial Services",
    "government": "Government",
    "defence": "Defense",
    "defense": "Defense",
    "military": "Defense",
    "healthcare": "Healthcare",
    "health": "Healthcare",
    "energy": "Energy",
    "oil": "Energy",
    "gas": "Energy",
    "technology": "Technology",
    "telecom": "Telecommunications",
    "media": "Media",
    "education": "Education",
    "aerospace": "Aerospace",
    "transportation": "Transportation",
    "retail": "Retail",
    "manufacturing": "Manufacturing",
    "pharmaceutical": "Pharmaceutical",
    "critical infrastructure": "Critical Infrastructure",
}
