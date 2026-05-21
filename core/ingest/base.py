"""
BaseConnector — every data source implements this interface.

To add a new connector:
1. Create a new file in core/ingest/ (e.g. crowdstrike.py)
2. Subclass BaseConnector
3. Implement is_available() and run(session)
4. Register it in scripts/update_data.py

The run() method is responsible for writing to the database directly
via the provided SQLAlchemy session. It should be idempotent — safe
to run multiple times without creating duplicates.
"""

from abc import ABC, abstractmethod
from datetime import datetime

from sqlalchemy.orm import Session

from core.models import SyncLog


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
    Keep this in sync with resolution.py.
    """
    import re
    name = name.lower().strip()
    name = re.sub(r"[\s\-_\.]+", " ", name)   # collapse separators to single space
    name = re.sub(r"[^a-z0-9 ]", "", name)    # strip everything else
    return name.strip()
