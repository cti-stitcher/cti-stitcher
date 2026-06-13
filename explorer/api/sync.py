"""
/api/sync — connector status and data refresh endpoints.
"""

import os
from datetime import datetime
from fastapi import APIRouter, Request
from sqlalchemy.orm import Session

from core.models import SyncLog
from core.ingest.attack import AttackConnector
from core.ingest.ctid_nist80053 import CtidNist80053Connector
from core.ingest.misp_galaxy import MispGalaxyConnector
from core.ingest.malpedia import MalpediaConnector
from core.ingest.mandiant import MandiantConnector

router = APIRouter(prefix="/api/sync", tags=["sync"])

# NOTE: order matters. ctid_nist80053 joins against Technique rows and
# must run after attack — see core/ingest/README.md "Ordering dependencies".
ALL_CONNECTORS = [
    AttackConnector(),
    CtidNist80053Connector(),
    MispGalaxyConnector(),
    MalpediaConnector(),
    MandiantConnector(),
]


@router.get("/status")
def sync_status(request: Request):
    """Return last sync time and status for each connector."""
    db: Session = request.app.state.db_session

    out = []
    for connector in ALL_CONNECTORS:
        last = (
            db.query(SyncLog)
            .filter_by(connector=connector.name)
            .order_by(SyncLog.run_at.desc())
            .first()
        )
        out.append({
            "connector": connector.name,
            "requires_auth": connector.requires_auth,
            "available": connector.is_available(),
            "last_run": last.run_at.isoformat() if last else None,
            "last_status": last.status if last else None,
            "last_records_updated": last.records_updated if last else None,
        })

    return out


@router.post("")
def run_sync(request: Request):
    """
    Trigger a full data sync across all available connectors.
    Runs synchronously — may take a minute on first run.
    After sync, rebuilds the resolution index.
    """
    db: Session = request.app.state.db_session
    results = []

    for connector in ALL_CONNECTORS:
        log = connector.sync(db)
        results.append({
            "connector": connector.name,
            "status": log.status,
            "records_updated": log.records_updated,
            "message": log.message,
        })

    # Rebuild resolution index after sync
    request.app.state.resolver.rebuild()

    return {"synced_at": datetime.utcnow().isoformat(), "results": results}


@router.get("/connectors")
def list_connectors():
    """Return connector configuration status."""
    return [
        {
            "connector": c.name,
            "requires_auth": c.requires_auth,
            "available": c.is_available(),
            "env_vars": _env_vars_for(c.name),
        }
        for c in ALL_CONNECTORS
    ]


def _env_vars_for(name: str) -> list[str]:
    return {
        "malpedia": ["MALPEDIA_API_KEY"],
        "mandiant": ["MANDIANT_API_KEY", "MANDIANT_API_SECRET"],
    }.get(name, [])
