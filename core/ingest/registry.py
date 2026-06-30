"""
Connector registry — the single authoritative list of all data sources.

Import ALL_CONNECTORS from here in both scripts/update_data.py and
explorer/api/sync.py so a new connector only needs to be added once.

Ordering constraint: attack must run first. ctid_nist80053 and d3fend
join against Technique rows created by attack and will silently skip
mappings if attack has not yet populated the techniques table.
"""

from core.ingest.attack import AttackConnector
from core.ingest.ctid_nist80053 import CtidNist80053Connector
from core.ingest.d3fend import D3FendConnector
from core.ingest.misp_galaxy import MispGalaxyConnector
from core.ingest.malpedia import MalpediaConnector
from core.ingest.mandiant import MandiantConnector
from core.ingest.base import BaseConnector

ALL_CONNECTORS: list[BaseConnector] = [
    AttackConnector(),
    CtidNist80053Connector(),
    D3FendConnector(),
    MispGalaxyConnector(),
    MalpediaConnector(),
    MandiantConnector(),
]
