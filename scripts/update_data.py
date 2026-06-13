"""
update_data.py — pull fresh data from all available connectors.

Usage:
    python scripts/update_data.py
    python scripts/update_data.py --connector attack        # single connector
    python scripts/update_data.py --connector misp_galaxy
"""

import argparse
import sys
from pathlib import Path

# Make sure repo root is on the path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv()

from core.db import init_db, get_session
from core.ingest.attack import AttackConnector
from core.ingest.ctid_nist80053 import CtidNist80053Connector
from core.ingest.misp_galaxy import MispGalaxyConnector
from core.ingest.malpedia import MalpediaConnector
from core.ingest.mandiant import MandiantConnector

# NOTE: order matters. ctid_nist80053 joins against Technique rows and
# must run after attack — see core/ingest/README.md "Ordering dependencies".
ALL_CONNECTORS = {
    "attack": AttackConnector(),
    "ctid_nist80053": CtidNist80053Connector(),
    "misp_galaxy": MispGalaxyConnector(),
    "malpedia": MalpediaConnector(),
    "mandiant": MandiantConnector(),
}


def main():
    parser = argparse.ArgumentParser(description="cti-stitcher data sync")
    parser.add_argument("--connector", choices=list(ALL_CONNECTORS.keys()),
                        help="Run a single connector instead of all")
    args = parser.parse_args()

    init_db()

    with get_session() as session:
        connectors = (
            {args.connector: ALL_CONNECTORS[args.connector]}
            if args.connector
            else ALL_CONNECTORS
        )

        for name, connector in connectors.items():
            print(f"\n{'='*50}")
            print(f"Connector: {name}")
            if not connector.is_available():
                print(f"  SKIPPED — not configured (set credentials in .env)")
                continue
            log = connector.sync(session)
            print(f"  Status: {log.status} | Records: {log.records_updated}")
            if log.message:
                print(f"  Message: {log.message}")

    print(f"\n{'='*50}")
    print("Sync complete. Start the explorer with: python -m explorer")


if __name__ == "__main__":
    main()
