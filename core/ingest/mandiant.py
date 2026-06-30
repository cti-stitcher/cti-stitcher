"""
Mandiant / Google Threat Intelligence connector.

Requires Mandiant Advantage API credentials (free tier available):
https://www.mandiant.com/advantage/threat-intelligence/free-version

Set MANDIANT_API_KEY and MANDIANT_API_SECRET in your .env file to enable.
Gracefully skipped if credentials are not set.

Note: Much of Mandiant's APT naming is already covered via MISP galaxy clusters.
This connector pulls additional detail and fresher data where available.
"""

import os
import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector, find_actor_by_names, normalize_alias, truncate
from core.models import Actor, Alias

MANDIANT_TOKEN_URL = "https://api.intelligence.mandiant.com/token"
MANDIANT_ACTORS_URL = "https://api.intelligence.mandiant.com/v4/actor"
SOURCE = "mandiant"


class MandiantConnector(BaseConnector):
    name = "mandiant"
    requires_auth = True

    def is_available(self) -> bool:
        return bool(os.getenv("MANDIANT_API_KEY") and os.getenv("MANDIANT_API_SECRET"))

    def run(self, session: Session) -> int:
        token = self._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "X-App-Name": "cti-stitcher",
        }

        print(f"[{self.name}] Fetching actor list...")
        new_aliases = 0
        next_url = MANDIANT_ACTORS_URL

        while next_url:
            resp = requests.get(next_url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for actor in data.get("threat-actors", []):
                canonical_name = actor.get("name", "").strip()
                aliases = [a.get("name", "") for a in actor.get("aliases", []) if a.get("name")]
                all_names = list({canonical_name} | set(aliases))

                actor_db_id = find_actor_by_names(session, all_names)
                if actor_db_id is None:
                    db_actor = Actor(
                        name=canonical_name,
                        description=truncate(actor.get("description") or ""),
                        in_attack=False,
                    )
                    session.add(db_actor)
                    session.flush()
                    actor_db_id = db_actor.id

                for alias_name in all_names:
                    if not alias_name.strip():
                        continue
                    norm = normalize_alias(alias_name)
                    exists = (
                        session.query(Alias)
                        .filter_by(actor_id=actor_db_id, alias_normalized=norm, source=SOURCE)
                        .first()
                    )
                    if not exists:
                        session.add(Alias(
                            actor_id=actor_db_id,
                            alias=alias_name.strip(),
                            alias_normalized=norm,
                            source=SOURCE,
                            confidence="high",
                        ))
                        new_aliases += 1

            # Pagination
            next_url = data.get("next", None)

        session.flush()
        print(f"[{self.name}] Done: {new_aliases} new aliases")
        return new_aliases

    def _get_token(self) -> str:
        resp = requests.post(
            MANDIANT_TOKEN_URL,
            data={"grant_type": "client_credentials"},
            auth=(os.getenv("MANDIANT_API_KEY"), os.getenv("MANDIANT_API_SECRET")),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


