"""
Malpedia connector.

No credentials required — the actor and family endpoints are publicly available.
https://malpedia.caad.fkie.fraunhofer.de/usage/api

Adds cross-vendor actor aliases (Fancy Bear, Cozy Bear, etc.) and malware family
associations beyond what ATT&CK covers. Runs automatically as part of the full sync.
"""

import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector, find_actor_by_names, normalize_alias, truncate
from core.models import Actor, Alias, Software, ActorSoftware

MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de/api"
SOURCE = "malpedia"


class MalpediaConnector(BaseConnector):
    name = "malpedia"
    requires_auth = False

    def is_available(self) -> bool:
        return True  # public API, no key needed

    def run(self, session: Session) -> int:
        # /api/get/actors returns all actor metadata in one call
        # Response: dict keyed by handle {"apt.28": {value, meta, families, ...}, ...}
        print(f"[{self.name}] Fetching all actors...")
        resp = requests.get(f"{MALPEDIA_BASE}/get/actors", timeout=60)
        resp.raise_for_status()
        actors_data: dict = resp.json()
        print(f"[{self.name}] Got {len(actors_data)} actors")

        new_aliases = 0
        for handle, detail in actors_data.items():
            canonical_name = detail.get("value", handle)
            synonyms: list[str] = detail.get("meta", {}).get("synonyms", [])
            all_names = list({canonical_name} | set(synonyms))

            # Match against existing actors by any known alias, or create new
            actor_db_id = find_actor_by_names(session, all_names)
            if actor_db_id is None:
                actor = Actor(
                    name=canonical_name,
                    description=truncate(detail.get("description", "")),
                    in_attack=False,
                )
                session.add(actor)
                session.flush()
                actor_db_id = actor.id

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

            # Associate malware families
            for family in detail.get("families", []):
                family_name = family if isinstance(family, str) else family.get("name", "")
                if not family_name:
                    continue
                sw = session.query(Software).filter_by(name=family_name).first()
                if not sw:
                    sw = Software(name=family_name, software_type="malware")
                    session.add(sw)
                    session.flush()
                exists_rel = (
                    session.query(ActorSoftware)
                    .filter_by(actor_id=actor_db_id, software_id=sw.id, source=SOURCE)
                    .first()
                )
                if not exists_rel:
                    session.add(ActorSoftware(
                        actor_id=actor_db_id,
                        software_id=sw.id,
                        source=SOURCE,
                    ))

        session.flush()
        print(f"[{self.name}] Done: {new_aliases} new aliases")
        return new_aliases
