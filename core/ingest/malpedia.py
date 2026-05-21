"""
Malpedia connector.

Requires a free Malpedia API key: https://malpedia.caad.fkie.fraunhofer.de/
Set MALPEDIA_API_KEY in your .env file to enable.

Malpedia provides rich actor profiles with cross-vendor alias data
and malware family associations. Gracefully skipped if no key is set.
"""

import os
import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector, normalize_alias
from core.models import Actor, Alias, Software, ActorSoftware

MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de/api"
SOURCE = "malpedia"


class MalpediaConnector(BaseConnector):
    name = "malpedia"
    requires_auth = True

    def is_available(self) -> bool:
        return bool(os.getenv("MALPEDIA_API_KEY"))

    def run(self, session: Session) -> int:
        api_key = os.getenv("MALPEDIA_API_KEY")
        headers = {"Authorization": f"apitoken {api_key}"}

        print(f"[{self.name}] Fetching actor list...")
        resp = requests.get(f"{MALPEDIA_BASE}/list/actors", headers=headers, timeout=30)
        resp.raise_for_status()
        actors_list = resp.json()  # list of actor handles e.g. ["apt.28", "fin.7"]

        new_aliases = 0
        for handle in actors_list:
            try:
                detail = requests.get(
                    f"{MALPEDIA_BASE}/get/actor/{handle}",
                    headers=headers,
                    timeout=15,
                ).json()
            except Exception as e:
                print(f"[{self.name}] Warning: could not fetch {handle}: {e}")
                continue

            canonical_name = detail.get("value", handle)
            synonyms: list[str] = detail.get("meta", {}).get("synonyms", [])
            all_names = list({canonical_name} | set(synonyms))

            # Find existing actor or create new
            actor_db_id = _find_actor(session, all_names)
            if actor_db_id is None:
                actor = Actor(
                    name=canonical_name,
                    description=detail.get("description", "")[:2000],
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


def _find_actor(session: Session, names: list[str]) -> int | None:
    for name in names:
        norm = normalize_alias(name)
        alias_row = session.query(Alias).filter_by(alias_normalized=norm).first()
        if alias_row:
            return alias_row.actor_id
    return None
