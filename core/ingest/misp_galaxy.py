"""
MISP Galaxy connector — threat-actor cluster.

Pulls the MISP threat-actor galaxy JSON directly from GitHub.
No authentication required.

This is one of the richest cross-vendor alias sources available:
it already cross-references Mandiant APT names, CrowdStrike
bear/panda/etc names, Microsoft Blizzard/Typhoon names, and more.
"""

import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector, normalize_alias
from core.models import Actor, Alias, Targeting

MISP_GALAXY_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/"
    "clusters/threat-actor.json"
)

SOURCE = "misp_galaxy"


class MispGalaxyConnector(BaseConnector):
    name = "misp_galaxy"
    requires_auth = False

    def is_available(self) -> bool:
        return True

    def run(self, session: Session) -> int:
        print(f"[{self.name}] Downloading MISP galaxy threat-actor cluster...")
        resp = requests.get(MISP_GALAXY_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clusters = data.get("values", [])
        print(f"[{self.name}] Downloaded {len(clusters)} clusters")

        new_actors = 0
        new_aliases = 0

        for cluster in clusters:
            canonical_name = cluster.get("value", "").strip()
            if not canonical_name:
                continue

            meta = cluster.get("meta", {})
            synonyms: list[str] = meta.get("synonyms", [])
            country = _extract_country(meta)
            description = cluster.get("description", "")

            # Try to find existing actor by matching any synonym to our alias table
            actor_db_id = _find_actor(session, canonical_name, synonyms)

            if actor_db_id is None:
                # New actor — not in ATT&CK, store without attack_group_id
                actor = Actor(
                    name=canonical_name,
                    description=description[:2000] if description else None,
                    country_code=country,
                    in_attack=False,
                )
                session.add(actor)
                session.flush()
                actor_db_id = actor.id
                new_actors += 1

            # Upsert all names as aliases
            all_names = list({canonical_name} | set(synonyms))
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

            # Sector targeting from meta
            for sector in _extract_sectors(meta):
                exists = (
                    session.query(Targeting)
                    .filter_by(actor_id=actor_db_id, target_type="industry", value=sector, source=SOURCE)
                    .first()
                )
                if not exists:
                    session.add(Targeting(
                        actor_id=actor_db_id,
                        target_type="industry",
                        value=sector,
                        source=SOURCE,
                        confidence="medium",
                    ))

            # Country targeting from meta
            for country_target in _extract_target_countries(meta):
                exists = (
                    session.query(Targeting)
                    .filter_by(actor_id=actor_db_id, target_type="country", value=country_target, source=SOURCE)
                    .first()
                )
                if not exists:
                    session.add(Targeting(
                        actor_id=actor_db_id,
                        target_type="country",
                        value=country_target,
                        source=SOURCE,
                        confidence="medium",
                    ))

        session.flush()
        print(f"[{self.name}] Done: {new_actors} new actors, {new_aliases} new aliases")
        return new_actors + new_aliases


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_actor(session: Session, name: str, synonyms: list[str]) -> int | None:
    """
    Try to match any of the provided names to an existing actor
    via the alias table. Returns actor db id or None.
    """
    for candidate in [name] + synonyms:
        norm = normalize_alias(candidate)
        alias_row = session.query(Alias).filter_by(alias_normalized=norm).first()
        if alias_row:
            return alias_row.actor_id
    return None


def _extract_country(meta: dict) -> str | None:
    country_map = {
        "china": "CN", "russia": "RU", "north korea": "KP",
        "iran": "IR", "vietnam": "VN", "india": "IN",
        "pakistan": "PK", "turkey": "TR", "ukraine": "UA",
        "israel": "IL", "united states": "US", "usa": "US",
    }
    country_raw = meta.get("country", "").lower()
    return country_map.get(country_raw, country_raw.upper()[:2] if country_raw else None)


SECTOR_KEYWORDS = {
    "financial": "Financial Services", "banking": "Financial Services",
    "government": "Government", "defence": "Defense", "defense": "Defense",
    "military": "Defense", "healthcare": "Healthcare", "health": "Healthcare",
    "energy": "Energy", "oil": "Energy", "technology": "Technology",
    "telecom": "Telecommunications", "media": "Media", "education": "Education",
    "aerospace": "Aerospace", "transportation": "Transportation",
    "manufacturing": "Manufacturing", "pharmaceutical": "Pharmaceutical",
}


def _extract_sectors(meta: dict) -> list[str]:
    sectors = set()
    cfr_targets = meta.get("cfr-target-category", [])
    for t in cfr_targets:
        t_lower = t.lower()
        for kw, label in SECTOR_KEYWORDS.items():
            if kw in t_lower:
                sectors.add(label)
    return list(sectors)


def _extract_target_countries(meta: dict) -> list[str]:
    return [c for c in meta.get("cfr-suspected-victims", []) if c]
