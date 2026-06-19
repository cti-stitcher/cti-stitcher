"""
MITRE ATT&CK connector.

Pulls the Enterprise ATT&CK STIX 2.0 bundle from MITRE's GitHub.
No authentication required.

Data pulled:
  - Intrusion sets (threat actor groups)
  - Aliases per group
  - Techniques and sub-techniques used by each group
  - Software (tools/malware) used by each group
  - Target sectors and countries from group descriptions (best-effort)
"""

import re
import requests

from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector, normalize_alias
from core.models import Actor, Alias, ActorSoftware, ActorTechnique, Software, Technique

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

SOURCE = "attack"

# Rough sector keywords → normalized sector label
# Used to extract targeting from free-text descriptions
SECTOR_KEYWORDS = {
    "financial": "Financial Services",
    "banking": "Financial Services",
    "government": "Government",
    "defense": "Defense",
    "military": "Defense",
    "healthcare": "Healthcare",
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


class AttackConnector(BaseConnector):
    name = "attack"
    requires_auth = False

    def is_available(self) -> bool:
        return True

    def run(self, session: Session) -> int:
        print(f"[{self.name}] Downloading ATT&CK bundle...")
        resp = requests.get(ATTACK_BUNDLE_URL, timeout=60)
        resp.raise_for_status()
        bundle = resp.json()
        objects = bundle.get("objects", [])
        print(f"[{self.name}] Downloaded {len(objects)} STIX objects")

        # Index objects by ID for relationship resolution
        obj_by_id = {o["id"]: o for o in objects}

        # --- Pass 1: Techniques ---
        technique_db_map: dict[str, int] = {}  # attack_id → db pk
        tech_count = 0
        for obj in objects:
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue
            attack_id = _get_attack_id(obj)
            if not attack_id:
                continue

            is_sub = "." in attack_id
            tactic = _get_tactics(obj)

            existing = session.query(Technique).filter_by(attack_id=attack_id).first()
            if existing:
                existing.name = obj.get("name", existing.name)
                existing.tactic = tactic
                db_id = existing.id
            else:
                t = Technique(
                    attack_id=attack_id,
                    name=obj.get("name", ""),
                    description=_truncate(obj.get("description", "")),
                    tactic=tactic,
                    is_subtechnique=is_sub,
                )
                session.add(t)
                session.flush()
                db_id = t.id
                tech_count += 1

            technique_db_map[attack_id] = db_id

        session.flush()

        # --- Pass 2: Software ---
        software_db_map: dict[str, int] = {}  # attack_id → db pk
        sw_count = 0
        for obj in objects:
            if obj.get("type") not in ("tool", "malware") or obj.get("revoked"):
                continue
            attack_id = _get_attack_id(obj)
            if not attack_id:
                continue

            sw_type = "tool" if obj.get("type") == "tool" else "malware"
            existing = session.query(Software).filter_by(attack_id=attack_id).first()
            if existing:
                db_id = existing.id
            else:
                sw = Software(
                    attack_id=attack_id,
                    name=obj.get("name", ""),
                    software_type=sw_type,
                    description=_truncate(obj.get("description", "")),
                )
                session.add(sw)
                session.flush()
                db_id = sw.id
                sw_count += 1

            software_db_map[attack_id] = db_id

        session.flush()

        # --- Pass 3: Intrusion sets (actors) ---
        actor_stix_map: dict[str, int] = {}  # stix_id → db pk
        actor_count = 0
        for obj in objects:
            if obj.get("type") != "intrusion-set" or obj.get("revoked"):
                continue

            attack_id = _get_attack_id(obj)
            stix_id = obj.get("id")
            name = obj.get("name", "")
            raw_aliases = obj.get("aliases", [])
            country = _extract_country(obj)

            existing = (
                session.query(Actor)
                .filter(
                    (Actor.attack_group_id == attack_id) | (Actor.stix_id == stix_id)
                )
                .first()
            )

            if existing:
                existing.attack_group_id = attack_id
                existing.stix_id = stix_id
                existing.name = name
                existing.description = _truncate(obj.get("description", ""))
                existing.country_code = country
                existing.first_seen = obj.get("first_seen", existing.first_seen)
                existing.last_seen = obj.get("last_seen", existing.last_seen)
                existing.in_attack = True
                actor_db_id = existing.id
            else:
                actor = Actor(
                    attack_group_id=attack_id,
                    stix_id=stix_id,
                    name=name,
                    description=_truncate(obj.get("description", "")),
                    country_code=country,
                    first_seen=obj.get("first_seen"),
                    last_seen=obj.get("last_seen"),
                    in_attack=True,
                )
                session.add(actor)
                session.flush()
                actor_db_id = actor.id
                actor_count += 1

            actor_stix_map[stix_id] = actor_db_id

            # Upsert all aliases (canonical name + ATT&CK group ID + any listed aliases)
            # Include the ATT&CK group ID (e.g. G0016) so analysts can search by it directly
            all_names = list({name} | set(raw_aliases) | ({attack_id} if attack_id else set()))
            for alias_name in all_names:
                norm = normalize_alias(alias_name)
                existing_alias = (
                    session.query(Alias)
                    .filter_by(actor_id=actor_db_id, alias_normalized=norm, source=SOURCE)
                    .first()
                )
                if not existing_alias:
                    session.add(Alias(
                        actor_id=actor_db_id,
                        alias=alias_name,
                        alias_normalized=norm,
                        source=SOURCE,
                        confidence="high",
                    ))

            # Extract targeting from description (best-effort)
            _upsert_targeting(session, actor_db_id, obj.get("description", ""), SOURCE)

        session.flush()

        # --- Pass 4: Relationships ---
        rel_count = 0
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("revoked"):
                continue

            rel_type = obj.get("relationship_type")
            src_id = obj.get("source_ref", "")
            tgt_id = obj.get("target_ref", "")

            if src_id not in actor_stix_map:
                continue

            actor_db_id = actor_stix_map[src_id]

            if rel_type == "uses":
                tgt_obj = obj_by_id.get(tgt_id, {})
                tgt_type = tgt_obj.get("type")

                if tgt_type == "attack-pattern":
                    tech_attack_id = _get_attack_id(tgt_obj)
                    tech_db_id = technique_db_map.get(tech_attack_id)
                    if tech_db_id:
                        # The relationship description is the verbatim STIX procedure citation —
                        # how this specific actor uses this specific technique.
                        procedure = _truncate(obj.get("description", ""), max_len=4000)
                        exists = (
                            session.query(ActorTechnique)
                            .filter_by(actor_id=actor_db_id, technique_id=tech_db_id, source=SOURCE)
                            .first()
                        )
                        if not exists:
                            session.add(ActorTechnique(
                                actor_id=actor_db_id,
                                technique_id=tech_db_id,
                                source=SOURCE,
                                confidence="high",
                                procedure=procedure or None,
                            ))
                            rel_count += 1
                        elif procedure and not exists.procedure:
                            # Backfill procedure on existing rows from prior syncs
                            exists.procedure = procedure

                elif tgt_type in ("tool", "malware"):
                    sw_attack_id = _get_attack_id(tgt_obj)
                    sw_db_id = software_db_map.get(sw_attack_id)
                    if sw_db_id:
                        exists = (
                            session.query(ActorSoftware)
                            .filter_by(actor_id=actor_db_id, software_id=sw_db_id, source=SOURCE)
                            .first()
                        )
                        if not exists:
                            session.add(ActorSoftware(
                                actor_id=actor_db_id,
                                software_id=sw_db_id,
                                source=SOURCE,
                            ))

        session.flush()
        total = actor_count + tech_count + sw_count + rel_count
        print(f"[{self.name}] Done: {actor_count} actors, {tech_count} techniques, "
              f"{sw_count} software, {rel_count} new relationships")
        return total


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _get_tactics(obj: dict) -> str:
    phases = obj.get("kill_chain_phases", [])
    tactics = [p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"]
    return ",".join(tactics)


def _extract_country(obj: dict) -> str | None:
    """Best-effort country extraction from external references."""
    for ref in obj.get("external_references", []):
        desc = ref.get("description", "").lower()
        for code, country in [
            ("china", "CN"), ("russia", "RU"), ("north korea", "KP"),
            ("iran", "IR"), ("vietnam", "VN"), ("india", "IN"),
            ("pakistan", "PK"), ("turkey", "TR"), ("ukraine", "UA"),
        ]:
            if code in desc:
                return country
    return None


def _upsert_targeting(session: Session, actor_id: int, description: str, source: str) -> None:
    """Extract sector keywords from description and store as targeting rows."""
    from core.models import Targeting
    desc_lower = description.lower()
    seen = set()
    for keyword, sector in SECTOR_KEYWORDS.items():
        if keyword in desc_lower and sector not in seen:
            seen.add(sector)
            exists = (
                session.query(Targeting)
                .filter_by(actor_id=actor_id, target_type="industry", value=sector, source=source)
                .first()
            )
            if not exists:
                session.add(Targeting(
                    actor_id=actor_id,
                    target_type="industry",
                    value=sector,
                    source=source,
                    confidence="medium",
                ))


def _truncate(text: str, max_len: int = 2000) -> str:
    return text[:max_len] if text else ""
