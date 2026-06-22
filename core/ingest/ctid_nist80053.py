"""
CTID NIST 800-53 connector.

Pulls the Center for Threat-Informed Defense (CTID) Mappings Explorer's
ATT&CK-to-NIST-800-53 (rev5) crosswalk and links existing Technique rows
to the controls that mitigate them.

No authentication required.

ORDERING DEPENDENCY: this connector must run AFTER the `attack` connector.
It joins mapping rows against existing `Technique.attack_id` values and
does not create new Technique rows itself — if `attack` hasn't populated
the techniques table yet, every mapping row will be skipped as "unknown
technique". See core/ingest/README.md.
"""

import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector
from core.models import Control, Technique, TechniqueControl

CTID_NIST80053_URL = (
    "https://center-for-threat-informed-defense.github.io/mappings-explorer/"
    "data/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/"
    "nist_800_53-rev5_attack-16.1-enterprise_json.json"
)

SOURCE = "ctid_nist80053"
FRAMEWORK = "nist_800_53"


class CtidNist80053Connector(BaseConnector):
    name = "ctid_nist80053"
    requires_auth = False

    def is_available(self) -> bool:
        return True

    def run(self, session: Session) -> int:
        print(f"[{self.name}] Downloading CTID ATT&CK -> NIST 800-53 mapping...")
        resp = requests.get(CTID_NIST80053_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        # The published mapping JSON has no top-level "status" field — only
        # "mapping_type", which is either "mitigates" (a real mapping) or
        # "non_mappable" (technique has no applicable control).
        mappings = [
            m for m in data.get("mapping_objects", [])
            if m.get("mapping_type") == "mitigates" and m.get("capability_id")
        ]
        print(f"[{self.name}] Downloaded {len(mappings)} mitigates mappings")

        # --- Pass 1: upsert Control rows ---
        control_db_map: dict[str, int] = {}  # capability_id -> db pk
        new_controls = 0
        seen_capability_ids = set()
        for m in mappings:
            cap_id = m["capability_id"]
            if cap_id in seen_capability_ids:
                continue
            seen_capability_ids.add(cap_id)

            existing = (
                session.query(Control)
                .filter_by(framework=FRAMEWORK, control_id=cap_id)
                .first()
            )
            if existing:
                existing.control_group = m.get("capability_group")
                existing.name = m.get("capability_description", existing.name)
                control_db_map[cap_id] = existing.id
            else:
                c = Control(
                    framework=FRAMEWORK,
                    control_id=cap_id,
                    control_group=m.get("capability_group"),
                    name=m.get("capability_description", cap_id),
                )
                session.add(c)
                session.flush()
                control_db_map[cap_id] = c.id
                new_controls += 1

        session.flush()
        print(f"[{self.name}] Controls: {len(control_db_map)} total, {new_controls} new")

        # --- Pass 2: upsert TechniqueControl links ---
        new_links = 0
        skipped_unknown_technique = 0
        for m in mappings:
            attack_id = m.get("attack_object_id")
            cap_id = m["capability_id"]

            technique = session.query(Technique).filter_by(attack_id=attack_id).first()
            if not technique:
                skipped_unknown_technique += 1
                continue

            control_db_id = control_db_map[cap_id]
            exists = (
                session.query(TechniqueControl)
                .filter_by(technique_id=technique.id, control_id=control_db_id, source=SOURCE)
                .first()
            )
            if not exists:
                session.add(TechniqueControl(
                    technique_id=technique.id,
                    control_id=control_db_id,
                    mapping_type=m.get("mapping_type", "mitigates"),
                    source=SOURCE,
                ))
                new_links += 1

        session.flush()
        if skipped_unknown_technique:
            print(
                f"[{self.name}] WARNING: skipped {skipped_unknown_technique} mappings "
                f"for techniques not found in DB — run the `attack` connector first."
            )
        print(f"[{self.name}] Done: {new_controls} new controls, {new_links} new technique-control links")
        return new_controls + new_links
