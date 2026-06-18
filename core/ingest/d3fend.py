"""
D3FEND connector — ingests MITRE D3FEND countermeasures and their ATT&CK mappings.

Data source: https://d3fend.mitre.org/ontologies/d3fend.json (JSON-LD, ~4.7MB)

Mapping approach: artifact-based inference
  - D3FEND countermeasure acts on digital artifact X via action-verb properties
    (e.g. d3f:analyzes, d3f:detects, d3f:blocks)
  - ATT&CK offensive technique uses digital artifact X via offensive-verb properties
    (e.g. d3f:creates, d3f:modifies, d3f:abuses)
  - Shared artifact => the countermeasure addresses the ATT&CK technique

This mirrors exactly how d3fend.mitre.org computes "ATT&CK Techniques Addressed"
on each countermeasure page.  The D3FEND REST API has been decommissioned;
the ontology JSON is the authoritative source.

ORDERING DEPENDENCY: must run after the `attack` connector — it joins
inferred ATT&CK IDs against existing Technique rows and skips unknowns.
"""

from collections import defaultdict

import requests
from sqlalchemy.orm import Session

from core.ingest.base import BaseConnector
from core.models import D3FendTechnique, TechniqueD3Fend, Technique

ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"

# Action-verb properties that appear on D3FEND countermeasure nodes
_DEFENSIVE_VERBS = [
    "d3f:analyzes", "d3f:authenticates", "d3f:blocks", "d3f:configures",
    "d3f:creates", "d3f:deletes", "d3f:detects", "d3f:disables", "d3f:enables",
    "d3f:encrypts", "d3f:enforces", "d3f:erases", "d3f:evaluates", "d3f:filters",
    "d3f:hardens", "d3f:identifies", "d3f:inventories", "d3f:isolates", "d3f:limits",
    "d3f:manages", "d3f:mediates-access-to", "d3f:modifies", "d3f:monitors",
    "d3f:neutralizes", "d3f:quarantines", "d3f:reads", "d3f:regenerates",
    "d3f:restores", "d3f:restricts", "d3f:suspends", "d3f:terminates",
    "d3f:updates", "d3f:validates", "d3f:verifies",
]

# Action-verb properties that appear on ATT&CK offensive-technique nodes
_OFFENSIVE_VERBS = [
    "d3f:abuses", "d3f:accesses", "d3f:adds", "d3f:analyzes", "d3f:connects",
    "d3f:copies", "d3f:creates", "d3f:deletes", "d3f:disables", "d3f:enables",
    "d3f:encrypts", "d3f:executes", "d3f:forges", "d3f:hides", "d3f:injects",
    "d3f:installs", "d3f:interprets", "d3f:invokes", "d3f:loads", "d3f:may-access",
    "d3f:may-add", "d3f:may-create", "d3f:may-execute", "d3f:may-invoke",
    "d3f:may-modify", "d3f:may-produce", "d3f:may-run", "d3f:may-transfer",
    "d3f:modifies", "d3f:obfuscates", "d3f:produces", "d3f:queries", "d3f:reads",
    "d3f:runs", "d3f:unmounts", "d3f:uses",
]

# All verbs (union) used when scanning either node type
_ALL_VERBS = list(set(_DEFENSIVE_VERBS + _OFFENSIVE_VERBS))

_TACTICS = {
    "d3f:Harden", "d3f:Detect", "d3f:Isolate",
    "d3f:Deceive", "d3f:Evict", "d3f:Restore",
}


class D3FendConnector(BaseConnector):
    name = "d3fend"
    requires_auth = False

    def is_available(self) -> bool:
        return True  # public URL, no auth needed

    def run(self, session: Session) -> int:
        print(f"[{self.name}] Fetching D3FEND ontology...")
        resp = requests.get(ONTOLOGY_URL, timeout=60)
        resp.raise_for_status()
        graph = resp.json()["@graph"]
        print(f"[{self.name}] Ontology loaded: {len(graph)} nodes")

        id_to_node: dict[str, dict] = {n["@id"]: n for n in graph}

        # --- Step 1: map ATT&CK Enterprise technique @ids to attack-id strings ---
        attack_id_map: dict[str, str] = {}  # node @id  ->  "T1566"
        for n in graph:
            aid = n.get("d3f:attack-id", "")
            if isinstance(aid, str) and aid.startswith("T1"):
                attack_id_map[n["@id"]] = aid
        attack_node_ids = set(attack_id_map.keys())

        # --- Step 2: build artifact -> [ATT&CK node @ids] from offensive nodes ---
        artifact_to_attacks: dict[str, set] = defaultdict(set)
        for n in graph:
            if n["@id"] not in attack_node_ids:
                continue
            for ref in _refs(n, _OFFENSIVE_VERBS):
                if ref not in attack_node_ids:          # it's an artifact, not an ATT&CK tech
                    artifact_to_attacks[ref].add(n["@id"])

        # --- Step 3: preload DB state ---
        db_techniques: dict[str, int] = {
            t.attack_id: t.id for t in session.query(Technique).all()
        }
        existing_d3fend: dict[str, D3FendTechnique] = {
            d.d3fend_id: d for d in session.query(D3FendTechnique).all()
        }
        existing_mappings: set[tuple[int, int]] = {
            (m.technique_id, m.d3fend_technique_id)
            for m in session.query(TechniqueD3Fend).all()
        }

        # --- Step 4: ingest D3FEND countermeasures ---
        d3fend_nodes = [n for n in graph if "d3f:d3fend-id" in n]
        print(f"[{self.name}] Processing {len(d3fend_nodes)} D3FEND countermeasures...")

        new_techniques = 0
        new_mappings = 0

        for node in d3fend_nodes:
            did = node.get("d3f:d3fend-id", "")
            if not did:
                continue

            label = (
                node.get("rdfs:label")
                or node.get("skos:prefLabel")
                or did
            )
            definition = (
                node.get("d3f:definition")
                or node.get("d3f:kb-abstract")
                or ""
            )
            tactic = _tactic(node, id_to_node)

            # Upsert D3FendTechnique
            if did not in existing_d3fend:
                dt = D3FendTechnique(
                    d3fend_id=did,
                    name=label,
                    tactic=tactic,
                    definition=definition[:2000] if definition else None,
                )
                session.add(dt)
                session.flush()
                existing_d3fend[did] = dt
                new_techniques += 1
            else:
                dt = existing_d3fend[did]
                dt.name = label
                dt.tactic = tactic

            dt_db_id = existing_d3fend[did].id

            # Compute ATT&CK coverage via artifact inference
            attack_hits: set[str] = set()
            for art in _refs(node, _DEFENSIVE_VERBS):
                if art in attack_id_map:
                    # direct ATT&CK reference (rare — e.g. DomainTrustPolicy)
                    attack_hits.add(attack_id_map[art])
                else:
                    for atk_id in artifact_to_attacks.get(art, set()):
                        attack_hits.add(attack_id_map[atk_id])

            # Ingest TechniqueD3Fend links
            for attack_id in attack_hits:
                tech_db_id = db_techniques.get(attack_id)
                if not tech_db_id:
                    continue
                key = (tech_db_id, dt_db_id)
                if key not in existing_mappings:
                    session.add(TechniqueD3Fend(
                        technique_id=tech_db_id,
                        d3fend_technique_id=dt_db_id,
                    ))
                    existing_mappings.add(key)
                    new_mappings += 1

        session.commit()
        print(
            f"[{self.name}] Done: {new_techniques} new countermeasures, "
            f"{new_mappings} new ATT&CK mappings"
        )
        return new_techniques + new_mappings


# ---------------------------------------------------------------------------
# Ontology helpers
# ---------------------------------------------------------------------------

def _refs(node: dict, verbs: list[str]) -> set:
    """
    Collect all @id values referenced by a node via the given verb properties.
    Blank nodes (_:N...) are excluded — they encode OWL restrictions, not artifacts.
    """
    refs = set()
    for prop in verbs:
        vals = node.get(prop, [])
        if isinstance(vals, dict):
            vals = [vals]
        elif not isinstance(vals, list):
            vals = [{"@id": str(vals)}]
        for v in vals:
            ref = v.get("@id", "") if isinstance(v, dict) else str(v)
            if ref and not ref.startswith("_:"):
                refs.add(ref)
    return refs


def _tactic(node: dict, id_to_node: dict, depth: int = 0) -> str:
    """
    Walk d3f:enables and rdfs:subClassOf to find the top-level D3FEND tactic.
    Returns one of: Harden / Detect / Isolate / Deceive / Evict / Restore / Unknown.
    """
    if depth > 10:
        return "Unknown"

    enables = node.get("d3f:enables")
    if enables:
        eid = enables.get("@id", "") if isinstance(enables, dict) else str(enables)
        if eid in _TACTICS:
            return eid.replace("d3f:", "")

    parents = node.get("rdfs:subClassOf", [])
    if isinstance(parents, dict):
        parents = [parents]

    for p in parents:
        pid = p.get("@id", "") if isinstance(p, dict) else ""
        if not pid or pid.startswith("_:"):
            continue
        pn = id_to_node.get(pid)
        if pn:
            t = _tactic(pn, id_to_node, depth + 1)
            if t != "Unknown":
                return t

    return "Unknown"
