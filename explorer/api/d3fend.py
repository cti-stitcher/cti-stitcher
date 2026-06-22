"""
/api/d3fend                        — list all D3FEND countermeasures with posture and technique counts.
/api/d3fend/{id}/toggle            — cycle a countermeasure's status: not_deployed → partial → deployed.
/api/d3fend/recommendations/{id}   — ranked action list for a specific actor.
/api/gap/d3fend/all                — aggregate D3FEND coverage leaderboard across all actors.
/api/gap/d3fend/{id}               — per-actor D3FEND gap analysis.

NOTE: /api/gap/d3fend/all must be registered BEFORE /api/gap/d3fend/{actor_id}
to prevent FastAPI from coercing the string "all" to an integer.

Coverage semantics (three-bucket model + partial state)
-------------------------------------------------------
Countermeasure status:
  not_deployed  — default; not in use (counts as 0)
  partial       — deployed against a subset of the relevant surface (counts as 0.5)
  deployed      — fully deployed (counts as 1.0)

Technique-level bucketing:
  covered         — ≥1 countermeasure is 'deployed' for this technique
  partial_covered — ≥1 countermeasure is 'partial', none are 'deployed'
  not_deployed    — D3FEND has countermeasures but all are 'not_deployed'
  no_mapping      — D3FEND has no artifact-level mapping for this technique

Coverage % = (covered + 0.5 * partial_covered) / (covered + partial_covered + not_deployed)
no_mapping techniques are excluded from the denominator — a data gap is not a deployment gap.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.db import get_session
from core.models import (
    Actor, ActorTechnique, D3FendTechnique, D3FendPosture,
    Technique, TechniqueD3Fend,
)

router = APIRouter(tags=["d3fend"])

TACTIC_ORDER = ["Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore", "Unknown"]
STATUS_CYCLE = {"not_deployed": "partial", "partial": "deployed", "deployed": "not_deployed"}


def _db():
    with get_session() as s:
        yield s


def _posture_map(db: Session) -> dict[int, str]:
    """Return {d3fend_technique_id: status} for all rows in d3fend_posture."""
    return {r.d3fend_technique_id: r.status for r in db.query(D3FendPosture).all()}


# ---------------------------------------------------------------------------
# Countermeasure list  GET /api/d3fend
# ---------------------------------------------------------------------------

@router.get("/api/d3fend")
def list_d3fend(db: Session = Depends(_db)):
    """
    All D3FEND countermeasures with technique_count and posture status.
    Sorted by tactic order, then alphabetically by name.
    """
    techniques = db.query(D3FendTechnique).order_by(D3FendTechnique.name).all()

    technique_counts: dict[int, int] = {}
    for row in db.query(TechniqueD3Fend).all():
        technique_counts[row.d3fend_technique_id] = (
            technique_counts.get(row.d3fend_technique_id, 0) + 1
        )

    posture = _posture_map(db)

    out = [
        {
            "id": dt.id,
            "d3fend_id": dt.d3fend_id,
            "name": dt.name,
            "tactic": dt.tactic or "Unknown",
            "definition": dt.definition,
            "technique_count": technique_counts.get(dt.id, 0),
            "status": posture.get(dt.id, "not_deployed"),
            # legacy field — kept for any clients that read 'implemented'
            "implemented": posture.get(dt.id, "not_deployed") == "deployed",
        }
        for dt in techniques
    ]

    out.sort(key=lambda x: (
        TACTIC_ORDER.index(x["tactic"]) if x["tactic"] in TACTIC_ORDER else 99,
        x["name"],
    ))
    return out


# ---------------------------------------------------------------------------
# Posture toggle  POST /api/d3fend/{d3fend_id}/toggle
# Cycles: not_deployed → partial → deployed → not_deployed
# ---------------------------------------------------------------------------

@router.post("/api/d3fend/{d3fend_id}/toggle")
def toggle_d3fend_posture(d3fend_id: str, db: Session = Depends(_db)):
    """Cycle a D3FEND countermeasure through not_deployed → partial → deployed."""
    dt = db.query(D3FendTechnique).filter(
        D3FendTechnique.d3fend_id == d3fend_id.upper()
    ).first()
    if not dt:
        raise HTTPException(status_code=404, detail="D3FEND technique not found")

    posture = db.query(D3FendPosture).filter_by(d3fend_technique_id=dt.id).first()
    if posture:
        posture.status = STATUS_CYCLE.get(posture.status, "partial")
    else:
        posture = D3FendPosture(d3fend_technique_id=dt.id, status="partial")
        db.add(posture)

    db.commit()
    return {
        "d3fend_id": d3fend_id.upper(),
        "status": posture.status,
        "implemented": posture.status == "deployed",
    }


# ---------------------------------------------------------------------------
# Actor-specific ranked action list  GET /api/d3fend/recommendations/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/api/d3fend/recommendations/{actor_id}")
def get_d3fend_recommendations(actor_id: int, db: Session = Depends(_db)):
    """
    Ranked list of not_deployed D3FEND countermeasures for an actor.

    Counts how many of the actor's uncovered techniques each undeployed
    countermeasure would close. Sorted descending by technique_closure_count.

    A technique counts as uncovered if it has no deployed or partial countermeasure.
    Techniques with no D3FEND mapping are excluded — the tool cannot help there.
    """
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    posture = _posture_map(db)
    deployed_ids: set[int] = {k for k, v in posture.items() if v == "deployed"}
    active_ids: set[int] = {k for k, v in posture.items() if v in ("deployed", "partial")}

    actor_techniques = (
        db.query(ActorTechnique, Technique)
        .join(Technique, ActorTechnique.technique_id == Technique.id)
        .filter(ActorTechnique.actor_id == actor_id)
        .all()
    )

    if not actor_techniques:
        return {"actor": {"id": actor.id, "name": actor.name}, "recommendations": []}

    technique_ids = [tech.id for _, tech in actor_techniques]
    tech_map: dict[int, Technique] = {tech.id: tech for _, tech in actor_techniques}

    d3fend_rows = (
        db.query(TechniqueD3Fend, D3FendTechnique)
        .join(D3FendTechnique, TechniqueD3Fend.d3fend_technique_id == D3FendTechnique.id)
        .filter(TechniqueD3Fend.technique_id.in_(technique_ids))
        .all()
    )

    cm_to_techniques: dict[int, set[int]] = {}
    tech_to_cms: dict[int, set[int]] = {}
    cm_meta: dict[int, D3FendTechnique] = {}

    for td, dt in d3fend_rows:
        cm_to_techniques.setdefault(dt.id, set()).add(td.technique_id)
        tech_to_cms.setdefault(td.technique_id, set()).add(dt.id)
        cm_meta[dt.id] = dt

    # Techniques with no active (deployed or partial) countermeasure
    not_covered_tech_ids: set[int] = set()
    for tech_id in technique_ids:
        cms = tech_to_cms.get(tech_id, set())
        if not cms:
            continue  # no_mapping — skip
        if not cms.intersection(active_ids):
            not_covered_tech_ids.add(tech_id)

    if not not_covered_tech_ids:
        return {
            "actor": {"id": actor.id, "name": actor.name, "attack_group_id": actor.attack_group_id},
            "recommendations": [],
        }

    recommendations = []
    for cm_id, dt in cm_meta.items():
        if cm_id in deployed_ids:
            continue  # fully deployed — skip

        closeable = cm_to_techniques[cm_id].intersection(not_covered_tech_ids)
        if not closeable:
            continue

        techs = sorted(
            [
                {
                    "attack_id": tech_map[tid].attack_id,
                    "name": tech_map[tid].name,
                    "tactic": (tech_map[tid].tactic or "unknown").split(",")[0].strip(),
                    "is_subtechnique": tech_map[tid].is_subtechnique,
                }
                for tid in closeable
            ],
            key=lambda t: t["attack_id"],
        )

        recommendations.append({
            "d3fend_id": dt.d3fend_id,
            "name": dt.name,
            "tactic": dt.tactic or "Unknown",
            "current_status": posture.get(cm_id, "not_deployed"),
            "technique_closure_count": len(closeable),
            "techniques": techs,
        })

    recommendations.sort(key=lambda r: -r["technique_closure_count"])

    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
        },
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# All-actors D3FEND leaderboard  GET /api/gap/d3fend/all
# (MUST be registered before /api/gap/d3fend/{actor_id})
# ---------------------------------------------------------------------------

@router.get("/api/gap/d3fend/all")
def get_d3fend_gap_all(db: Session = Depends(_db)):
    """
    D3FEND coverage leaderboard across all actors.

    coverage_pct = (covered + 0.5 * partial_covered) / mappable_techniques
    Techniques with no D3FEND mapping are excluded from the denominator.
    Returns actors sorted ascending by coverage_pct (most exposed first).
    """
    posture = _posture_map(db)
    deployed_ids: set[int] = {k for k, v in posture.items() if v == "deployed"}
    partial_ids: set[int] = {k for k, v in posture.items() if v == "partial"}

    all_d3fend_links = db.query(TechniqueD3Fend).all()
    mappable_tech_ids: set[int] = {r.technique_id for r in all_d3fend_links}

    # Build technique -> set of countermeasure IDs index
    tech_to_cms: dict[int, set[int]] = {}
    for row in all_d3fend_links:
        tech_to_cms.setdefault(row.technique_id, set()).add(row.d3fend_technique_id)

    all_at = db.query(ActorTechnique).all()
    tech_by_actor: dict[int, list[int]] = {}
    for at in all_at:
        tech_by_actor.setdefault(at.actor_id, []).append(at.technique_id)

    actors = db.query(Actor).order_by(Actor.name).all()
    result = []
    for actor in actors:
        tech_ids = tech_by_actor.get(actor.id, [])
        if not tech_ids:
            continue

        total = len(tech_ids)
        n_covered = 0
        n_partial = 0
        n_not_deployed = 0
        n_no_mapping = 0

        for tid in tech_ids:
            if tid not in mappable_tech_ids:
                n_no_mapping += 1
                continue
            cms = tech_to_cms.get(tid, set())
            if cms.intersection(deployed_ids):
                n_covered += 1
            elif cms.intersection(partial_ids):
                n_partial += 1
            else:
                n_not_deployed += 1

        mappable = n_covered + n_partial + n_not_deployed
        pct = round((n_covered + 0.5 * n_partial) / mappable * 100) if mappable else 0

        result.append({
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
            "total_techniques": total,
            "mappable_techniques": mappable,
            "no_mapping": n_no_mapping,
            "covered": n_covered,
            "partial_covered": n_partial,
            "not_deployed": n_not_deployed,
            "coverage_pct": pct,
        })

    result.sort(key=lambda a: a["coverage_pct"])

    return {
        "posture": {
            "deployed_count": len(deployed_ids),
            "partial_count": len(partial_ids),
        },
        "actors": result,
    }


# ---------------------------------------------------------------------------
# Per-actor D3FEND gap analysis  GET /api/gap/d3fend/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/api/gap/d3fend/{actor_id}")
def get_d3fend_gap(actor_id: int, db: Session = Depends(_db)):
    """
    Per-actor D3FEND gap analysis.

    covered         — ≥1 countermeasure is 'deployed' (partially_covered=False)
    covered (partial) — ≥1 countermeasure is 'partial', none deployed (partially_covered=True)
    not_deployed    — D3FEND has countermeasures but all are 'not_deployed'
    no_mapping      — D3FEND has no artifact mapping for this technique

    coverage_pct = (covered + 0.5 * partial_covered) / mappable
    """
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    posture = _posture_map(db)
    deployed_ids: set[int] = {k for k, v in posture.items() if v == "deployed"}
    partial_ids: set[int] = {k for k, v in posture.items() if v == "partial"}

    actor_techniques = (
        db.query(ActorTechnique, Technique)
        .join(Technique, ActorTechnique.technique_id == Technique.id)
        .filter(ActorTechnique.actor_id == actor_id)
        .all()
    )

    if not actor_techniques:
        return _d3fend_response(actor, [], [], [], posture)

    technique_ids = [tech.id for _, tech in actor_techniques]

    d3fend_rows = (
        db.query(TechniqueD3Fend, D3FendTechnique)
        .join(D3FendTechnique, TechniqueD3Fend.d3fend_technique_id == D3FendTechnique.id)
        .filter(TechniqueD3Fend.technique_id.in_(technique_ids))
        .all()
    )

    d3fend_by_technique: dict[int, list[tuple]] = {}
    for td, dt in d3fend_rows:
        d3fend_by_technique.setdefault(td.technique_id, []).append(
            (dt.id, dt.d3fend_id, dt.name, dt.tactic or "Unknown")
        )

    covered = []
    not_deployed = []
    no_mapping = []

    for at, tech in actor_techniques:
        tactics = [t.strip() for t in (tech.tactic or "unknown").split(",")]
        mapped = d3fend_by_technique.get(tech.id, [])

        tech_dict = {
            "attack_id": tech.attack_id,
            "name": tech.name,
            "is_subtechnique": tech.is_subtechnique,
            "tactic": tactics[0] if tactics else "unknown",
            "tactics": tactics,
            "total_countermeasures": len(mapped),
        }

        if not mapped:
            no_mapping.append(tech_dict)
        else:
            deployed_cm = [
                {"d3fend_id": cid_str, "name": cname, "tactic": ctactic, "status": "deployed"}
                for db_id, cid_str, cname, ctactic in sorted(mapped, key=lambda x: x[1])
                if db_id in deployed_ids
            ]
            partial_cm = [
                {"d3fend_id": cid_str, "name": cname, "tactic": ctactic, "status": "partial"}
                for db_id, cid_str, cname, ctactic in sorted(mapped, key=lambda x: x[1])
                if db_id in partial_ids
            ]
            available_cm = [
                {"d3fend_id": cid_str, "name": cname, "tactic": ctactic, "status": "not_deployed"}
                for db_id, cid_str, cname, ctactic in sorted(mapped, key=lambda x: x[1])
                if db_id not in deployed_ids and db_id not in partial_ids
            ]

            if deployed_cm:
                tech_dict["implemented_countermeasures"] = deployed_cm + partial_cm
                tech_dict["available_countermeasures"] = available_cm
                tech_dict["partially_covered"] = False
                covered.append(tech_dict)
            elif partial_cm:
                tech_dict["implemented_countermeasures"] = partial_cm
                tech_dict["available_countermeasures"] = available_cm
                tech_dict["partially_covered"] = True
                covered.append(tech_dict)
            else:
                tech_dict["available_countermeasures"] = available_cm
                not_deployed.append(tech_dict)

    for lst in (covered, not_deployed, no_mapping):
        lst.sort(key=lambda t: t["attack_id"])

    return _d3fend_response(actor, covered, not_deployed, no_mapping, posture)


def _d3fend_response(
    actor: Actor,
    covered: list,
    not_deployed: list,
    no_mapping: list,
    posture: dict,
) -> dict:
    n_fully_covered = sum(1 for t in covered if not t.get("partially_covered"))
    n_partial_covered = sum(1 for t in covered if t.get("partially_covered"))
    mappable = len(covered) + len(not_deployed)
    coverage_pct = round(
        (n_fully_covered + 0.5 * n_partial_covered) / mappable * 100
    ) if mappable else 0

    deployed_count = sum(1 for v in posture.values() if v == "deployed")
    partial_count = sum(1 for v in posture.values() if v == "partial")

    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
        },
        "posture": {
            "deployed_count": deployed_count,
            "partial_count": partial_count,
        },
        "summary": {
            "total_techniques": mappable + len(no_mapping),
            "mappable_techniques": mappable,
            "no_mapping": len(no_mapping),
            "covered": n_fully_covered,
            "partial_covered": n_partial_covered,
            "not_deployed": len(not_deployed),
            "coverage_pct": coverage_pct,
        },
        "covered": covered,
        "not_deployed": not_deployed,
        "no_mapping": no_mapping,
    }
