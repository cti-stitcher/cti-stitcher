"""
/api/d3fend       — list all D3FEND countermeasures with posture and technique counts.
/api/d3fend/{id}/toggle — toggle a countermeasure's implemented status.
/api/gap/d3fend/all      — aggregate D3FEND coverage leaderboard across all actors.
/api/gap/d3fend/{id}     — per-actor D3FEND gap analysis.

NOTE: /api/gap/d3fend/all must be registered BEFORE /api/gap/d3fend/{actor_id}
to prevent FastAPI from coercing the string "all" to an integer.
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


def _db():
    with get_session() as s:
        yield s


# ---------------------------------------------------------------------------
# Countermeasure list  GET /api/d3fend
# ---------------------------------------------------------------------------

@router.get("/api/d3fend")
def list_d3fend(db: Session = Depends(_db)):
    """
    All D3FEND countermeasures with technique_count and implemented flag.
    Sorted by tactic order, then alphabetically by name.
    """
    techniques = db.query(D3FendTechnique).order_by(D3FendTechnique.name).all()

    # Batch: technique counts per D3FEND technique
    technique_counts: dict[int, int] = {}
    for row in db.query(TechniqueD3Fend).all():
        technique_counts[row.d3fend_technique_id] = (
            technique_counts.get(row.d3fend_technique_id, 0) + 1
        )

    # Implemented set
    implemented_ids: set[int] = {
        r.d3fend_technique_id
        for r in db.query(D3FendPosture).filter_by(implemented=True).all()
    }

    out = [
        {
            "id": dt.id,
            "d3fend_id": dt.d3fend_id,
            "name": dt.name,
            "tactic": dt.tactic or "Unknown",
            "definition": dt.definition,
            "technique_count": technique_counts.get(dt.id, 0),
            "implemented": dt.id in implemented_ids,
        }
        for dt in techniques
    ]

    # Sort by tactic order then name
    out.sort(key=lambda x: (
        TACTIC_ORDER.index(x["tactic"]) if x["tactic"] in TACTIC_ORDER else 99,
        x["name"],
    ))
    return out


# ---------------------------------------------------------------------------
# Posture toggle  POST /api/d3fend/{d3fend_id}/toggle
# ---------------------------------------------------------------------------

@router.post("/api/d3fend/{d3fend_id}/toggle")
def toggle_d3fend_posture(d3fend_id: str, db: Session = Depends(_db)):
    """Toggle a D3FEND countermeasure's implemented status."""
    dt = db.query(D3FendTechnique).filter(
        D3FendTechnique.d3fend_id == d3fend_id.upper()
    ).first()
    if not dt:
        raise HTTPException(status_code=404, detail="D3FEND technique not found")

    posture = db.query(D3FendPosture).filter_by(d3fend_technique_id=dt.id).first()
    if posture:
        posture.implemented = not posture.implemented
    else:
        posture = D3FendPosture(d3fend_technique_id=dt.id, implemented=True)
        db.add(posture)

    db.commit()
    return {"d3fend_id": d3fend_id.upper(), "implemented": posture.implemented}


# ---------------------------------------------------------------------------
# All-actors D3FEND leaderboard  GET /api/gap/d3fend/all
# (MUST be registered before /api/gap/d3fend/{actor_id})
# ---------------------------------------------------------------------------

@router.get("/api/gap/d3fend/all")
def get_d3fend_gap_all(db: Session = Depends(_db)):
    """
    D3FEND coverage leaderboard across all actors with technique data.
    3 queries total regardless of actor count.
    Returns actors sorted ascending by d3fend_coverage_pct (most exposed first).
    """
    implemented_ids: set[int] = {
        r.d3fend_technique_id
        for r in db.query(D3FendPosture).filter_by(implemented=True).all()
    }

    # Technique IDs covered by implemented D3FEND countermeasures
    if implemented_ids:
        covered_tech_ids: set[int] = {
            r.technique_id
            for r in db.query(TechniqueD3Fend)
            .filter(TechniqueD3Fend.d3fend_technique_id.in_(implemented_ids))
            .all()
        }
    else:
        covered_tech_ids = set()

    # Batch load all actor-technique links
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
        covered = sum(1 for tid in tech_ids if tid in covered_tech_ids)
        pct = round(covered / total * 100) if total else 0
        result.append({
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
            "total_techniques": total,
            "covered": covered,
            "not_covered": total - covered,
            "coverage_pct": pct,
        })

    result.sort(key=lambda a: a["coverage_pct"])

    return {
        "posture": {"implemented_count": len(implemented_ids)},
        "actors": result,
    }


# ---------------------------------------------------------------------------
# Per-actor D3FEND gap analysis  GET /api/gap/d3fend/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/api/gap/d3fend/{actor_id}")
def get_d3fend_gap(actor_id: int, db: Session = Depends(_db)):
    """
    Per-actor D3FEND gap analysis.

    Returns:
    - covered_techniques: actor techniques addressed by ≥1 implemented D3FEND countermeasure
    - not_covered_techniques: remaining, with available (unimplemented) countermeasures as hints

    Also returns per-tactic D3FEND coverage breakdown.
    """
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    implemented_ids: set[int] = {
        r.d3fend_technique_id
        for r in db.query(D3FendPosture).filter_by(implemented=True).all()
    }

    # Actor's techniques
    actor_techniques = (
        db.query(ActorTechnique, Technique)
        .join(Technique, ActorTechnique.technique_id == Technique.id)
        .filter(ActorTechnique.actor_id == actor_id)
        .all()
    )

    if not actor_techniques:
        return _d3fend_response(actor, [], [], len(implemented_ids))

    technique_ids = [tech.id for _, tech in actor_techniques]

    # Batch: all D3FEND countermeasures mapped to these techniques
    d3fend_rows = (
        db.query(TechniqueD3Fend, D3FendTechnique)
        .join(D3FendTechnique, TechniqueD3Fend.d3fend_technique_id == D3FendTechnique.id)
        .filter(TechniqueD3Fend.technique_id.in_(technique_ids))
        .all()
    )

    # d3fend_by_technique: technique_db_id -> list of (d3fend_db_id, d3fend_id, name, tactic)
    d3fend_by_technique: dict[int, list[tuple]] = {}
    for td, dt in d3fend_rows:
        d3fend_by_technique.setdefault(td.technique_id, []).append(
            (dt.id, dt.d3fend_id, dt.name, dt.tactic or "Unknown")
        )

    covered = []
    not_covered = []

    for at, tech in actor_techniques:
        tactics = [t.strip() for t in (tech.tactic or "unknown").split(",")]
        mapped = d3fend_by_technique.get(tech.id, [])

        implemented_cm = [
            {"d3fend_id": cid_str, "name": cname, "tactic": ctactic}
            for db_id, cid_str, cname, ctactic in sorted(mapped, key=lambda x: x[1])
            if db_id in implemented_ids
        ]
        available_cm = [
            {"d3fend_id": cid_str, "name": cname, "tactic": ctactic}
            for db_id, cid_str, cname, ctactic in sorted(mapped, key=lambda x: x[1])
            if db_id not in implemented_ids
        ]

        tech_dict = {
            "attack_id": tech.attack_id,
            "name": tech.name,
            "is_subtechnique": tech.is_subtechnique,
            "tactic": tactics[0] if tactics else "unknown",
            "tactics": tactics,
            "total_countermeasures": len(mapped),
        }

        if not mapped:
            tech_dict["available_countermeasures"] = []
            tech_dict["note"] = "no_mapping"
            not_covered.append(tech_dict)
        elif implemented_cm:
            tech_dict["implemented_countermeasures"] = implemented_cm
            covered.append(tech_dict)
        else:
            tech_dict["available_countermeasures"] = available_cm
            not_covered.append(tech_dict)

    covered.sort(key=lambda t: t["attack_id"])
    not_covered.sort(key=lambda t: t["attack_id"])

    return _d3fend_response(actor, covered, not_covered, len(implemented_ids))


def _d3fend_response(
    actor: Actor, covered: list, not_covered: list, implemented_count: int
) -> dict:
    total = len(covered) + len(not_covered)
    coverage_pct = round(len(covered) / total * 100) if total else 0
    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
        },
        "posture": {"implemented_count": implemented_count},
        "summary": {
            "total_techniques": total,
            "covered": len(covered),
            "not_covered": len(not_covered),
            "coverage_pct": coverage_pct,
        },
        "covered": covered,
        "not_covered": not_covered,
    }
