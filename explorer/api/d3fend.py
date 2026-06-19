"""
/api/d3fend                        — list all D3FEND countermeasures with posture and technique counts.
/api/d3fend/{id}/toggle            — toggle a countermeasure's implemented status.
/api/d3fend/recommendations/{id}   — ranked action list for a specific actor.
/api/gap/d3fend/all                — aggregate D3FEND coverage leaderboard across all actors.
/api/gap/d3fend/{id}               — per-actor D3FEND gap analysis.

NOTE: /api/gap/d3fend/all must be registered BEFORE /api/gap/d3fend/{actor_id}
to prevent FastAPI from coercing the string "all" to an integer.

NOTE: /api/gap/d3fend/all must be registered BEFORE /api/gap/d3fend/{actor_id}
to prevent FastAPI from coercing the string "all" to an integer.

Coverage semantics (three-bucket model)
---------------------------------------
A technique can fall into one of three buckets — not two:

  covered      — ≥1 implemented D3FEND countermeasure addresses this technique.
  not_deployed — D3FEND has countermeasures for this technique, but none are
                 marked as implemented. Action: deploy a countermeasure.
  no_mapping   — D3FEND has no artifact-level mapping for this technique at all.
                 Action: this tool cannot help; look elsewhere for detection guidance.

Coverage % is calculated over (covered + not_deployed) only — i.e. the techniques
D3FEND can actually speak to. Blending no_mapping into the denominator would make
low coverage look like a deployment gap when it's really a data gap.
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
# Actor-specific ranked action list  GET /api/d3fend/recommendations/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/api/d3fend/recommendations/{actor_id}")
def get_d3fend_recommendations(actor_id: int, db: Session = Depends(_db)):
    """
    Ranked list of unimplemented D3FEND countermeasures for an actor.

    For each countermeasure that is NOT yet deployed, count how many of the
    actor's not-deployed (mappable, uncovered) techniques it would address.
    Sorted descending by technique_closure_count — i.e. the single deployment
    that eliminates the most gaps comes first.

    Only techniques in the not_deployed bucket count toward closure — techniques
    with no_mapping are excluded because D3FEND cannot help there regardless.
    Techniques already covered by another implemented countermeasure are also
    excluded (they're already closed; deploying this wouldn't change coverage %).

    Response shape:
      {
        "actor": {...},
        "recommendations": [
          {
            "d3fend_id": "D3-PSA",
            "name": "Process Spawn Analysis",
            "tactic": "Detect",
            "technique_closure_count": 12,
            "techniques": [{"attack_id": "T1059", "name": "...", ...}, ...]
          }, ...
        ]
      }
    """
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    implemented_ids: set[int] = {
        r.d3fend_technique_id
        for r in db.query(D3FendPosture).filter_by(implemented=True).all()
    }

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

    # Batch: all D3FEND links for this actor's techniques
    d3fend_rows = (
        db.query(TechniqueD3Fend, D3FendTechnique)
        .join(D3FendTechnique, TechniqueD3Fend.d3fend_technique_id == D3FendTechnique.id)
        .filter(TechniqueD3Fend.technique_id.in_(technique_ids))
        .all()
    )

    # Build two indexes:
    #   cm_to_techniques: countermeasure db_id -> set of technique db_ids it covers
    #   tech_to_cms:      technique db_id      -> set of countermeasure db_ids
    cm_to_techniques: dict[int, set[int]] = {}
    tech_to_cms: dict[int, set[int]] = {}
    cm_meta: dict[int, D3FendTechnique] = {}

    for td, dt in d3fend_rows:
        cm_to_techniques.setdefault(dt.id, set()).add(td.technique_id)
        tech_to_cms.setdefault(td.technique_id, set()).add(dt.id)
        cm_meta[dt.id] = dt

    # Identify not_deployed techniques:
    #   - has ≥1 D3FEND mapping (in tech_to_cms)
    #   - none of those mappings are implemented
    not_deployed_tech_ids: set[int] = set()
    for tech_id in technique_ids:
        cms = tech_to_cms.get(tech_id, set())
        if not cms:
            continue  # no_mapping — skip
        if not cms.intersection(implemented_ids):
            not_deployed_tech_ids.add(tech_id)

    if not not_deployed_tech_ids:
        return {
            "actor": {"id": actor.id, "name": actor.name, "attack_group_id": actor.attack_group_id},
            "recommendations": [],
        }

    # For each unimplemented countermeasure, count how many not_deployed
    # techniques it would close
    recommendations = []
    for cm_id, dt in cm_meta.items():
        if cm_id in implemented_ids:
            continue  # already deployed

        closeable = cm_to_techniques[cm_id].intersection(not_deployed_tech_ids)
        if not closeable:
            continue  # doesn't help any not_deployed technique for this actor

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
    D3FEND coverage leaderboard across all