"""
/api/controls  — controls list and control detail endpoints.

Provides the reverse-lookup view: given a NIST 800-53 control, which
techniques does it mitigate and which actors use those techniques?
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from core.db import get_session
from core.models import Actor, ActorTechnique, Control, Technique, TechniqueControl

router = APIRouter(prefix="/api/controls", tags=["controls"])


def _db():
    with get_session() as s:
        yield s


# ---------------------------------------------------------------------------
# List endpoint  GET /api/controls
# ---------------------------------------------------------------------------

@router.get("")
def list_controls(db: Session = Depends(_db)):
    """
    Return all controls with technique count and distinct actor count.
    Sorted by control_group then control_id.
    """
    controls = (
        db.query(Control)
        .order_by(Control.control_group, Control.control_id)
        .all()
    )

    result = []
    for control in controls:
        technique_count = (
            db.query(TechniqueControl)
            .filter_by(control_id=control.id)
            .count()
        )
        actor_count = (
            db.query(func.count(distinct(ActorTechnique.actor_id)))
            .join(TechniqueControl, ActorTechnique.technique_id == TechniqueControl.technique_id)
            .filter(TechniqueControl.control_id == control.id)
            .scalar()
        ) or 0

        result.append({
            "id": control.id,
            "control_id": control.control_id,
            "name": control.name,
            "control_group": control.control_group,
            "framework": control.framework,
            "technique_count": technique_count,
            "actor_count": actor_count,
        })

    return result


# ---------------------------------------------------------------------------
# Detail endpoint  GET /api/controls/{control_id}
# ---------------------------------------------------------------------------

@router.get("/{control_id}")
def get_control(control_id: str, db: Session = Depends(_db)):
    """
    Return a control with its full technique list, each technique annotated
    with the actors that use it.
    """
    control = (
        db.query(Control)
        .filter(Control.control_id == control_id.upper())
        .first()
    )
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    # Techniques mapped to this control
    technique_rows = (
        db.query(TechniqueControl, Technique)
        .join(Technique, TechniqueControl.technique_id == Technique.id)
        .filter(TechniqueControl.control_id == control.id)
        .order_by(Technique.attack_id)
        .all()
    )

    # Batch-load actors for all technique IDs (one query, not N)
    technique_ids = [tech.id for _, tech in technique_rows]
    actor_rows = (
        db.query(ActorTechnique, Actor)
        .join(Actor, ActorTechnique.actor_id == Actor.id)
        .filter(ActorTechnique.technique_id.in_(technique_ids))
        .order_by(Actor.name)
        .all()
    ) if technique_ids else []

    actors_by_technique: dict[int, list] = {}
    for at, actor in actor_rows:
        actors_by_technique.setdefault(at.technique_id, []).append({
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
        })

    techniques = []
    for tc, tech in technique_rows:
        tactics = [t.strip() for t in (tech.tactic or "unknown").split(",")]
        techniques.append({
            "attack_id": tech.attack_id,
            "name": tech.name,
            "is_subtechnique": tech.is_subtechnique,
            "tactic": tactics[0] if tactics else "unknown",
            "tactics": tactics,
            "actors": actors_by_technique.get(tech.id, []),
        })

    return {
        "id": control.id,
        "control_id": control.control_id,
        "name": control.name,
        "control_group": control.control_group,
        "framework": control.framework,
        "technique_count": len(techniques),
        "actor_count": len({a["id"] for t in techniques for a in t["actors"]}),
        "techniques": techniques,
    }
