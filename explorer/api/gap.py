"""
/api/posture  — read and toggle the org's NIST 800-53 control posture.
/api/gap/all  — aggregate coverage leaderboard across all actors.
/api/gap/{id} — per-actor gap analysis: which techniques are covered vs. not.

Posture is stored in the control_posture table and is entirely user-managed
(no connector writes to it). The gap analysis joins posture against the
TechniqueControl crosswalk to determine coverage.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.db import get_session
from core.models import (
    Actor, ActorTechnique, Control, ControlPosture, Technique, TechniqueControl,
)

router = APIRouter(tags=["gap"])


def _db():
    with get_session() as s:
        yield s


# ---------------------------------------------------------------------------
# Posture endpoints
# ---------------------------------------------------------------------------

@router.get("/api/posture")
def get_posture(db: Session = Depends(_db)):
    """Return the set of control DB IDs currently marked as implemented."""
    rows = db.query(ControlPosture).filter_by(implemented=True).all()
    return {"implemented_control_ids": [r.control_id for r in rows]}


@router.post("/api/posture/{control_id}/toggle")
def toggle_posture(control_id: str, db: Session = Depends(_db)):
    """
    Toggle a control's implemented status.
    control_id is the string ID (e.g. "AC-02"), not the DB pk.
    Returns the new state.
    """
    control = db.query(Control).filter(Control.control_id == control_id.upper()).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    posture = db.query(ControlPosture).filter_by(control_id=control.id).first()
    if posture:
        posture.implemented = not posture.implemented
    else:
        posture = ControlPosture(control_id=control.id, implemented=True)
        db.add(posture)

    db.commit()
    return {"control_id": control_id.upper(), "implemented": posture.implemented}


# ---------------------------------------------------------------------------
# Aggregate gap analysis  GET /api/gap/all
# ---------------------------------------------------------------------------

@router.get("/api/gap/all")
def get_gap_all(db: Session = Depends(_db)):
    """
    Coverage leaderboard across all actors with techniques.

    Batch approach — 3 queries total regardless of actor count:
      1. Implemented control IDs from posture table.
      2. All technique IDs covered by those controls (via TechniqueControl).
      3. All ActorTechnique rows to compute per-actor coverage.

    Returns actors sorted ascending by coverage_pct (most exposed first).
    """
    implemented_ids: set[int] = {
        r.control_id
        for r in db.query(ControlPosture).filter_by(implemented=True).all()
    }

    # Technique IDs that have at least one implemented control
    if implemented_ids:
        covered_technique_ids: set[int] = {
            tc.technique_id
            for tc in db.query(TechniqueControl)
            .filter(TechniqueControl.control_id.in_(implemented_ids))
            .all()
        }
    else:
        covered_technique_ids = set()

    # Batch load all actor-technique links
    all_at = db.query(ActorTechnique).all()
    techniques_by_actor: dict[int, list[int]] = {}
    for at in all_at:
        techniques_by_actor.setdefault(at.actor_id, []).append(at.technique_id)

    actors = db.query(Actor).order_by(Actor.name).all()

    result = []
    for actor in actors:
        tech_ids = techniques_by_actor.get(actor.id, [])
        if not tech_ids:
            continue
        total = len(tech_ids)
        covered = sum(1 for tid in tech_ids if tid in covered_technique_ids)
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
        "posture": {"implemented_control_count": len(implemented_ids)},
        "actors": result,
    }


# ---------------------------------------------------------------------------
# Per-actor gap analysis  GET /api/gap/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/api/gap/{actor_id}")
def get_gap(actor_id: int, db: Session = Depends(_db)):
    """
    Per-actor gap analysis.

    Returns actor's techniques split into:
    - covered: at least one implemented control mitigates this technique
    - not_covered: no implemented control mitigates this technique

    Each not_covered technique lists which available (but not-yet-implemented)
    controls would mitigate it, as a prioritization hint.
    """
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    # Implemented control DB IDs (set for O(1) lookup)
    implemented_ids: set[int] = {
        r.control_id
        for r in db.query(ControlPosture).filter_by(implemented=True).all()
    }

    # All techniques used by this actor
    actor_techniques = (
        db.query(ActorTechnique, Technique)
        .join(Technique, ActorTechnique.technique_id == Technique.id)
        .filter(ActorTechnique.actor_id == actor_id)
        .all()
    )

    if not actor_techniques:
        return _gap_response(actor, [], [], implemented_count=len(implemented_ids))

    technique_ids = [tech.id for _, tech in actor_techniques]

    # All controls mapped to those techniques (batch load)
    control_rows = (
        db.query(TechniqueControl, Control)
        .join(Control, TechniqueControl.control_id == Control.id)
        .filter(TechniqueControl.technique_id.in_(technique_ids))
        .all()
    )

    # controls_by_technique: technique_db_id -> list of (control_db_id, control_id_str, name)
    controls_by_technique: dict[int, list[tuple]] = {}
    for tc, ctrl in control_rows:
        controls_by_technique.setdefault(tc.technique_id, []).append(
            (ctrl.id, ctrl.control_id, ctrl.name)
        )

    covered = []
    not_covered = []

    for at, tech in actor_techniques:
        tactics = [t.strip() for t in (tech.tactic or "unknown").split(",")]
        mapped_controls = controls_by_technique.get(tech.id, [])

        implemented_controls = [
            {"control_id": cid_str, "name": cname}
            for db_id, cid_str, cname in sorted(mapped_controls, key=lambda x: x[1])
            if db_id in implemented_ids
        ]
        available_controls = [
            {"control_id": cid_str, "name": cname}
            for db_id, cid_str, cname in sorted(mapped_controls, key=lambda x: x[1])
            if db_id not in implemented_ids
        ]

        tech_dict = {
            "attack_id": tech.attack_id,
            "name": tech.name,
            "is_subtechnique": tech.is_subtechnique,
            "tactic": tactics[0] if tactics else "unknown",
            "tactics": tactics,
            "total_controls": len(mapped_controls),
        }

        if not mapped_controls:
            # No controls mapped at all in CTID crosswalk — treat as grey zone
            tech_dict["available_controls"] = []
            tech_dict["note"] = "no_mapping"
            not_covered.append(tech_dict)
        elif implemented_controls:
            tech_dict["implemented_controls"] = implemented_controls
            covered.append(tech_dict)
        else:
            tech_dict["available_controls"] = available_controls
            not_covered.append(tech_dict)

    # Sort each bucket by attack_id
    covered.sort(key=lambda t: t["attack_id"])
    not_covered.sort(key=lambda t: t["attack_id"])

    return _gap_response(actor, covered, not_covered, implemented_count=len(implemented_ids))


def _gap_response(actor: Actor, covered: list, not_covered: list, implemented_count: int) -> dict:
    total = len(covered) + len(not_covered)
    coverage_pct = round(len(covered) / total * 100) if total else 0
    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "attack_group_id": actor.attack_group_id,
            "country_code": actor.country_code,
        },
        "posture": {
            "implemented_control_count": implemented_count,
        },
        "summary": {
            "total_techniques": total,
            "covered": len(covered),
            "not_covered": len(not_covered),
            "coverage_pct": coverage_pct,
        },
        "covered": covered,
        "not_covered": not_covered,
    }
