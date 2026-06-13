"""
/api/actors  — actor list and actor detail endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from core.db import get_session
from core.models import Actor, Alias, ActorTechnique, ActorSoftware, Targeting, Technique, Software, Control, TechniqueControl

router = APIRouter(prefix="/api/actors", tags=["actors"])


def _db():
    with get_session() as s:
        yield s


# ---------------------------------------------------------------------------
# List endpoint  GET /api/actors
# ---------------------------------------------------------------------------

@router.get("")
def list_actors(
    industry: Optional[str] = Query(None, description="Filter by target industry"),
    region: Optional[str] = Query(None, description="Filter by target region or country"),
    country_code: Optional[str] = Query(None, description="Filter by actor origin country (ISO code)"),
    limit: int = Query(200, le=500),
    db: Session = Depends(_db),
):
    """
    Return a list of actors with summary info.
    Supports filtering by target industry, region, and actor origin country.
    """
    query = db.query(Actor)

    if country_code:
        query = query.filter(Actor.country_code == country_code.upper())

    actors = query.order_by(Actor.name).limit(limit).all()

    # Apply industry/region filter via targeting table (post-fetch for simplicity)
    if industry or region:
        filtered = []
        for actor in actors:
            targets = db.query(Targeting).filter_by(actor_id=actor.id).all()
            target_values = [t.value.lower() for t in targets]
            if industry and industry.lower() not in target_values:
                continue
            if region and region.lower() not in target_values:
                continue
            filtered.append(actor)
        actors = filtered

    return [_actor_summary(actor, db) for actor in actors]


# ---------------------------------------------------------------------------
# Detail endpoint  GET /api/actors/{actor_id}
# ---------------------------------------------------------------------------

@router.get("/{actor_id}")
def get_actor(actor_id: int, db: Session = Depends(_db)):
    actor = db.query(Actor).filter_by(id=actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return _actor_detail(actor, db)


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _actor_summary(actor: Actor, db: Session) -> dict:
    aliases = db.query(Alias).filter_by(actor_id=actor.id).all()
    technique_count = db.query(ActorTechnique).filter_by(actor_id=actor.id).count()
    industries = [
        t.value for t in db.query(Targeting)
        .filter_by(actor_id=actor.id, target_type="industry").all()
    ]
    return {
        "id": actor.id,
        "name": actor.name,
        "attack_group_id": actor.attack_group_id,
        "country_code": actor.country_code,
        "technique_count": technique_count,
        "industries": sorted(set(industries)),
        "aliases": [
            {"alias": a.alias, "source": a.source, "confidence": a.confidence}
            for a in aliases
            if a.alias != actor.name
        ][:8],  # cap at 8 for list view
        "in_attack": actor.in_attack,
    }


def _actor_detail(actor: Actor, db: Session) -> dict:
    aliases = db.query(Alias).filter_by(actor_id=actor.id).all()

    # Techniques grouped by tactic
    actor_techniques = (
        db.query(ActorTechnique, Technique)
        .join(Technique, ActorTechnique.technique_id == Technique.id)
        .filter(ActorTechnique.actor_id == actor.id)
        .all()
    )
    # NIST 800-53 controls that mitigate these techniques (ctid_nist80053 connector)
    technique_ids = [tech.id for _, tech in actor_techniques]
    controls_by_technique: dict[int, list] = {}
    if technique_ids:
        control_rows = (
            db.query(TechniqueControl, Control)
            .join(Control, TechniqueControl.control_id == Control.id)
            .filter(TechniqueControl.technique_id.in_(technique_ids))
            .all()
        )
        for tc, control in control_rows:
            controls_by_technique.setdefault(tc.technique_id, []).append({
                "control_id": control.control_id,
                "name": control.name,
                "control_group": control.control_group,
                "framework": control.framework,
                "mapping_type": tc.mapping_type,
            })
        for lst in controls_by_technique.values():
            lst.sort(key=lambda c: c["control_id"])

    by_tactic: dict[str, list] = {}
    for at, tech in actor_techniques:
        for tactic in (tech.tactic or "unknown").split(","):
            tactic = tactic.strip()
            by_tactic.setdefault(tactic, []).append({
                "attack_id": tech.attack_id,
                "name": tech.name,
                "is_subtechnique": tech.is_subtechnique,
                "source": at.source,
                "controls": controls_by_technique.get(tech.id, []),
            })

    # Software
    actor_software = (
        db.query(ActorSoftware, Software)
        .join(Software, ActorSoftware.software_id == Software.id)
        .filter(ActorSoftware.actor_id == actor.id)
        .all()
    )

    # Targeting
    targeting = db.query(Targeting).filter_by(actor_id=actor.id).all()

    return {
        "id": actor.id,
        "name": actor.name,
        "attack_group_id": actor.attack_group_id,
        "stix_id": actor.stix_id,
        "country_code": actor.country_code,
        "first_seen": actor.first_seen,
        "last_seen": actor.last_seen,
        "description": actor.description,
        "in_attack": actor.in_attack,
        "aliases": [
            {"alias": a.alias, "source": a.source, "confidence": a.confidence}
            for a in sorted(aliases, key=lambda x: x.source)
        ],
        "techniques_by_tactic": by_tactic,
        "technique_count": sum(len(v) for v in by_tactic.values()),
        "software": [
            {"name": sw.name, "type": sw.software_type, "attack_id": sw.attack_id}
            for _, sw in actor_software
        ],
        "targeting": {
            "industries": sorted({t.value for t in targeting if t.target_type == "industry"}),
            "regions": sorted({t.value for t in targeting if t.target_type == "region"}),
            "countries": sorted({t.value for t in targeting if t.target_type == "country"}),
        },
        "mitre_url": f"https://attack.mitre.org/groups/{actor.attack_group_id}/" if actor.attack_group_id else None,
        "malpedia_url": None,  # populated by malpedia connector in future
    }
