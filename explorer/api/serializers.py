"""
Shared serializers for API responses.

Centralises dict-shaping logic that is reused across multiple route modules
so that route files don't need to import each other.
"""

from sqlalchemy.orm import Session

from core.models import Actor, Alias, ActorTechnique, Targeting


def actor_summary(actor: Actor, db: Session) -> dict:
    """Lightweight actor representation used in list and search responses."""
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
