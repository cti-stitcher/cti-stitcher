"""
/api/targeting/{target_type}/{value}  — all actors targeting a region, country, or industry.

target_type: region | country | industry
value: URL-encoded string matching Targeting.value (e.g. "Western Europe", "CN", "Financial")

Returns actors sorted by TTP count descending, with shared-TTP overlap counts
between actors in the list — useful for spotting converging threat campaigns.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from urllib.parse import unquote

from core.db import get_session
from core.models import Actor, ActorTechnique, Targeting

router = APIRouter(tags=["targeting"])

VALID_TYPES = {"region", "country", "industry"}


@router.get("/api/targeting/{target_type}/{value:path}")
def get_targeting(
    target_type: str,
    value: str,
    from_id: Optional[int] = Query(default=None),
):
    """
    All actors targeting the given region/country/industry.

    from_id (optional): when provided, shared_ttp_count/pct for each actor reflects
    overlap specifically with that source actor — i.e. "how similar is their
    tradecraft to the actor I just came from?"  When absent, falls back to
    "shared with ≥2 actors in this list" (cross-group convergence view).
    """
    if target_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"target_type must be one of: {', '.join(VALID_TYPES)}")

    decoded_value = unquote(value)

    with get_session() as db:
        actor_rows = (
            db.query(Actor)
            .join(Targeting, Actor.id == Targeting.actor_id)
            .filter(
                Targeting.target_type == target_type,
                Targeting.value == decoded_value,
            )
            .order_by(Actor.name)
            .distinct()
            .all()
        )

        if not actor_rows:
            return {
                "target_type": target_type,
                "value": decoded_value,
                "actors": [],
                "total_actors": 0,
                "from_id": from_id,
            }

        actor_ids = [a.id for a in actor_rows]

        # Fetch techniques for all actors in the list
        all_at = (
            db.query(ActorTechnique)
            .filter(ActorTechnique.actor_id.in_(actor_ids))
            .all()
        )
        actor_tech_sets: dict[int, set[int]] = {}
        for at in all_at:
            actor_tech_sets.setdefault(at.actor_id, set()).add(at.technique_id)

        # --- Overlap mode ---
        # from_id present → compare each actor against the source actor specifically
        # from_id absent  → compare against the whole list (convergence signal)
        if from_id is not None:
            # Fetch source actor's techniques (may or may not be in the target list)
            source_techs: set[int] = set(actor_tech_sets.get(from_id, set()))
            if not source_techs:
                source_at = (
                    db.query(ActorTechnique)
                    .filter(ActorTechnique.actor_id == from_id)
                    .all()
                )
                source_techs = {at.technique_id for at in source_at}

            def shared_info(actor_id: int) -> tuple[int, float]:
                own = actor_tech_sets.get(actor_id, set())
                count = len(own & source_techs)
                pct = round(count / len(own) * 100, 1) if own else 0.0
                return count, pct

            overlap_label = "with_source"
        else:
            # Cross-list convergence
            tech_usage: dict[int, int] = {}
            for tech_set in actor_tech_sets.values():
                for tid in tech_set:
                    tech_usage[tid] = tech_usage.get(tid, 0) + 1
            shared_tech_ids: set[int] = {tid for tid, cnt in tech_usage.items() if cnt >= 2}

            def shared_info(actor_id: int) -> tuple[int, float]:
                own = actor_tech_sets.get(actor_id, set())
                count = len(own & shared_tech_ids)
                pct = round(count / len(own) * 100, 1) if own else 0.0
                return count, pct

            overlap_label = "cross_list"

        actors_out = []
        for actor in actor_rows:
            own_techs = actor_tech_sets.get(actor.id, set())
            shared_count, shared_pct = shared_info(actor.id)
            actors_out.append({
                "id": actor.id,
                "name": actor.name,
                "attack_group_id": actor.attack_group_id,
                "country_code": actor.country_code,
                "ttp_count": len(own_techs),
                "shared_ttp_count": shared_count,
                "shared_ttp_pct": shared_pct,
            })

        # Sort: highest overlap % first, then raw count as tiebreaker
        # Push the source actor itself to the top regardless
        actors_out.sort(key=lambda a: (
            0 if a["id"] == from_id else 1,
            -a["shared_ttp_pct"],
            -a["shared_ttp_count"],
        ))

        return {
            "target_type": target_type,
            "value": decoded_value,
            "total_actors": len(actors_out),
            "overlap_mode": overlap_label,
            "from_id": from_id,
            "actors": actors_out,
        }
