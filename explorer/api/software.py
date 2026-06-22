"""
/api/software                 — list all software (tools + malware) with actor counts.
/api/software/{software_id}   — detail: software info + all actors that use it + overlap.

The overlap section answers: "which other actors in this list share the most tools
with each other?" Useful for spotting infrastructure clusters and attribution hints.
"""

from fastapi import APIRouter, HTTPException
from sqlalchemy import func

from core.db import get_session
from core.models import Actor, ActorSoftware, Software

router = APIRouter(tags=["software"])


# ---------------------------------------------------------------------------
# Software list  GET /api/software
# ---------------------------------------------------------------------------

@router.get("/api/software")
def list_software():
    """All software entries with actor_count, sorted by actor_count desc."""
    with get_session() as db:
        rows = (
            db.query(Software, func.count(ActorSoftware.id).label("actor_count"))
            .outerjoin(ActorSoftware, Software.id == ActorSoftware.software_id)
            .group_by(Software.id)
            .order_by(func.count(ActorSoftware.id).desc())
            .all()
        )
        return [
            {
                "id": sw.id,
                "attack_id": sw.attack_id,
                "name": sw.name,
                "software_type": sw.software_type,
                "actor_count": count,
            }
            for sw, count in rows
        ]


# ---------------------------------------------------------------------------
# Software detail  GET /api/software/{software_id}
# ---------------------------------------------------------------------------

@router.get("/api/software/{software_id}")
def get_software(software_id: int):
    """
    Software detail + all actors that use it + shared-tool overlap.

    Overlap: for each actor in the list, counts how many OTHER tools (beyond
    this one) are shared with at least one other actor in the same list.
    High overlap = likely infrastructure sharing or common tradecraft cluster.
    """
    with get_session() as db:
        sw = db.query(Software).filter_by(id=software_id).first()
        if not sw:
            raise HTTPException(status_code=404, detail="Software not found")

        # All actors that use this software
        actor_rows = (
            db.query(Actor)
            .join(ActorSoftware, Actor.id == ActorSoftware.actor_id)
            .filter(ActorSoftware.software_id == software_id)
            .order_by(Actor.name)
            .all()
        )

        if not actor_rows:
            return {
                "software": _sw_dict(sw),
                "actors": [],
                "total_actors": 0,
            }

        actor_ids = [a.id for a in actor_rows]

        # For each actor, get their full software list
        all_links = (
            db.query(ActorSoftware, Software)
            .join(Software, ActorSoftware.software_id == Software.id)
            .filter(ActorSoftware.actor_id.in_(actor_ids))
            .all()
        )

        # actor_id -> set of software IDs (excluding the current one)
        actor_sw_sets: dict[int, set[int]] = {}
        actor_sw_names: dict[int, list[str]] = {}
        for link, s in all_links:
            if s.id == software_id:
                continue
            actor_sw_sets.setdefault(link.actor_id, set()).add(s.id)
            actor_sw_names.setdefault(link.actor_id, [])
            if s.name not in actor_sw_names[link.actor_id]:
                actor_sw_names[link.actor_id].append(s.name)

        # Shared-tool overlap: for each actor, how many of their OTHER tools
        # are also used by at least one other actor in this list
        all_other_sw: set[int] = set()
        for sw_set in actor_sw_sets.values():
            all_other_sw |= sw_set

        # sw_id -> how many actors (in this list) use it
        sw_usage: dict[int, int] = {}
        for sw_set in actor_sw_sets.values():
            for sid in sw_set:
                sw_usage[sid] = sw_usage.get(sid, 0) + 1

        # Shared sw ids = used by ≥2 actors in this list
        shared_sw_ids: set[int] = {sid for sid, cnt in sw_usage.items() if cnt >= 2}

        actors_out = []
        for actor in actor_rows:
            own_sw = actor_sw_sets.get(actor.id, set())
            shared_count = len(own_sw & shared_sw_ids)
            shared_names = sorted([
                name for name in actor_sw_names.get(actor.id, [])
                if any(
                    s.id in shared_sw_ids
                    for link, s in all_links
                    if link.actor_id == actor.id and s.name == name
                )
            ])[:8]  # cap at 8 for display
            actors_out.append({
                "id": actor.id,
                "name": actor.name,
                "attack_group_id": actor.attack_group_id,
                "country_code": actor.country_code,
                "total_software": len(own_sw) + 1,  # +1 for current tool
                "shared_tool_count": shared_count,
                "shared_tools": shared_names,
            })

        # Sort: most shared tools first, then alphabetically
        actors_out.sort(key=lambda a: (-a["shared_tool_count"], a["name"]))

        return {
            "software": _sw_dict(sw),
            "actors": actors_out,
            "total_actors": len(actors_out),
        }


def _sw_dict(sw: Software) -> dict:
    return {
        "id": sw.id,
        "attack_id": sw.attack_id,
        "name": sw.name,
        "software_type": sw.software_type,
        "description": sw.description,
    }
