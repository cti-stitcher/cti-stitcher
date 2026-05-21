"""
/api/search — alias resolution endpoint.
"""

from fastapi import APIRouter, Query, Request
from sqlalchemy.orm import Session

from core.resolution import ResolutionIndex
from explorer.api.actors import _actor_summary

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
def search_actors(
    q: str = Query(..., min_length=1, description="Actor name or alias to search"),
    limit: int = Query(10, le=50),
    request: Request = None,
):
    """
    Search for actors by any known alias.
    Returns exact match first if found, then fuzzy candidates.
    """
    resolver: ResolutionIndex = request.app.state.resolver
    db: Session = request.app.state.db_session

    results = resolver.search(q, limit=limit)

    if not results:
        return {"query": q, "results": []}

    actors_out = []
    seen_ids = set()
    for res in results:
        if res.actor_id in seen_ids:
            continue
        seen_ids.add(res.actor_id)

        from core.models import Actor
        actor = db.query(Actor).filter_by(id=res.actor_id).first()
        if actor:
            summary = _actor_summary(actor, db)
            summary["match_type"] = res.match_type
            summary["matched_alias"] = res.matched_alias
            actors_out.append(summary)

    return {"query": q, "results": actors_out}
