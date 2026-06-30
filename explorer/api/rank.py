"""
/api/rank  — threat actor risk ranking.

Scores actors against the user's selected region/industry context and their
current control posture. Returns actors sorted by risk score descending.

Scoring model (100 pts total):
  Targeting relevance   20 pts  — industry + region/country match
  Posture exposure      35 pts  — % of actor's techniques not covered by user's posture
  Critical tactic exp.  25 pts  — exposure specifically on Initial Access, Execution,
                                   Privilege Escalation, Defense Evasion
                                   (these tactics = "can they get in and stay in")
  Recency               20 pts  — based on last_seen date

Ransomware ecosystem flag: surfaced separately, not baked into score, so it
doesn't obscure the posture signal for pure initial-access brokers.

Coverage definition (consistent with gap analysis):
  A technique is "covered" if the user has:
    - at least one implemented NIST 800-53 control that mitigates it, OR
    - at least one deployed D3FEND countermeasure that addresses it
  Partial D3FEND counts as 0.5 coverage (reflected in score weighting).
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query
from sqlalchemy import func

from core.db import get_session
from core.models import (
    Actor, ActorTechnique, ActorSoftware, Software,
    ControlPosture, TechniqueControl,
    D3FendPosture, TechniqueD3Fend,
    Technique, Targeting,
)

router = APIRouter(tags=["rank"])

# Tactics that represent the "getting in and staying in" phase — highest impact
CRITICAL_TACTICS = {
    "initial-access",
    "execution",
    "privilege-escalation",
    "defense-evasion",
    "persistence",
    "lateral-movement",
}

# Recency scoring thresholds (days)
RECENCY = [
    (365,   20),   # active within 1 year
    (730,   12),   # active within 2 years
    (1825,   6),   # active within 5 years
]
RECENCY_UNKNOWN = 8  # don't penalize unknown — absence of evidence isn't evidence of absence


def _days_since(dt_str: Optional[str]) -> Optional[int]:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _recency_score(actor: Actor) -> int:
    days = _days_since(actor.last_seen)
    if days is None:
        return RECENCY_UNKNOWN
    for threshold, pts in RECENCY:
        if days <= threshold:
            return pts
    return 0  # seen, but activity is too old to be relevant


def _is_ransomware_related(actor: Actor, software_names: list[str]) -> bool:
    """
    Heuristic flag: actor is likely an initial-access broker or ransomware operator
    if their description mentions ransomware, or they're associated with known
    ransomware families.
    """
    desc = (actor.description or "").lower()
    if "ransomware" in desc or "ransom" in desc:
        return True
    ransomware_keywords = {"ransomware", "locker", "cryptor", "crypt0r"}
    for name in software_names:
        if any(kw in name.lower() for kw in ransomware_keywords):
            return True
    return False


@router.get("/api/rank")
def rank_actors(
    industry: Optional[str] = Query(None, description="Target industry to filter on"),
    region:   Optional[str] = Query(None, description="Target region or country to filter on"),
    limit:    int            = Query(50, le=200),
):
    """
    Return top actors ranked by risk score for the given industry/region context,
    weighted by the user's current posture gaps.
    """
    with get_session() as db:

        # ── 1. Build posture coverage sets ──────────────────────────────────

        # NIST: technique IDs covered by at least one implemented control
        implemented_control_ids: set[int] = {
            r.control_id
            for r in db.query(ControlPosture).filter_by(implemented=True).all()
        }
        if implemented_control_ids:
            nist_covered: set[int] = {
                r.technique_id
                for r in db.query(TechniqueControl)
                .filter(TechniqueControl.control_id.in_(implemented_control_ids))
                .all()
            }
        else:
            nist_covered = set()

        # D3FEND: technique IDs covered by deployed or partial countermeasures
        # deployed = full cover, partial = 0.5 cover (tracked separately for scoring)
        d3fend_posture: dict[int, str] = {
            r.d3fend_technique_id: r.status
            for r in db.query(D3FendPosture).all()
        }
        deployed_d3fend_ids: set[int] = {k for k, v in d3fend_posture.items() if v == "deployed"}
        partial_d3fend_ids:  set[int] = {k for k, v in d3fend_posture.items() if v == "partial"}

        # technique_id -> D3FEND coverage level: "full" | "partial" | None
        d3fend_tech_coverage: dict[int, str] = {}
        for row in db.query(TechniqueD3Fend).all():
            tid = row.technique_id
            did = row.d3fend_technique_id
            if did in deployed_d3fend_ids:
                d3fend_tech_coverage[tid] = "full"
            elif did in partial_d3fend_ids and d3fend_tech_coverage.get(tid) != "full":
                d3fend_tech_coverage[tid] = "partial"

        def is_covered(technique_id: int) -> bool:
            return (
                technique_id in nist_covered
                or d3fend_tech_coverage.get(technique_id) == "full"
            )

        def coverage_weight(technique_id: int) -> float:
            """0 = uncovered, 0.5 = partial D3FEND only, 1.0 = fully covered."""
            if technique_id in nist_covered:
                return 1.0
            level = d3fend_tech_coverage.get(technique_id)
            if level == "full":
                return 1.0
            if level == "partial":
                return 0.5
            return 0.0

        posture_configured = bool(implemented_control_ids or deployed_d3fend_ids or partial_d3fend_ids)

        # ── 2. Resolve actors matching targeting criteria ────────────────────

        actor_query = db.query(Actor).filter(Actor.in_attack == True)

        if industry or region:
            # Subquery: actor IDs that match targeting criteria
            target_q = db.query(Targeting.actor_id)
            conditions = []
            if industry:
                conditions.append(
                    (Targeting.target_type == "industry") &
                    (func.lower(Targeting.value) == industry.lower())
                )
            if region:
                conditions.append(
                    ((Targeting.target_type == "region") | (Targeting.target_type == "country")) &
                    (func.lower(Targeting.value) == region.lower())
                )
            from sqlalchemy import or_
            if len(conditions) == 1:
                target_q = target_q.filter(conditions[0])
            else:
                # Both must match — intersect
                industry_ids = {
                    r.actor_id for r in db.query(Targeting.actor_id)
                    .filter(
                        (Targeting.target_type == "industry") &
                        (func.lower(Targeting.value) == industry.lower())
                    ).all()
                } if industry else None

                region_ids = {
                    r.actor_id for r in db.query(Targeting.actor_id)
                    .filter(
                        or_(Targeting.target_type == "region", Targeting.target_type == "country"),
                        func.lower(Targeting.value) == region.lower()
                    ).all()
                } if region else None

                if industry_ids is not None and region_ids is not None:
                    matched_ids = industry_ids & region_ids
                elif industry_ids is not None:
                    matched_ids = industry_ids
                else:
                    matched_ids = region_ids

                if not matched_ids:
                    return {"filters": {"industry": industry, "region": region},
                            "posture_configured": posture_configured, "actors": []}

                actor_query = actor_query.filter(Actor.id.in_(matched_ids))

        actors = actor_query.all()
        if not actors:
            return {"filters": {"industry": industry, "region": region},
                    "posture_configured": posture_configured, "actors": []}

        # ── 3. Bulk-load techniques for all matched actors ───────────────────

        actor_ids = [a.id for a in actors]
        all_at = (
            db.query(ActorTechnique, Technique)
            .join(Technique, ActorTechnique.technique_id == Technique.id)
            .filter(ActorTechnique.actor_id.in_(actor_ids))
            .all()
        )

        # actor_id -> list of (technique_id, tactic)
        actor_techniques: dict[int, list[tuple[int, str]]] = {}
        for at, tech in all_at:
            actor_techniques.setdefault(at.actor_id, []).append(
                (tech.id, tech.tactic or "unknown")
            )

        # ── 4. Bulk-load software for ransomware flag ────────────────────────

        all_sw = (
            db.query(ActorSoftware, Software)
            .join(Software, ActorSoftware.software_id == Software.id)
            .filter(ActorSoftware.actor_id.in_(actor_ids))
            .all()
        )
        actor_software_names: dict[int, list[str]] = {}
        for asw, sw in all_sw:
            actor_software_names.setdefault(asw.actor_id, []).append(sw.name)

        # ── 5. Targeting match sets (for score component) ────────────────────

        industry_actor_ids: set[int] = set()
        region_actor_ids:   set[int] = set()

        if industry:
            industry_actor_ids = {
                r.actor_id for r in db.query(Targeting.actor_id)
                .filter(
                    Targeting.target_type == "industry",
                    func.lower(Targeting.value) == industry.lower(),
                    Targeting.actor_id.in_(actor_ids),
                ).all()
            }
        if region:
            from sqlalchemy import or_ as _or
            region_actor_ids = {
                r.actor_id for r in db.query(Targeting.actor_id)
                .filter(
                    _or(Targeting.target_type == "region", Targeting.target_type == "country"),
                    func.lower(Targeting.value) == region.lower(),
                    Targeting.actor_id.in_(actor_ids),
                ).all()
            }

        # ── 6. Score each actor ──────────────────────────────────────────────

        results = []
        for actor in actors:
            techs = actor_techniques.get(actor.id, [])
            sw_names = actor_software_names.get(actor.id, [])
            total = len(techs)

            # -- Targeting relevance (20 pts) --
            industry_match = actor.id in industry_actor_ids if industry else None
            region_match   = actor.id in region_actor_ids   if region   else None
            targeting_score = 0
            if industry and industry_match: targeting_score += 12
            if region   and region_match:   targeting_score += 8
            # No filters → full targeting score (not penalizing for lack of filter)
            if not industry and not region:  targeting_score = 20

            # -- Posture exposure (35 pts) --
            if total == 0 or not posture_configured:
                exposure_score = 17  # neutral — no data to penalise or reward
            else:
                uncovered_weight = sum(
                    1.0 - coverage_weight(tid) for tid, _ in techs
                )
                exposure_frac = uncovered_weight / total
                exposure_score = round(exposure_frac * 35)

            # -- Critical tactic exposure (25 pts) --
            critical_techs = [
                (tid, tac) for tid, tac in techs
                if any(t.strip() in CRITICAL_TACTICS for t in tac.split(","))
            ]
            n_critical = len(critical_techs)
            if n_critical == 0 or not posture_configured:
                critical_score = 12  # neutral
            else:
                uncovered_critical = sum(
                    1.0 - coverage_weight(tid) for tid, _ in critical_techs
                )
                critical_score = round((uncovered_critical / n_critical) * 25)

            # -- Recency (20 pts) --
            recency_score = _recency_score(actor)

            total_score = targeting_score + exposure_score + critical_score + recency_score

            results.append({
                "id":              actor.id,
                "name":            actor.name,
                "attack_group_id": actor.attack_group_id,
                "country_code":    actor.country_code,
                "last_seen":       actor.last_seen,
                "ttp_count":       total,
                "critical_ttp_count": n_critical,
                "score":           total_score,
                "score_breakdown": {
                    "targeting":  targeting_score,
                    "exposure":   exposure_score,
                    "critical":   critical_score,
                    "recency":    recency_score,
                },
                "industry_match":  industry_match,
                "region_match":    region_match,
                "ransomware_flag": _is_ransomware_related(actor, sw_names),
            })

        results.sort(key=lambda r: -r["score"])

        return {
            "filters": {"industry": industry, "region": region},
            "posture_configured": posture_configured,
            "actors": results[:limit],
        }
