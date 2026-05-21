"""
Actor alias resolution index — the Rosetta Stone engine.

Built in memory at startup from the aliases table.
Rebuilt automatically after any sync.

Usage:
    resolver = ResolutionIndex(session)
    result = resolver.resolve("Cozy Bear")
    # result.actor_id, result.attack_group_id, result.canonical_name, result.confidence
"""

import re
from dataclasses import dataclass
from typing import Optional

from rapidfuzz import process, fuzz
from sqlalchemy.orm import Session

from core.models import Actor, Alias

FUZZY_THRESHOLD = 85  # minimum score (0-100) for a fuzzy match to count


@dataclass
class ResolveResult:
    actor_id: int
    canonical_name: str
    attack_group_id: Optional[str]
    confidence: str          # high / medium / low
    match_type: str          # exact / fuzzy / none
    matched_alias: str       # which alias string was matched


class ResolutionIndex:
    """
    In-memory index mapping normalized alias strings to actor records.
    Instantiate once at app startup; call rebuild() after any sync.
    """

    def __init__(self, session: Session):
        self._session = session
        self._index: dict[str, ResolveResult] = {}
        self._norm_list: list[str] = []
        self.rebuild()

    def rebuild(self) -> None:
        """Reload all aliases from the database and rebuild the index."""
        self._index = {}

        rows = (
            self._session.query(Alias, Actor)
            .join(Actor, Alias.actor_id == Actor.id)
            .all()
        )

        for alias_row, actor_row in rows:
            norm = alias_row.alias_normalized
            # Higher-confidence sources win if there's a collision on the normalized key
            if norm in self._index:
                existing = self._index[norm]
                if _confidence_rank(alias_row.confidence) <= _confidence_rank(existing.confidence):
                    continue  # keep the higher-confidence entry

            self._index[norm] = ResolveResult(
                actor_id=actor_row.id,
                canonical_name=actor_row.name,
                attack_group_id=actor_row.attack_group_id,
                confidence=alias_row.confidence,
                match_type="exact",
                matched_alias=alias_row.alias,
            )

        self._norm_list = list(self._index.keys())
        print(f"[resolution] Index built: {len(self._norm_list)} aliases")

    def resolve(self, query: str) -> Optional[ResolveResult]:
        """
        Resolve a free-text actor name to a canonical actor.

        1. Exact match on normalized string (fast dict lookup)
        2. Fuzzy match via rapidfuzz (slower, used as fallback)
        3. None if no match above threshold
        """
        if not query or not query.strip():
            return None

        norm = _normalize(query)

        # --- Exact match ---
        if norm in self._index:
            result = self._index[norm]
            result.match_type = "exact"
            return result

        # --- Fuzzy match ---
        if not self._norm_list:
            return None

        best = process.extractOne(
            norm,
            self._norm_list,
            scorer=fuzz.token_sort_ratio,
            score_cutoff=FUZZY_THRESHOLD,
        )

        if best is None:
            return None

        matched_norm, score, _ = best
        result = self._index[matched_norm]

        # Downgrade confidence for fuzzy matches
        fuzzy_confidence = "medium" if score >= 92 else "low"
        return ResolveResult(
            actor_id=result.actor_id,
            canonical_name=result.canonical_name,
            attack_group_id=result.attack_group_id,
            confidence=fuzzy_confidence,
            match_type="fuzzy",
            matched_alias=result.matched_alias,
        )

    def search(self, query: str, limit: int = 10) -> list[ResolveResult]:
        """
        Return up to `limit` actors whose aliases contain the query string.
        Used for the browse/search view — returns multiple candidates.
        """
        if not query or not query.strip():
            return []

        norm = _normalize(query)
        seen_actors: set[int] = set()
        results: list[ResolveResult] = []

        # Substring matches first
        for key, result in self._index.items():
            if norm in key and result.actor_id not in seen_actors:
                seen_actors.add(result.actor_id)
                results.append(result)
                if len(results) >= limit:
                    return results

        # Fuzzy fill if we have room
        if len(results) < limit and self._norm_list:
            candidates = process.extract(
                norm,
                self._norm_list,
                scorer=fuzz.token_sort_ratio,
                limit=limit * 2,
                score_cutoff=FUZZY_THRESHOLD,
            )
            for matched_norm, score, _ in candidates:
                result = self._index[matched_norm]
                if result.actor_id not in seen_actors:
                    seen_actors.add(result.actor_id)
                    results.append(ResolveResult(
                        actor_id=result.actor_id,
                        canonical_name=result.canonical_name,
                        attack_group_id=result.attack_group_id,
                        confidence="medium" if score >= 92 else "low",
                        match_type="fuzzy",
                        matched_alias=result.matched_alias,
                    ))
                if len(results) >= limit:
                    break

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Must match normalize_alias() in base.py exactly."""
    text = text.lower().strip()
    text = re.sub(r"[\s\-_\.]+", " ", text)
    text = re.sub(r"[^a-z0-9 ]", "", text)
    return text.strip()


def _confidence_rank(confidence: str) -> int:
    """Lower number = higher confidence."""
    return {"high": 0, "medium": 1, "low": 2}.get(confidence, 3)
