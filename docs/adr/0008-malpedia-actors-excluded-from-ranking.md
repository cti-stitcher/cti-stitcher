# ADR-0008: Malpedia-only actors excluded from risk ranking

**Status:** Accepted

## Context

The Malpedia connector adds 2,300+ actors that do not appear in the ATT&CK dataset (`in_attack=False`). These actors have alias data, malware family associations, and sometimes `last_seen` and `country_code` attributes, but they almost never have ATT&CK technique associations — which means their posture exposure and critical tactic scores would always fall back to the neutral values (17 and 12 respectively).

## Decision

The `/api/rank` endpoint filters to `Actor.in_attack == True`. Malpedia-only actors are excluded from the ranking entirely.

A ranking where 2,300 actors all score identically on the two highest-weighted components (60% of the score) would produce a meaningless leaderboard dominated by recency and targeting noise rather than genuine posture signal.

## Consequences

- Analysts cannot rank Malpedia-only actors against ATT&CK actors in a single view.
- If a Malpedia actor is later linked to ATT&CK (i.e. ATT&CK adds a group entry and the sync resolves the alias), they will appear in future ranking runs automatically.
- If technique data for Malpedia actors becomes available (e.g. via a future Malpedia API endpoint or a contributed crosswalk), this decision should be revisited.
