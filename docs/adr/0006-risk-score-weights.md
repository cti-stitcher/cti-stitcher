# ADR-0006: Risk score weights (20/35/25/20)

**Status:** Accepted

## Context

The risk ranking model needed a single comparable score across actors so analysts could prioritise which threats to address first. Four signals are available: whether the actor targets the analyst's sector/region, how exposed the org's posture is to the actor's techniques, whether those techniques concentrate in high-impact kill-chain phases, and how recently the actor was active.

## Decision

100-point model with the following weights:

| Component | Weight | Rationale |
|---|---|---|
| Targeting relevance | 20 pts | Intentionally underweighted — targeting data is derived from keyword extraction on ATT&CK descriptions and MISP Galaxy fields, making it medium-confidence and noisy. A sector match should influence the score but not dominate it. |
| Posture exposure | 35 pts | Primary signal. Measures the fraction of the actor's techniques not covered by the org's current NIST/D3FEND posture. |
| Critical tactic exposure | 25 pts | Secondary posture signal. Measures exposure specifically on the highest-impact kill-chain phases (initial-access, execution, privilege-escalation, defense-evasion, persistence, lateral-movement). |
| Recency | 20 pts | Measures how recently the actor was observed active. Actors with no `last_seen` date get a neutral 8 pts — absence of evidence is not evidence of absence. Actors last seen >5 years ago score 0. |

Posture exposure and critical tactic exposure together account for 60% of the score because posture quality is the primary analytical question this tool answers.

## Consequences

- Targeting-only analysis (no posture configured) produces less differentiated scores; exposure and critical components fall back to neutral values (17 and 12 respectively).
- The 35/25 posture split may need rebalancing as the critical tactic set evolves.
- Weights came from iterative tuning, not a validated threat-scoring framework. Consider benchmarking against CVSS, DREAD, or a red-team's intuitive ranking as a future calibration step.
