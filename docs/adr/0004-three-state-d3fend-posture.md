# ADR-0004: Three-state D3FEND posture (not_deployed / partial / deployed)

**Status:** Accepted  
**Supersedes:** the original boolean `implemented` column (removed in v6 migration)

## Context

Real defensive deployments are rarely binary. A SIEM rule might be deployed in one environment but not another; an EDR capability might be licensed but not tuned. Forcing a boolean choice was causing analysts to either over-report coverage (marking partial deployments as "deployed") or under-report it (leaving useful partial controls as "not deployed"), both of which distort the gap analysis.

## Decision

Replace the boolean `implemented` with a three-state `status` enum: `not_deployed` (default), `partial`, `deployed`. In all coverage arithmetic, `partial` counts as **0.5**. The toggle cycles `not_deployed → partial → deployed → not_deployed`.

NIST 800-53 controls retain a boolean `implemented` (the control is either in policy or it isn't); the three-state model applies only to D3FEND countermeasures, where deployment granularity matters most.

## Consequences

- Coverage percentages more accurately reflect real-world posture.
- The 0.5 weight for `partial` is a deliberate conservative estimate — it acknowledges the capability exists without crediting full protection.
- Any new coverage calculation added to the codebase must use `(covered + 0.5 × partial_covered) / mappable` — do not simplify to binary.
