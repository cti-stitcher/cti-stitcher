# ADR-0005: Enforced connector run order

**Status:** Accepted

## Context

Connectors share a single database and build on each other's output. `ctid_nist80053` joins against `Technique.attack_id` rows that only exist after `attack` has run. Alias resolution quality improves when ATT&CK's high-confidence aliases are written before lower-confidence sources (Malpedia) attempt to match against them.

## Decision

The sync sequence is fixed and enforced in `explorer/api/sync.py`:

```
attack → ctid_nist80053 → d3fend → misp_galaxy → malpedia → mandiant
```

All connectors are idempotent — re-running the full sequence is safe and preferred over running a subset. After the full sequence, `ResolutionIndex.rebuild()` is called once.

## Consequences

- `ctid_nist80053` silently skips any technique ID it cannot find in the DB — a partial `attack` run will produce incomplete control mappings with no error.
- Adding a new connector that depends on an existing one's output must be inserted after its dependency in the sequence.
- Connectors that have no inter-dependencies (e.g. a future ISAC feed) can be appended at the end without risk.
