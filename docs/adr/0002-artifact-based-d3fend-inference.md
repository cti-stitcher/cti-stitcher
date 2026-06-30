# ADR-0002: Artifact-based inference for ATT&CK ↔ D3FEND mapping

**Status:** Accepted

## Context

MITRE does not publish a flat ATT&CK-to-D3FEND mapping file. The D3FEND ontology encodes relationships via OWL properties: both offensive techniques and defensive countermeasures declare actions on **digital artifacts** (processes, files, network packets, registry keys, etc.). The d3fend.mitre.org website derives its technique↔countermeasure links by walking these artifact relationships at query time.

## Decision

Replicate d3fend.mitre.org's inference locally. During ingestion, build two indexes from the ontology JSON-LD:

1. `artifact_to_attacks` — artifact node → set of ATT&CK technique IDs (via `_OFFENSIVE_VERBS`)
2. Per countermeasure: scan `_DEFENSIVE_VERBS` properties for artifact references, resolve those artifacts through `artifact_to_attacks`, and write `TechniqueD3Fend` rows for each hit.

Blank nodes (`_:N...`) are OWL restriction nodes and must be excluded from artifact matching.

## Consequences

- Mappings stay current whenever the D3FEND ontology is re-fetched — no manual crosswalk file to maintain.
- Coverage is only as good as the ontology's artifact annotations; techniques with sparse OWL metadata will have fewer countermeasure links.
- The `no_mapping` bucket exists precisely for techniques the inference finds no D3FEND link for; these are excluded from the coverage denominator.
