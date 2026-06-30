# CONTEXT.md — cti-stitcher

## Purpose

cti-stitcher closes the gap between **what adversaries do** and **what defends against them**. It joins three disparate threat-knowledge systems — MITRE ATT&CK, NIST 800-53, and MITRE D3FEND — into a single local SQLite database and exposes a browser UI and REST API for analysis. No cloud, no vendor dependency.

The core question the tool answers: *Given my current defensive posture, which threat actors pose the greatest risk, and what should I deploy next to reduce exposure?*

---

## Domain Concepts

### TTP (Tactic, Technique, Procedure)

An adversary's methods. In this codebase:

- **Tactic** — a kill-chain phase name (e.g. `initial-access`, `execution`). A technique can belong to multiple tactics; stored as a comma-separated string in `Technique.tactic`.
- **Technique** — a MITRE ATT&CK technique or sub-technique identified by `attack_id` (e.g. `T1566`, `T1566.001`). Sub-techniques contain a dot in the ID.
- **Procedure** — the verbatim STIX relationship description of how a *specific actor* uses a *specific technique* (e.g. "APT29 used PowerShell to download payloads"). Only populated for ATT&CK-sourced relationships; null for Malpedia/MISP sources.

### Posture

The org's current defensive state — which NIST 800-53 controls are implemented and which D3FEND countermeasures are deployed. No connector writes posture; it is user-managed only.

### Gap

A technique an actor is known to use that the org's current posture does not cover. The gap is the primary output of the analysis.

### Coverage

How well the org's posture addresses a given actor's techniques.

**Formula:** `coverage_pct = (covered + 0.5 × partial_covered) / mappable × 100`

- **covered** — ≥1 deployed countermeasure or implemented control addresses this technique (weight: 1.0)
- **partial_covered** — ≥1 partial countermeasure, none deployed (weight: 0.5)
- **not_deployed** — mappings exist but none are deployed/implemented (weight: 0)
- **no_mapping** — no D3FEND or NIST mapping exists for this technique; excluded from the denominator entirely
- **mappable** — covered + partial_covered + not_deployed (the denominator)

### Artifact-Based Inference (D3FEND)

The strategy used to link ATT&CK techniques to D3FEND countermeasures. Both offensive techniques and defensive countermeasures declare relationships to **digital artifacts** (processes, files, network packets, etc.) via OWL properties. If a countermeasure acts on artifact X and an ATT&CK technique also acts on artifact X, they are linked. This mirrors d3fend.mitre.org's own inference engine.

---

## Entities

### Actor

A threat actor or intrusion set. Key attributes:

- `attack_group_id` — MITRE ATT&CK canonical group ID (e.g. `G0016`). Null for actors that exist only in Malpedia or MISP.
- `in_attack` — True if the actor exists in the ATT&CK dataset; False for Malpedia/MISP-only actors.
- `stix_id` — STIX 2.0 object ID used for cross-referencing the ATT&CK bundle.
- `country_code` — ISO 3166-1 alpha-2 attribution (e.g. `RU`, `CN`).

### Alias

Every name any source uses for an actor — the identity resolution layer.

- `alias_normalized` — canonical form for lookup: lowercased, separators (`-`, `_`, `.`, whitespace) collapsed to a single space, non-alphanumeric stripped.
- `source` — which connector wrote this row: `attack` / `misp_galaxy` / `malpedia` / `mandiant`.
- `confidence` — `high` / `medium` / `low`. On collision, higher confidence wins.

The unique constraint is `(actor_id, alias_normalized, source)` — the same name from different sources gets separate rows.

### Technique

A MITRE ATT&CK technique or sub-technique. `is_subtechnique` is True when `attack_id` contains a dot. Sub-techniques have a `parent_id` FK to their parent row.

### ActorTechnique

Association between an actor and a technique they are known to use. Contains the optional `procedure` citation.

### Control

A NIST 800-53 rev5 control. Identified by `control_id` (e.g. `AC-02`). Grouped by `control_group` (the family prefix, e.g. `AC`, `SC`).

### ControlPosture

User-managed table tracking which controls are implemented (`implemented: bool`). No connector writes here.

### TechniqueControl

The CTID crosswalk linking an ATT&CK technique to a NIST 800-53 control. Only `mapping_type == "mitigates"` rows are ingested; `non_mappable` entries are filtered out.

### D3FendTechnique

A MITRE D3FEND defensive countermeasure. Identified by `d3fend_id` (e.g. `D3-PSA`). Tactic is one of: `Harden`, `Detect`, `Isolate`, `Deceive`, `Evict`, `Restore`.

### D3FendPosture

User-managed three-state deployment status for each countermeasure.

- `not_deployed` (default) — not in use
- `partial` — partially deployed; counts as 0.5 in all coverage math
- `deployed` — fully deployed; counts as 1.0

Toggling cycles `not_deployed → partial → deployed → not_deployed`.

### Software

A tool or malware family. `software_type` is `tool` or `malware` (from STIX object types).

### Targeting

Known sectors, regions, or countries an actor targets. `target_type` is `industry`, `region`, or `country`. Populated by keyword extraction from ATT&CK descriptions (confidence `medium`) and structured MISP Galaxy fields.

### SyncLog

Per-connector audit record. `status` is `success` / `partial` / `failed` / `skipped`.

---

## Data Sources and Connectors

Connectors must be idempotent. They run in this order (order enforced):

1. **attack** — MITRE ATT&CK Enterprise STIX 2.0 bundle. Populates actors, techniques, software, aliases, procedure citations, and targeting. The foundational dataset.
2. **ctid_nist80053** — Center for Threat-Informed Defense crosswalk. Requires `attack` to have run first (joins against existing technique IDs).
3. **d3fend** — MITRE D3FEND ontology JSON-LD. Uses artifact-based inference to build technique↔countermeasure links.
4. **misp_galaxy** — MISP threat-actor galaxy. Richest cross-vendor alias source (Mandiant, CrowdStrike, Microsoft naming).
5. **malpedia** — Malpedia public API. Adds 2,300+ actors beyond ATT&CK; no auth required. Actors added here have `in_attack=False`.
6. **mandiant** — Mandiant/Google Threat Intelligence API. Requires `MANDIANT_API_KEY` + `MANDIANT_API_SECRET`. Optional.

After each sync, the `ResolutionIndex` is rebuilt from all alias rows.

---

## Risk Ranking

100-point scoring model across four buckets:

| Component | Max pts | Neutral (no posture configured) |
|---|---|---|
| `targeting_score` | 20 | 20 (full, no filter) |
| `exposure_score` | 35 | 17 |
| `critical_score` | 25 | 12 |
| `recency_score` | 20 | 8 (unknown last\_seen) |

- `exposure_score` — fraction of the actor's techniques not covered by posture × 35
- `critical_score` — uncovered fraction of `CRITICAL_TACTICS` techniques × 25
- `CRITICAL_TACTICS` — `{initial-access, execution, privilege-escalation, defense-evasion}` — "can they get in and stay in"
- `ransomware_flag` — heuristic boolean surfaced in the UI; does not reduce the score

`posture_configured` is True if any NIST controls are implemented or any D3FEND countermeasures are set. If False, exposure and critical scores go to neutral values rather than zero.

---

## Alias Resolution

`ResolutionIndex` is an in-memory alias lookup engine built at startup.

- **Exact match** — normalized query hits `_index` directly
- **Fuzzy match** — `rapidfuzz.fuzz.token_sort_ratio` at threshold 85
- **Collision resolution** — if two sources provide the same normalized alias for different actors, the higher-confidence entry wins

`normalize_alias()` in `core/ingest/base.py` and `_normalize()` in `core/resolution.py` must always be identical. Any change to normalization logic must update both.

---

## Key Invariants

- **No LLM synthesis.** Every data point is traceable to MITRE ATT&CK STIX, the CTID crosswalk, or the D3FEND ontology. Avoid generating inferred claims.
- **Posture is user-only.** `ControlPosture` and `D3FendPosture` are never written by connectors.
- **`no_mapping` is excluded from the denominator.** Do not count no-mapping techniques when computing coverage percentages.
- **`partial` = 0.5 everywhere.** This weight applies to both NIST and D3FEND coverage calculations.
- **`in_attack=False` actors are real.** They exist in Malpedia/MISP but not ATT&CK. The UI's "ATT&CK actors only" filter (`in_attack=true`) excludes them, but they are valid actors in the DB.
- **Connector order matters.** `ctid_nist80053` must run after `attack`. Do not reorder the sync sequence.
- **TACTIC_ORDER is canonical.** The sort order `["Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]` (D3FEND) and the ATT&CK kill-chain order are used consistently across the report, UI, and API. Don't introduce alternative orderings.

---

## Vocabulary Avoid List

Don't use these terms — use the canonical form instead:

| Avoid | Use instead |
|---|---|
| "control deployed" | "control implemented" (NIST controls are *implemented*; D3FEND countermeasures are *deployed*) |
| "technique mitigated" | "technique covered" (covered/partial_covered/not_covered is the coverage vocabulary) |
| "threat group" | "actor" (the codebase and domain use "actor" throughout) |
| "sub-technique" as a separate concept | "technique" (sub-techniques are `Technique` rows with `is_subtechnique=True`; treat them uniformly unless the distinction is specifically relevant) |
| "mapping" (ambiguous) | Specify which crosswalk: "NIST mapping" (TechniqueControl) or "D3FEND mapping" (TechniqueD3Fend) |
