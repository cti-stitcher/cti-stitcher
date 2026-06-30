# ADR-0003: No LLM synthesis — all data traceable to source

**Status:** Accepted

## Context

CTI analysis requires auditability. An analyst citing "APT29 uses T1566.001" in a threat model must be able to trace that claim back to a specific STIX relationship in the ATT&CK bundle, not an LLM inference. Generated or inferred claims that cannot be sourced introduce unacceptable risk of hallucination in a security context.

## Decision

Every data point in the database must be traceable to one of: the MITRE ATT&CK STIX bundle, the CTID NIST 800-53 crosswalk, the D3FEND ontology, or a named external source (MISP Galaxy, Malpedia, Mandiant API). No connector may generate, infer, or synthesize claims using a language model.

The `procedure` field in `ActorTechnique` stores the **verbatim** STIX `relationship.description` string — no paraphrasing.

## Consequences

- Every displayed claim is citable. The Excel report's "Gap Summary" sheet makes this explicit with source column references.
- Analysts can use the tool's output directly in threat model documentation without a secondary verification step.
- Coverage gaps in the source data (e.g. techniques with no NIST mapping) surface as `no_mapping` rather than being papered over.
