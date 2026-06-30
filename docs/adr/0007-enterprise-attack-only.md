# ADR-0007: Enterprise ATT&CK matrix only

**Status:** Accepted

## Context

MITRE ATT&CK publishes three matrices: Enterprise (Windows, macOS, Linux, cloud, network), Mobile (Android, iOS), and ICS (industrial control systems). The STIX bundle for each is a separate download with its own technique namespace.

## Decision

Ingest only the Enterprise matrix (`enterprise-attack.json`). Mobile and ICS are out of scope.

The tool is designed for enterprise IT and SOC analysts working in conventional IT environments. Mobile threat actors and ICS/OT adversaries operate in sufficiently different contexts that mixing their techniques into the same posture and coverage model would produce misleading results without dedicated Mobile and ICS control crosswalks (which do not currently exist in the CTID dataset used for NIST mapping).

## Consequences

- Actors who operate primarily or exclusively in Mobile or ICS contexts (e.g. Sandworm's ICS-specific tooling) will appear with fewer techniques than they actually employ.
- Adding Mobile or ICS support would require: a separate connector (or matrix flag in the existing connector), dedicated NIST/D3FEND crosswalks, and UI filtering so analysts can scope their view to a specific matrix.
- Users from OT/ICS teams should be informed of this limitation before using the tool for ICS actor analysis.
