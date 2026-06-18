# cti-stitcher

Open source threat intelligence toolchain for CTI analysts.

**v1: Threat Actor Explorer** — search any actor alias (APT29, Cozy Bear, Midnight Blizzard) and get a unified profile anchored to MITRE ATT&CK. Runs fully local, no cloud required.

**v2: CTI-to-Risk Mapper (enrichment)** — every technique on an actor profile is decorated with the NIST 800-53 rev5 controls that mitigate it (via CTID's published ATT&CK crosswalk), closing the gap between "what they do" and "what stops them."

**v2.5: Controls Browse** — reverse lookup: pick any NIST 800-53 control, see every technique it mitigates and every actor that uses those techniques. Mark controls as implemented to track your posture.

**v3: Gap Analysis** — mark your implemented controls and get per-actor coverage scores. Single-actor drill-down shows covered vs. uncovered techniques with prioritized remediation hints. All-actors leaderboard shows your worst exposures at a glance.

**v4: D3FEND Integration** — adds a detection and hardening layer alongside the compliance layer. Browse MITRE D3FEND countermeasures (Harden / Detect / Isolate / Deceive / Evict / Restore), mark what you've deployed, and see dual coverage scores per actor — NIST 800-53 compliance % and D3FEND detection coverage % side by side.

---

## Install

```bash
git clone https://github.com/cti-stitcher/cti-stitcher
cd cti-stitcher
pip install -r requirements.txt
```

## Configure (optional)

Copy `.env.example` to `.env` and add API keys for optional connectors:

```bash
cp .env.example .env
# Edit .env and add MALPEDIA_API_KEY and/or MANDIANT credentials
```

ATT&CK, MISP Galaxy, CTID NIST 800-53, and D3FEND all run without any configuration.

## Sync data (first run)

```bash
python -m explorer
```

Then trigger a sync via the Connectors page at `http://localhost:8000/settings`, or:

```bash
curl -X POST http://localhost:8000/api/sync
```

First run takes 2–3 minutes (ATT&CK + CTID + D3FEND ontology). Run again anytime to refresh.

> **Order matters:** `ctid_nist80053` and `d3fend` both join against techniques created by `attack` and must run after it. The default full sync already enforces this order.

## Run the explorer

```bash
python -m explorer
```

Open **http://localhost:8000** in your browser.

---

## Data sources

| Connector | Auth required | What it adds |
|-----------|--------------|-------------|
| MITRE ATT&CK | None | Canonical actor IDs, TTPs, malware |
| CTID NIST 800-53 mapping | None | NIST 800-53 rev5 controls per technique |
| MITRE D3FEND | None | Defensive countermeasures mapped to ATT&CK via artifact inference |
| MISP Galaxy | None | Cross-vendor alias coverage |
| Malpedia | Free API key | Malware families, additional aliases |
| Mandiant | Free API key | Mandiant APT naming, fresher data |

## Project structure

```
core/          Shared data layer (models, DB, ingestion, resolution)
explorer/      FastAPI app + browser UI — actor explorer, controls, gap analysis, D3FEND
scripts/       Data sync utilities
```

## Adding a connector

1. Create `core/ingest/<source>.py`
2. Subclass `BaseConnector` from `core/ingest/base.py`
3. Implement `is_available()` and `run(session)`
4. Register it in `explorer/api/sync.py`

See `core/ingest/README.md` for details.

## Roadmap

- [x] v1: Threat Actor Explorer
- [x] v2: CTI-to-risk mapper — NIST 800-53 rev5 controls shown on actor/technique pages
- [x] v2.5: Controls browse page — reverse lookup: control → techniques → actors, posture toggles
- [x] v3: Gap analysis — per-actor coverage %, all-actors leaderboard, remediation hints
- [x] v4: D3FEND integration — detection coverage layer alongside NIST compliance, dual coverage bars
- [ ] v5: Actor threat model report — pick an actor, generate a structured report with procedure-level TTPs, matched D3FEND countermeasures, and NIST control gaps (requires ATT&CK procedure ingestion + LLM synthesis)
- [ ] v1.5: Geographic map overlay
- [ ] CIS Controls bridge (blocked on machine-readable CIS↔ATT&CK mapping)

---

Contributions welcome. See `docs/` for architecture notes.
