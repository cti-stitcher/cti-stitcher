# cti-stitcher

Open source threat intelligence toolchain for CTI analysts.

**v1: Threat Actor Explorer** — search any actor alias (APT29, Cozy Bear, Midnight Blizzard) and get a unified profile anchored to MITRE ATT&CK. Runs fully local, no cloud required.

**v2: CTI-to-Risk Mapper (enrichment)** — every technique on an actor profile is decorated with the NIST 800-53 rev5 controls that mitigate it (via CTID's published ATT&CK crosswalk), closing the gap between "what they do" and "what stops them."

---

## Install

```bash
git clone https://github.com/<your-handle>/cti-stitcher
cd cti-stitcher
pip install -r requirements.txt
```

## Configure (optional)

Copy `.env.example` to `.env` and add API keys for optional connectors:

```bash
cp .env.example .env
# Edit .env and add MALPEDIA_API_KEY and/or MANDIANT credentials
```

ATT&CK and MISP Galaxy run without any configuration.

## Sync data (first run)

```bash
python scripts/update_data.py
```

This pulls from MITRE ATT&CK, the CTID NIST 800-53 mapping, and MISP Galaxy (~1–2 min on first run) and caches everything locally. Run it again anytime to refresh.

> **Order matters:** `ctid_nist80053` maps onto techniques created by `attack`, so it must run after it. The default full sync (no `--connector` flag) already runs in the correct order — only watch this if you're running connectors individually.

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
| CTID NIST 800-53 mapping | None | NIST 800-53 rev5 controls per technique (runs after ATT&CK) |
| MISP Galaxy | None | Cross-vendor alias coverage |
| Malpedia | Free API key | Malware families, additional aliases |
| Mandiant | Free API key | Mandiant APT naming, fresher data |

## Project structure

```
core/          Shared data layer (models, DB, ingestion, resolution)
explorer/      Threat Actor Explorer (FastAPI + browser UI) — now includes NIST 800-53 control enrichment
risk_mapper/   Gap analysis: org control posture -> coverage gaps per actor (v3 — stub, not yet built)
dissem/        Dissemination tracker (backlog)
scripts/       Data sync utilities
```

## Adding a connector

1. Create `core/ingest/<source>.py`
2. Subclass `BaseConnector` from `core/ingest/base.py`
3. Implement `is_available()` and `run(session)`
4. Register it in `scripts/update_data.py` and `explorer/api/sync.py`

See `core/ingest/README.md` for details.

## Roadmap

- [x] v1: Threat Actor Explorer
- [x] v2: CTI-to-risk mapper, enrichment-only (NIST 800-53 rev5 controls shown on actor/technique pages)
- [ ] v1.5: Geographic map overlay
- [ ] v2.5: Controls browse page (pick a control, see related techniques/actors); CIS Controls bridge (needs a current, machine-readable CIS<->ATT&CK mapping — none exists yet)
- [ ] v3: Risk mapper gap analysis (org provides control posture, get coverage gaps per actor); TTP-to-detection gap analyzer (ATT&CK Navigator layer input)
- [ ] v4: Dissemination and feedback loop tracker

---

Contributions welcome. See `docs/` for architecture notes.
