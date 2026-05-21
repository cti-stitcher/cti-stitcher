# cti-stitcher

Open source threat intelligence toolchain for CTI analysts.

**v1: Threat Actor Explorer** — search any actor alias (APT29, Cozy Bear, Midnight Blizzard) and get a unified profile anchored to MITRE ATT&CK. Runs fully local, no cloud required.

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

This pulls from MITRE ATT&CK and MISP Galaxy (~1–2 min on first run) and caches everything locally. Run it again anytime to refresh.

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
| MISP Galaxy | None | Cross-vendor alias coverage |
| Malpedia | Free API key | Malware families, additional aliases |
| Mandiant | Free API key | Mandiant APT naming, fresher data |

## Project structure

```
core/          Shared data layer (models, DB, ingestion, resolution)
explorer/      Threat Actor Explorer (FastAPI + browser UI)
risk_mapper/   CTI-to-risk framework mapper (v2 — not yet built)
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

- [ ] v1: Threat Actor Explorer (current)
- [ ] v1.5: Geographic map overlay
- [ ] v2: CTI-to-risk framework mapper (NIST 800-53 / CIS Controls bridge)
- [ ] v2.5: TTP-to-detection gap analyzer (ATT&CK Navigator layer input)
- [ ] v3: Dissemination and feedback loop tracker

---

Contributions welcome. See `docs/` for architecture notes.
