# cti-stitcher

Open source threat intelligence toolchain for CTI analysts.

## The problem

CTI analysts have a gap between *threat knowledge* and *defense posture*. MITRE ATT&CK tells you what adversaries do. NIST 800-53 and D3FEND tell you how to stop them. But translating "APT29 uses T1059.001" into "we're missing SC-7 and here are the five D3FEND countermeasures that would close it" requires manually joining three separate data sources every time.

`cti-stitcher` automates that join locally — no cloud dependency, no vendor lock-in. Point it at a threat actor, get a unified view of their TTPs, your control gaps, your detection gaps, and a ranked action list of what to deploy next.

---

**v1: Threat Actor Explorer** — search any actor alias (APT29, Cozy Bear, Midnight Blizzard) and get a unified profile anchored to MITRE ATT&CK. Runs fully local, no cloud required.

**v2: CTI-to-Risk Mapper** — every technique on an actor profile is decorated with the NIST 800-53 rev5 controls that mitigate it (via CTID's published ATT&CK crosswalk), closing the gap between "what they do" and "what stops them."

**v2.5: Controls Browse** — reverse lookup: pick any NIST 800-53 control, see every technique it mitigates and every actor that uses those techniques. Mark controls as implemented to track your posture.

**v3: Gap Analysis** — mark your implemented controls and get per-actor coverage scores. Single-actor drill-down shows covered vs. uncovered techniques with prioritized remediation hints. All-actors leaderboard shows your worst exposures at a glance.

**v4: D3FEND Integration** — adds a detection and hardening layer alongside the compliance layer. Browse MITRE D3FEND countermeasures (Harden / Detect / Isolate / Deceive / Evict / Restore), mark what you've deployed, and see dual coverage scores per actor — NIST 800-53 compliance % and D3FEND detection coverage % side by side.

**v5: Threat Model Report** — one-click Excel export per actor. Five sheets: actor profile, full TTP list with verbatim STIX procedure citations, NIST 800-53 control mapping with posture, D3FEND countermeasure mapping with posture, and a gap summary with ranked action list sorted by techniques closed. Pure sourced extraction — every row traceable to MITRE ATT&CK, CTID, or D3FEND ontology data.

**v6: Partial posture + UX polish** — D3FEND posture gains a three-state cycle (not deployed → partial → deployed) with coverage math that weights partial as 0.5. Excel report updated to reflect partial state. Browser auto-opens on `python -m explorer`.

**v7: Malpedia + reverse pivots + explorer polish** — Malpedia integration adds cross-vendor malware families and actor aliases with no API key required. ATT&CK-only filter in the explorer prevents Malpedia's 2,300+ actors from flooding the list. Controls page gains sort by Control ID, most techniques, or most actors. Click any tool/malware badge on an actor profile to pivot to every other actor using it with shared infrastructure signal. Click any region, country, or industry tag to see all actors with the same targeting focus, sorted by TTP overlap % with your starting actor.

**v8: Threat Actor Risk Ranking + posture-aware actor profiles** — new Risk Rank page scores every ATT&CK actor 0–100 across four buckets: targeting match (does this actor go after your industry/country?), posture exposure (% of their TTPs your controls don't cover), critical tactic exposure (uncovered Initial Access, Execution, Privilege Escalation, Defense Evasion specifically), and recency. Ransomware ecosystem actors get a separate badge rather than a score penalty so initial access brokers aren't buried. Actor profiles now color-code every technique-id badge by your coverage posture: red for critical-tactic gaps, amber for other gaps, blue for covered — at a glance you can see exactly where this actor has the upper hand on you.

---

## Install

```bash
git clone https://github.com/cti-stitcher/cti-stitcher
cd cti-stitcher
pip install -r requirements.txt
```

## Configure (optional)

ATT&CK, MISP Galaxy, CTID NIST 800-53, D3FEND, and Malpedia all run without any configuration.

To enable the Mandiant connector, copy `.env.example` to `.env` and add your credentials:

```bash
cp .env.example .env
# Edit .env and add MANDIANT credentials
```

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
| Malpedia | None | Malware families, additional actor aliases |
| Mandiant | Free API key | Mandiant APT naming, fresher data |

## Project structure

```
core/          Shared data layer (models, DB, ingestion, resolution)
explorer/      FastAPI app + browser UI — actor explorer, controls, gap analysis, D3FEND, risk ranking
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
- [x] v2: CTI-to-risk mapper — NIST 800-53 technique crosswalk
- [x] v2.5: Controls browse + posture tracking
- [x] v3: Gap analysis — per-actor coverage scores
- [x] v4: D3FEND integration — detection countermeasure layer
- [x] v5: Threat model report — Excel export with STIX citations
- [x] v6: Partial posture state + UX polish
- [x] v7: Malpedia + reverse pivots (software, targeting)
- [x] v8: Risk ranking + posture-aware actor profiles
- [ ] Actor-to-actor comparison view
- [ ] ATT&CK Navigator layer import/export
- [ ] CSV export of ranked detection gaps
