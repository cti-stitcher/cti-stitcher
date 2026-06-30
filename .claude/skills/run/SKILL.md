---
name: run
description: Launch the cti-stitcher Explorer web app and verify it is working correctly.
---

## Launching the app

From the repo root, start the server in the background:

```bash
python -m explorer
```

The server starts on `http://127.0.0.1:8000` and opens a browser tab automatically. Wait ~3 seconds for startup before hitting endpoints.

## Smoke-test sequence

After any code change, verify these endpoints in order:

```bash
# 1. Connector registry — must show 6 connectors, malpedia requires_auth=false
curl -s http://127.0.0.1:8000/api/sync/status

# 2. Alias resolution + actor serializer
curl -s "http://127.0.0.1:8000/api/search?q=apt28"

# 3. Actor list with in_attack filter
curl -s "http://127.0.0.1:8000/api/actors?in_attack=true&limit=5"

# 4. Actor detail
curl -s http://127.0.0.1:8000/api/actors/1
```

## Running a full sync

Triggers all connectors (takes 1–3 minutes — downloads ATT&CK bundle, D3FEND ontology, MISP galaxy, Malpedia):

```bash
curl -s -X POST http://127.0.0.1:8000/api/sync
```

Expected result: `attack`, `ctid_nist80053`, `d3fend`, `misp_galaxy`, `malpedia` all show `"status": "success"`. `mandiant` shows `"status": "skipped"` (no credentials configured — that is correct).

## Connector notes

- **malpedia** — public API, no key needed, uses bulk `/api/get/actors` endpoint
- **mandiant** — requires `MANDIANT_API_KEY` + `MANDIANT_API_SECRET` in `.env`; skipped when absent
- **Ordering constraint** — `attack` must complete before `ctid_nist80053` and `d3fend`; the registry enforces this order automatically

## Stopping the server

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```
