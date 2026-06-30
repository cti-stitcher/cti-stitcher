# ADR-0001: SQLite as the sole data store (local-first)

**Status:** Accepted

## Context

The tool is designed for individual analysts and small security teams who need to run threat intelligence analysis without a cloud dependency, vendor account, or running server. The data volume is bounded: ATT&CK has ~600 techniques and ~150 groups; D3FEND has ~500 countermeasures; NIST 800-53 has ~1,000 controls. All fit comfortably in a single SQLite file.

## Decision

Use SQLite at `data/cti-stitcher.db` (overridable via `DB_PATH`). No separate database server. Schema evolution uses safe, idempotent `ALTER TABLE ADD COLUMN` migrations; table recreation is used only when column type changes require it (guarded by `PRAGMA table_info` checks).

## Consequences

- Zero setup: clone, install, run. No database credentials or server process.
- Single-process only: the FastAPI app uses a shared `SessionLocal`; horizontal scaling is not possible without replacing the storage layer.
- SQLite's limited `ALTER TABLE` support means dropping or renaming columns requires table recreation — migrations must be written carefully.
