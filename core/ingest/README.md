# Adding a connector

Each data source is a self-contained connector. Adding one doesn't require touching any other part of the codebase.

## Steps

**1. Create your file**

```
core/ingest/<source_name>.py
```

**2. Subclass BaseConnector**

```python
from core.ingest.base import BaseConnector, normalize_alias

class MySourceConnector(BaseConnector):
    name = "my_source"          # shows up in sync log and UI
    requires_auth = True        # set True if you need an API key

    def is_available(self) -> bool:
        import os
        return bool(os.getenv("MY_SOURCE_API_KEY"))

    def run(self, session) -> int:
        # Pull data, write to DB using SQLAlchemy session
        # Return count of records created/updated
        # Must be idempotent — safe to run multiple times
        ...
```

**3. Register it**

Add your connector to:
- `scripts/update_data.py` — `ALL_CONNECTORS` dict
- `explorer/api/sync.py` — `ALL_CONNECTORS` list

**4. Add env vars**

Add any required env vars to `.env.example` with a comment.

## Normalization

Always use `normalize_alias(name)` from `base.py` when writing alias records. This keeps the lookup index consistent. Never store raw capitalization or punctuation in `alias_normalized`.

## Idempotency

Use the existing patterns — check for existing rows before inserting, use `session.flush()` between passes. The sync can run multiple times without duplicating data.

## Ordering dependencies

Most connectors are independent and can run in any order. If your connector needs rows created by another connector to already exist (e.g. it joins against `Technique` by `attack_id`), it has an ordering dependency.

- Document the dependency in a module docstring, like `ctid_nist80053.py` does (depends on `attack`).
- Place it after its dependency in both `ALL_CONNECTORS` collections (`scripts/update_data.py` dict and `explorer/api/sync.py` list) — order is preserved and the full sync runs top to bottom.
- Don't make the connector fail if the dependency hasn't run — degrade gracefully (skip and count what couldn't be linked, log a warning telling the user to run the dependency first). Running connectors individually via `--connector <name>` is supported and a user may run yours before its dependency.
- If you ever need a *hard* dependency (connector should refuse to run, not degrade), raise from `run()` so `sync()` records it as `failed` with a clear message — but prefer graceful degradation where possible.
