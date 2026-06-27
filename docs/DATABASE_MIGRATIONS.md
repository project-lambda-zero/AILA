# Database Migrations

Every schema change in AILA goes through Alembic. No exceptions. No `metadata.create_all()` in production code. No raw `CREATE TABLE` in application logic. This document explains why and how.

---

## Why Alembic

SQLModel's `metadata.create_all()` creates tables that don't exist but never modifies existing ones. It cannot:
- Add a column to an existing table
- Change a column type or constraint
- Drop a column or table
- Create an index on an existing table
- Rename anything

Once data exists, you need migrations. Alembic provides:
- Versioned, append-only migration files
- Forward (`upgrade`) and backward (`downgrade`) paths
- Dependency chain (each migration knows its predecessor)
- Offline mode (emit SQL without connecting)

---

## File Layout

```
src/aila/
  alembic.ini           # Alembic config (sqlalchemy.url overridden in env.py)
  alembic/
    env.py              # Migration environment (imports all models, sync driver)
    versions/
      __init__.py
      001_baseline_stamp.py
      002_plan_a_auth_tables.py
      ...
      060_vr_target_analysis_stages.py
      061_llm_idempotency_cache.py
      062_vr_outcome_review.py
      063_vr_auto_steering_dedup_key.py
      064_vr_branch_persona_voice_not_null.py
      065_task_records_input_hash_unique.py
      066_task_records_status_check.py
      067_workflow_state_cursor_archived_state.py    # current head
```

`alembic.ini` and the `alembic/` directory live under `src/aila/`, not at the repo root. All Alembic commands must run from `src/aila/`:

```bash
cd src/aila && alembic upgrade head
```

Or the Make wrappers:

- `make db-init` -- fresh database only. Creates every SQLModel-registered table via `metadata.create_all()`, then stamps `alembic_version` at the current head. Run once on a brand-new database.
- `make migrate` -- every subsequent run. Plain `alembic upgrade head`.

The split exists because the early module tables (vulnerability, forensics) predate the Alembic baseline (`001_baseline_stamp` is intentionally empty) and are still created via `metadata.create_all()` on first boot. `make db-init` covers the bootstrap; `make migrate` covers every column/index/table added after the baseline.

---

## How to Write a Migration

### Step 1: Change the SQLModel class

Edit the model in `src/aila/storage/db_models.py` (platform tables) or `src/aila/modules/<module>/db_models/` (module tables).

```python
# Example: add a column to an existing table
class ForensicsAnalystDirective(SQLModel, table=True):
    __tablename__ = "forensics_analyst_directives"
    # ... existing fields ...
    strategy_family: str | None = Field(default=None, sa_column=Column(String(64)))  # NEW
```

### Step 2: Create the migration file

**Do not use `alembic revision --autogenerate`.** Autogenerate is unreliable with SQLModel -- it misses column type changes, index modifications, and cross-schema references. Write migrations by hand.

Create a new file in `src/aila/alembic/versions/`:

```
{NNN}_{short_description}.py
```

Where `{NNN}` is the next sequential number (zero-padded to 3 digits). Check the latest file:

```bash
ls src/aila/alembic/versions/*.py | tail -1
# 067_workflow_state_cursor_archived_state.py -> next is 068
```

### Step 3: Write the migration

Use this template:

```python
"""063 -- add priority column to task records.

Adds a nullable priority field so operators can influence queue ordering.

Revision ID: 063_taskrecord_priority
Revises: 067_workflow_state_cursor_archived_state
Create Date: 2026-06-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "063_taskrecord_priority"
down_revision = "067_workflow_state_cursor_archived_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "taskrecord",
        sa.Column("priority", sa.Integer(), nullable=True, server_default="0"),
    )
    op.create_index("ix_taskrecord_priority", "taskrecord", ["priority"])


def downgrade() -> None:
    op.drop_index("ix_taskrecord_priority", table_name="taskrecord")
    op.drop_column("taskrecord", "priority")
```

### Step 4: Apply

```bash
cd src/aila && alembic upgrade head
```

### Step 5: Verify

```bash
# Check current revision
cd src/aila && alembic current

# Check migration history
cd src/aila && alembic history --verbose | head -20
```

---

## Migration Naming Convention

```
{NNN}_{module_or_area}_{description}.py
```

Examples from the codebase:

| File | Pattern |
|---|---|
| `001_baseline_stamp.py` | Platform baseline |
| `010_team_isolation.py` | Platform feature |
| `017_llm_cost_record.py` | Platform subsystem |
| `023_workflow_state_cursor.py` | Platform workflow engine |
| `028_forensics_tables.py` | Module initial tables |
| `040_vr_tables.py` | Module initial tables |
| `060_vr_target_analysis_stages.py` | Module column addition |
| `061_llm_idempotency_cache.py` | Platform subsystem |
| `062_vr_outcome_review.py` | Module column + new table |
| `063_vr_auto_steering_dedup_key.py` | Module column + partial UNIQUE |
| `064_vr_branch_persona_voice_not_null.py` | Module backfill + NOT NULL |
| `065_task_records_input_hash_unique.py` | Platform column + partial UNIQUE |
| `066_task_records_status_check.py` | Platform CHECK constraint |
| `067_workflow_state_cursor_archived_state.py` | Platform column addition |

The `revision` string inside the file must match the filename (without `.py`).

---

## Common Operations

### Add a column

```python
def upgrade() -> None:
    op.add_column("tablename", sa.Column("new_col", sa.Text(), nullable=True))

def downgrade() -> None:
    op.drop_column("tablename", "new_col")
```

### Add a column with a default (backfill existing rows)

```python
def upgrade() -> None:
    op.add_column(
        "tablename",
        sa.Column("status", sa.String(50), nullable=True),
    )
    # Backfill existing rows
    op.execute("UPDATE tablename SET status = 'active' WHERE status IS NULL")
    # Now make it non-nullable
    op.alter_column("tablename", "status", nullable=False)

def downgrade() -> None:
    op.drop_column("tablename", "status")
```

### Create a new table

```python
def upgrade() -> None:
    op.create_table(
        "my_module_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("data_json", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_my_module_records_name", "my_module_records", ["name"])

def downgrade() -> None:
    op.drop_index("ix_my_module_records_name", table_name="my_module_records")
    op.drop_table("my_module_records")
```

### Change a column type

```python
def upgrade() -> None:
    # Integer -> BigInteger (safe for PostgreSQL)
    op.alter_column(
        "forensics_project_evidence",
        "size_bytes",
        type_=sa.BigInteger(),
        existing_type=sa.Integer(),
    )

def downgrade() -> None:
    op.alter_column(
        "forensics_project_evidence",
        "size_bytes",
        type_=sa.Integer(),
        existing_type=sa.BigInteger(),
    )
```

### Drop a table

```python
def upgrade() -> None:
    op.drop_table("obsolete_table")

def downgrade() -> None:
    op.create_table(
        "obsolete_table",
        sa.Column("id", sa.Integer(), primary_key=True),
        # ... recreate all columns ...
    )
```

### Add an index

```python
def upgrade() -> None:
    op.create_index("ix_findings_cve_id", "latestfindingrecord", ["cve_id"])

def downgrade() -> None:
    op.drop_index("ix_findings_cve_id", table_name="latestfindingrecord")
```

---

## Module-Specific Tables

Modules that need their own tables follow these rules:

### 1. Table names are prefixed with the module ID

```
forensics_projects
forensics_artifacts
forensics_investigations
vulnerability_scoring_policy  (hypothetical)
```

This prevents name collisions between modules.

### 2. Models live in the module's `db_models/` package

```
src/aila/modules/my_module/
  db_models/
    __init__.py      # re-exports all models
    records.py       # SQLModel table classes
```

### 3. Models must be imported in `alembic/env.py`

The Alembic environment needs to see all SQLModel table classes for `metadata` to be complete. Add your module's models:

```python
# alembic/env.py
from aila.modules.my_module import db_models as _my_module_models  # noqa: F401
```

Without this import, Alembic autogenerate (if used) will not detect your tables, and foreign key references may fail.

### 4. Migrations are shared, not per-module

All migration files live in `src/aila/alembic/versions/`. There is one linear migration chain for the entire database. Module migrations interleave with platform migrations.

---

## Driver Configuration

AILA uses two PostgreSQL drivers:

| Context | Driver | URL scheme |
|---|---|---|
| Application runtime | asyncpg (async) | `postgresql+asyncpg://` |
| Alembic migrations | psycopg (sync) | `postgresql+psycopg://` |

`alembic/env.py` automatically converts the `AILA_DATABASE_URL` from `+asyncpg` to `+psycopg`. You set one URL; the driver swap is transparent.

---

## Rules

### Append-only

Never modify an existing migration file after it has been applied to any database (including your local dev database). If you got it wrong, write a new migration that fixes it.

### Always write downgrade

Every `upgrade()` must have a corresponding `downgrade()`. Even if you never plan to roll back, the downgrade function documents what the upgrade changed.

### No data logic in migrations

Migrations change schema. They do not insert seed data, run business logic, or call application code. Seed data belongs in `module.py:seed_data()` guarded by `SeedVersionRecord`.

Exception: backfilling a new column with a default value (as shown above) is acceptable because it's a schema-level operation.

### No `metadata.create_all()` in production code

The only place `create_all()` is allowed is in test fixtures (`conftest.py`) for in-memory test databases. Production databases are managed exclusively by Alembic.

### Test your migration

```bash
# Apply
cd src/aila && alembic upgrade head

# Verify the column/table exists
python -c "
from aila.storage.database import session_scope
from sqlmodel import text
with session_scope() as s:
    result = s.exec(text('SELECT column_name FROM information_schema.columns WHERE table_name = \\'my_table\\''))
    print([r[0] for r in result])
"

# Verify downgrade works
cd src/aila && alembic downgrade -1
cd src/aila && alembic upgrade head
```

---

## Troubleshooting

### "Target database is not up to date"

Your database is behind the migration chain. Run:

```bash
cd src/aila && alembic upgrade head
```

### "Can't locate revision"

A migration file references a `down_revision` that doesn't exist. Check that your `down_revision` matches the `revision` string of the previous migration file.

### "AILA_DATABASE_URL must be set"

The `.env` file is not loaded. Either:
- `source .env` before running Alembic
- Or set the variable directly: `AILA_DATABASE_URL=postgresql+asyncpg://... alembic upgrade head`

### "relation already exists"

The table already exists in the database but Alembic doesn't know about it (the migration was never recorded in `alembic_version`). Stamp the current state:

```bash
cd src/aila && alembic stamp head
```

This marks all migrations as applied without running them. Only use this when you're certain the schema is already up to date.
