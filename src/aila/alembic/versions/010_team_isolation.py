"""Add team_id columns and PostgreSQL RLS for team data isolation.

Three-step migration per D-05:
  1. Add nullable team_id TEXT column to all 22 team-scoped tables
  2. Backfill existing rows with sentinel team_id='default-team'
  3. Add NOT NULL constraint (except user_records and apikeyrecord where NULL = admin)

Then: create indexes and RLS policies per D-04.

Revision ID: 010_team_isolation
Revises: 009_knowledge_table_migration
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "010_team_isolation"
down_revision: Union[str, None] = "009_knowledge_table_migration"
branch_labels = None
depends_on = None

SENTINEL_TEAM_ID = "default-team"

# All 22 team-scoped tables — verified against actual __tablename__ in each model.
# Models without explicit __tablename__ use SQLModel default (lowercase classname).
# Models with explicit __tablename__ are annotated below.
TEAM_SCOPED_TABLES: list[str] = [
    # Platform db_models.py — default tablenames (lowercase classname)
    "managedsystemrecord",
    "workflowrunrecord",
    "permanentmemoryrecord",
    "reportartifactrecord",
    "artifactrecord",
    "auditeventrecord",
    # Platform db_models.py — explicit __tablename__
    "user_records",            # UserRecord.__tablename__ = "user_records"
    "apikeyrecord",            # ApiKeyRecord.__tablename__ = "apikeyrecord"
    "refresh_token_records",   # RefreshTokenRecord.__tablename__ = "refresh_token_records"
    # Vulnerability findings.py — default tablenames
    "prioritizedfindingrecord",
    "assettagrecord",
    "remediationrecord",
    # Vulnerability findings.py — explicit __tablename__
    "latest_finding_records",  # LatestFindingRecord.__tablename__ = "latest_finding_records"
    "finding_feedbacks",       # FindingFeedbackRecord.__tablename__ = "finding_feedbacks"
    # Vulnerability distribution.py — default tablenames
    "inventoryartifactrecord",
    "scheduledscanrecord",
    # SbD NFR db_models.py — explicit __tablename__
    "sbd_nfr_session_record",
    "sbd_nfr_answer_record",
    "sbd_nfr_activity_record",
    "sbd_nfr_session_system_record",
    "sbd_nfr_resolution_result_record",
    # Tasks models.py — explicit __tablename__
    "taskrecord",              # TaskRecord.__tablename__ = "taskrecord"
]

# Tables where team_id stays nullable (admin entities per TEAM-01, D-01)
NULLABLE_EXCEPTIONS: set[str] = {"user_records", "apikeyrecord"}


def upgrade() -> None:
    conn = op.get_bind()

    # --- Step 1: Add nullable team_id column to all team-scoped tables ---
    for table in TEAM_SCOPED_TABLES:
        inspector = sa.inspect(conn)
        columns = [c["name"] for c in inspector.get_columns(table)]
        if "team_id" not in columns:
            op.add_column(table, sa.Column("team_id", sa.Text(), nullable=True))

    # --- Step 2: Backfill existing rows with sentinel team_id ---
    for table in TEAM_SCOPED_TABLES:
        op.execute(
            sa.text(
                f"UPDATE {table} SET team_id = :sentinel WHERE team_id IS NULL"
            ).bindparams(sentinel=SENTINEL_TEAM_ID)
        )

    # --- Step 3: Add NOT NULL constraint (except nullable exceptions) ---
    for table in TEAM_SCOPED_TABLES:
        if table not in NULLABLE_EXCEPTIONS:
            op.alter_column(table, "team_id", nullable=False)

    # --- Step 4: Create named indexes ---
    for table in TEAM_SCOPED_TABLES:
        op.create_index(f"ix_{table}_team_id", table, ["team_id"])

    # --- Step 5: PostgreSQL RLS policies (D-04 defense-in-depth) ---

    # Create application role if not exists (idempotent)
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                CREATE ROLE aila_app;
            END IF;
        END
        $$;
    """))

    # Create admin role if not exists (idempotent)
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_admin') THEN
                CREATE ROLE aila_admin BYPASSRLS;
            END IF;
        END
        $$;
    """))

    # Enable RLS and create policies on each team-scoped table
    for table in TEAM_SCOPED_TABLES:
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"""
            CREATE POLICY team_isolation_{table} ON {table}
                USING (
                    team_id = current_setting('app.team_id', true)::text
                    OR current_setting('app.team_id', true) = ''
                    OR current_setting('app.team_id', true) IS NULL
                )
        """))
        # Grant table access to aila_app role
        op.execute(sa.text(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO aila_app"
        ))


def downgrade() -> None:
    # --- Reverse Step 5: Drop RLS policies and disable RLS ---
    for table in TEAM_SCOPED_TABLES:
        op.execute(sa.text(
            f"DROP POLICY IF EXISTS team_isolation_{table} ON {table}"
        ))
        op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            f"REVOKE SELECT, INSERT, UPDATE, DELETE ON {table} FROM aila_app"
        ))

    # --- Reverse Step 4: Drop indexes ---
    for table in TEAM_SCOPED_TABLES:
        op.drop_index(f"ix_{table}_team_id", table_name=table)

    # --- Reverse Step 3: Remove NOT NULL constraint ---
    for table in TEAM_SCOPED_TABLES:
        if table not in NULLABLE_EXCEPTIONS:
            op.alter_column(table, "team_id", nullable=True)

    # --- Reverse Step 1: Drop team_id column (drops data) ---
    for table in TEAM_SCOPED_TABLES:
        op.drop_column(table, "team_id")
