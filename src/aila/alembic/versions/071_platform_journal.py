"""071 -- platform_journal (C2 append-only hash-chained substrate) + dead-letter.

Adds the C2 correlation journal that the audit trail (#52), observability
(#39), the graph journal (#23), the replay corpus (#32), and untrusted-execution
evidence (#58) all build on. One append-only, hash-chained event log:

* ``platform_journal`` -- composite PK ``(chain_id, seq)``; ``chain_id`` is
  ``team:{team_id}`` for team rows or ``global`` for admin/system rows. Each row
  carries ``row_hash`` (chains to the previous row) and ``payload_hash`` (covers
  the possibly-redacted payload independently). A BEFORE UPDATE OR DELETE trigger
  enforces immutability at the database layer.
* ``platform_journal_deadletter`` -- fallback for legacy append paths that must
  not fail the business transaction; drained into the main chain by operator
  review.

Row hashing and seq allocation are performed application-side in
``platform/services/journal.py`` (Python-side chain head read + retry on PK
collision). The Postgres stored-function / ``FOR UPDATE NOWAIT`` hot-chain
optimization from the design is a follow-on and is not required for correctness.

Revision ID: 071_platform_journal
Revises: 070_malware_project_slim_and_ack
Create Date: 2026-07-20
"""
from __future__ import annotations

from alembic import op

revision: str = "071_platform_journal"
down_revision: str | None = "070_malware_project_slim_and_ack"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE platform_journal (
    chain_id          VARCHAR(64)  NOT NULL,
    seq               BIGINT       NOT NULL,
    journal_id        VARCHAR(36)  NOT NULL,
    team_id           VARCHAR(36),
    prev_hash         VARCHAR(64),
    row_hash          VARCHAR(64)  NOT NULL,
    payload_hash      VARCHAR(64)  NOT NULL,
    kind              VARCHAR(48)  NOT NULL,
    source            VARCHAR(128) NOT NULL,
    actor_kind        VARCHAR(16)  NOT NULL,
    actor_id          VARCHAR(128) NOT NULL,
    action            VARCHAR(128) NOT NULL,
    status            VARCHAR(16)  NOT NULL,
    run_id            VARCHAR(36),
    investigation_id  VARCHAR(36),
    branch_id         VARCHAR(36),
    turn_number       INTEGER,
    correlation_id    VARCHAR(64)  NOT NULL,
    parent_journal_id VARCHAR(36),
    payload_json      JSONB        NOT NULL,
    contains_secret   BOOLEAN      NOT NULL DEFAULT false,
    schema_version    SMALLINT     NOT NULL DEFAULT 1,
    occurred_at       TIMESTAMPTZ  NOT NULL,
    written_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, seq),
    CONSTRAINT uq_platform_journal_journal_id UNIQUE (journal_id),
    CONSTRAINT ck_platform_journal_hash_len
        CHECK (length(row_hash) = 64 AND length(payload_hash) = 64),
    CONSTRAINT ck_platform_journal_chain_id
        CHECK (chain_id LIKE 'team:%' OR chain_id = 'global')
)
""")
    op.execute(
        "CREATE INDEX ix_pj_correlation ON platform_journal (correlation_id, seq)"
    )
    op.execute(
        "CREATE INDEX ix_pj_kind_written ON platform_journal (kind, written_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_pj_team_kind_written "
        "ON platform_journal (team_id, kind, written_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_pj_investigation ON platform_journal (investigation_id, seq) "
        "WHERE investigation_id IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX ix_pj_run ON platform_journal (run_id, seq) "
        "WHERE run_id IS NOT NULL"
    )

    # Append-only enforcement: block UPDATE and DELETE at the DB layer.
    op.execute("""
CREATE OR REPLACE FUNCTION platform_journal_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'platform_journal is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql
""")
    op.execute("""
CREATE TRIGGER platform_journal_append_only
    BEFORE UPDATE OR DELETE ON platform_journal
    FOR EACH ROW EXECUTE FUNCTION platform_journal_no_mutate()
""")

    op.execute("""
CREATE TABLE platform_journal_deadletter (
    id             VARCHAR(36)  NOT NULL PRIMARY KEY,
    chain_id       VARCHAR(64)  NOT NULL,
    team_id        VARCHAR(36),
    entry_json     JSONB        NOT NULL,
    failure_kind   VARCHAR(32)  NOT NULL,
    failure_detail TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    replayed_at    TIMESTAMPTZ,
    replay_seq     BIGINT
)
""")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS platform_journal_deadletter")
    op.execute(
        "DROP TRIGGER IF EXISTS platform_journal_append_only ON platform_journal"
    )
    op.execute("DROP FUNCTION IF EXISTS platform_journal_no_mutate()")
    op.execute("DROP TABLE IF EXISTS platform_journal")
