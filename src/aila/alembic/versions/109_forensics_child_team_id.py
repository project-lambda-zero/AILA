"""109 -- denormalise team_id onto forensics child tables (#59).

The forensics module scopes rows to a tenant (team) through a single
root table (``forensics_projects.team_id``). Prior to this migration
every child table -- investigations, agent steps, write-ups, answer
candidates, analyst directives, finding suppressions, solid evidence,
artifacts, leads, project evidence -- inherited its tenant transitively
through a ``project_id`` join. That is safe when every reader remembers
to load the parent project first and gate on
``require_project_ownership`` (see
``aila.modules.forensics.db_models.team_scope``), but it leaves the
platform ``do_orm_execute`` listener (see
``aila.platform.services.team_scope``) unable to auto-filter reads on
those child rows: the listener only injects ``WHERE team_id = :caller``
when the queried model actually declares a ``team_id`` column.

The four child tables audited under #59 (the ones that carry the bulk
of investigation data and are the most frequent read targets) now
carry a redundant ``team_id`` column so the listener can add the WHERE
clause automatically. That makes the transitive parent-project guard a
defense-in-depth check rather than the sole barrier:

  * ``forensics_investigations``     (:class:`InvestigationRunRecord`)
  * ``forensics_agent_steps``        (:class:`AgentStepRecord`)
  * ``forensics_writeups``           (:class:`WriteUpRecord`)
  * ``forensics_answer_candidates``  (:class:`AnswerCandidateRecord`)

The column stays nullable to match the parent's ``NULL == admin-owned``
convention (see ``ForensicsProjectRecord.team_id``). Existing rows are
backfilled by joining back to the parent row that ultimately owns them
(agent-step rows join through their investigation row, which itself
carries the freshly backfilled column).

Every index name carries the ``ix_<tablename>_team_id`` convention used
throughout the platform so it cannot collide with another module's
identically-shaped index. This migration adds no named constraints
(FKs stay implicit and are not introduced here to avoid the platform
CASCADE order dance on delete).

Revision ID: 109_forensics_child_team_id
Revises:     108_rename_specialist_agents
Create Date: 2026-08-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "109_forensics_child_team_id"
down_revision: str | None = "108_rename_specialist_agents"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


# (table, index) pairs kept in join order: parents before children. The
# backfill walks the list top-to-bottom so ``forensics_agent_steps``
# reads a populated ``forensics_investigations.team_id`` when it lands.
_TABLES: tuple[tuple[str, str], ...] = (
    ("forensics_investigations", "ix_forensics_investigations_team_id"),
    ("forensics_writeups", "ix_forensics_writeups_team_id"),
    ("forensics_answer_candidates", "ix_forensics_answer_candidates_team_id"),
    ("forensics_agent_steps", "ix_forensics_agent_steps_team_id"),
)


def upgrade() -> None:
    # Step 1: add the nullable team_id column to each child table.
    for table, _ in _TABLES:
        op.add_column(table, sa.Column("team_id", sa.Text(), nullable=True))

    # Step 2: backfill from the parent project. Rows whose parent
    # project's team_id is NULL stay NULL (admin-owned, matches the
    # parent's convention). The join is UPDATE ... FROM which the
    # postgres dialect supports natively.
    op.execute(
        "UPDATE forensics_investigations AS i "
        "SET team_id = p.team_id "
        "FROM forensics_projects AS p "
        "WHERE p.id = i.project_id"
    )
    op.execute(
        "UPDATE forensics_writeups AS w "
        "SET team_id = p.team_id "
        "FROM forensics_projects AS p "
        "WHERE p.id = w.project_id"
    )
    op.execute(
        "UPDATE forensics_answer_candidates AS a "
        "SET team_id = p.team_id "
        "FROM forensics_projects AS p "
        "WHERE p.id = a.project_id"
    )
    # Agent steps join through the investigation row that was populated
    # in the previous UPDATE. A step whose investigation_id no longer
    # resolves (dangling row from a project deletion race) stays NULL.
    op.execute(
        "UPDATE forensics_agent_steps AS s "
        "SET team_id = i.team_id "
        "FROM forensics_investigations AS i "
        "WHERE i.id = s.investigation_id"
    )

    # Step 3: index each column so the team-scope listener's injected
    # ``WHERE team_id = :caller`` clause hits an index instead of a
    # sequential scan on tables that grow with every investigation.
    for table, index in _TABLES:
        op.create_index(index, table, ["team_id"])


def downgrade() -> None:
    # Drop indexes first, then the columns. Reverse of upgrade order.
    for table, index in reversed(_TABLES):
        op.drop_index(index, table_name=table)
        op.drop_column(table, "team_id")
