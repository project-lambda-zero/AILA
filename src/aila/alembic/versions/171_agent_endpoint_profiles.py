"""Add evidence-backed agent endpoint profiles and transport execution state.

Revision ID: 171_agent_endpoint_profiles
Revises: 170_pentest_platform_swarm
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "171_agent_endpoint_profiles"
down_revision: str | None = "170_pentest_platform_swarm"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("pentest_targets", sa.Column("active_profile_id", sa.String(length=36), nullable=True))
    op.create_index("ix_pentest_targets_active_profile_id", "pentest_targets", ["active_profile_id"])

    op.create_table(
        "pentest_target_profiles",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("profile_json", sa.Text(), nullable=False),
        sa.Column("assumptions_json", sa.Text(), nullable=False),
        sa.Column("issues_json", sa.Text(), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("validation_id", sa.String(), nullable=True),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["target_id"], ["pentest_targets.id"], name="fk_pentest_profile_target",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", "version", name="uq_pentest_profile_target_version"),
        sa.UniqueConstraint("target_id", "fingerprint", name="uq_pentest_profile_target_fingerprint"),
    )
    for name, columns in (
        ("ix_pentest_target_profiles_target_id", ["target_id"]),
        ("ix_pentest_target_profiles_team_id", ["team_id"]),
        ("ix_pentest_target_profiles_state", ["state"]),
        ("ix_pentest_target_profiles_validation_id", ["validation_id"]),
        ("ix_pentest_target_profiles_task_id", ["task_id"]),
    ):
        op.create_index(name, "pentest_target_profiles", columns)

    op.create_table(
        "pentest_profile_validation_runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("profile_id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("results_json", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["profile_id"], ["pentest_target_profiles.id"], name="fk_pentest_validation_profile",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in (
        ("ix_pentest_profile_validation_runs_profile_id", ["profile_id"]),
        ("ix_pentest_profile_validation_runs_team_id", ["team_id"]),
        ("ix_pentest_profile_validation_runs_status", ["status"]),
        ("ix_pentest_profile_validation_runs_task_id", ["task_id"]),
    ):
        op.create_index(name, "pentest_profile_validation_runs", columns)

    op.create_table(
        "pentest_agent_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("profile_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("identity_reference", sa.String(length=71), nullable=False),
        sa.Column("profile_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("lease_owner", sa.String(), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("session_reference", sa.String(length=80), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["profile_id"], ["pentest_target_profiles.id"], name="fk_pentest_session_profile",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["pentest_targets.id"], name="fk_pentest_session_target",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "profile_id", "identity_reference", name="uq_pentest_session_profile_identity",
        ),
    )
    for name, columns in (
        ("ix_pentest_agent_sessions_profile_id", ["profile_id"]),
        ("ix_pentest_agent_sessions_target_id", ["target_id"]),
        ("ix_pentest_agent_sessions_team_id", ["team_id"]),
        ("ix_pentest_agent_sessions_identity_reference", ["identity_reference"]),
        ("ix_pentest_agent_sessions_lease_owner", ["lease_owner"]),
        ("ix_pentest_agent_sessions_state", ["state"]),
    ):
        op.create_index(name, "pentest_agent_sessions", columns)

    attempt_columns = (
        sa.Column("profile_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("session_reference", sa.String(length=80), nullable=True),
        sa.Column("execution_validity", sa.String(length=40), server_default="valid", nullable=False),
        sa.Column("engagement", sa.String(length=40), server_default="engaged", nullable=False),
        sa.Column("availability", sa.String(length=40), server_default="normal", nullable=False),
        sa.Column("scoreability_reason", sa.String(length=200), nullable=True),
    )
    for column in attempt_columns:
        op.add_column("pentest_attempts", column)
    op.create_index("ix_pentest_attempts_execution_validity", "pentest_attempts", ["execution_validity"])
    op.create_index("ix_pentest_attempts_engagement", "pentest_attempts", ["engagement"])

    op.create_table(
        "pentest_transport_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("attempt_id", sa.String(), nullable=True),
        sa.Column("validation_id", sa.String(), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("event_index", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("channel", sa.String(length=80), nullable=False),
        sa.Column("kind", sa.String(length=80), nullable=False),
        sa.Column("native_reference", sa.String(length=80), nullable=True),
        sa.Column("payload_artifact_id", sa.String(length=80), nullable=True),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["attempt_id"], ["pentest_attempts.id"], name="fk_pentest_event_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["validation_id"], ["pentest_profile_validation_runs.id"], name="fk_pentest_event_validation",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"], ["pentest_agent_sessions.id"], name="fk_pentest_event_session",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in (
        ("ix_pentest_transport_events_team_id", ["team_id"]),
        ("ix_pentest_transport_events_attempt_id", ["attempt_id"]),
        ("ix_pentest_transport_events_validation_id", ["validation_id"]),
        ("ix_pentest_transport_events_session_id", ["session_id"]),
    ):
        op.create_index(name, "pentest_transport_events", columns)


def downgrade() -> None:
    for name in (
        "ix_pentest_transport_events_session_id",
        "ix_pentest_transport_events_validation_id",
        "ix_pentest_transport_events_attempt_id",
        "ix_pentest_transport_events_team_id",
    ):
        op.drop_index(name, table_name="pentest_transport_events")
    op.drop_table("pentest_transport_events")
    for name in (
        "ix_pentest_agent_sessions_state",
        "ix_pentest_agent_sessions_lease_owner",
        "ix_pentest_agent_sessions_identity_reference",
        "ix_pentest_agent_sessions_team_id",
        "ix_pentest_agent_sessions_target_id",
        "ix_pentest_agent_sessions_profile_id",
    ):
        op.drop_index(name, table_name="pentest_agent_sessions")
    op.drop_table("pentest_agent_sessions")
    for name in (
        "ix_pentest_profile_validation_runs_task_id",
        "ix_pentest_profile_validation_runs_status",
        "ix_pentest_profile_validation_runs_team_id",
        "ix_pentest_profile_validation_runs_profile_id",
    ):
        op.drop_index(name, table_name="pentest_profile_validation_runs")
    op.drop_table("pentest_profile_validation_runs")
    for name in (
        "ix_pentest_target_profiles_task_id",
        "ix_pentest_target_profiles_validation_id",
        "ix_pentest_target_profiles_state",
        "ix_pentest_target_profiles_team_id",
        "ix_pentest_target_profiles_target_id",
    ):
        op.drop_index(name, table_name="pentest_target_profiles")
    op.drop_table("pentest_target_profiles")
    op.drop_index("ix_pentest_attempts_engagement", table_name="pentest_attempts")
    op.drop_index("ix_pentest_attempts_execution_validity", table_name="pentest_attempts")
    for name in (
        "scoreability_reason", "availability", "engagement", "execution_validity",
        "session_reference", "profile_fingerprint",
    ):
        op.drop_column("pentest_attempts", name)
    op.drop_index("ix_pentest_targets_active_profile_id", table_name="pentest_targets")
    op.drop_column("pentest_targets", "active_profile_id")
