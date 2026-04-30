"""Plan C endpoint support tables — notifications, widget layouts, saved filters,
scheduled reports, finding workflow records, and asset tag vocabulary.

Revision ID: 003_plan_c_endpoint_tables
Revises: 002_plan_a_auth_tables
Create Date: 2026-04-09

Creates:
- notification_records: per-user notification persistence (RT-05/D-32)
- widget_layout_records: per-user dashboard widget layout JSON (BE-04/D-35)
- saved_filter_records: user-owned saved filters with team sharing (BE-09/D-41)
- scheduled_report_records: cron-based scheduled report definitions (BE-10/D-33)
- finding_workflow_records: finding state machine transition audit trail (BE-08/D-29)
- asset_tag_vocab_records: admin-managed tag key vocabulary (BE-07/D-40)
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003_plan_c_endpoint_tables"
down_revision: Union[str, None] = "002_plan_a_auth_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # notification_records: per-user notification persistence (RT-05/D-32)
    op.create_table(
        "notification_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False, server_default=""),
        sa.Column("category", sa.Text, nullable=False, server_default="info"),
        sa.Column("source_module", sa.Text, nullable=True),
        sa.Column("source_entity_id", sa.Text, nullable=True),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_notification_records_user_id", "notification_records", ["user_id"])
    op.create_index("ix_notification_records_category", "notification_records", ["category"])
    op.create_index("ix_notification_records_is_read", "notification_records", ["is_read"])

    # widget_layout_records: one layout per user (BE-04/D-35)
    op.create_table(
        "widget_layout_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("layout_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_widget_layout_records_user_id", "widget_layout_records", ["user_id"], unique=True)

    # saved_filter_records: user-owned saved filters with team sharing (BE-09/D-41)
    op.create_table(
        "saved_filter_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("filter_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("is_pinned", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("shared_with_team", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_saved_filter_records_user_id", "saved_filter_records", ["user_id"])
    op.create_index("ix_saved_filter_records_entity_type", "saved_filter_records", ["entity_type"])

    # scheduled_report_records: cron-based scheduled report definitions (BE-10/D-33)
    op.create_table(
        "scheduled_report_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("report_type", sa.Text, nullable=False),
        sa.Column("cron_expression", sa.Text, nullable=False),
        sa.Column("recipient_emails_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("config_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_scheduled_report_records_report_type", "scheduled_report_records", ["report_type"])
    op.create_index("ix_scheduled_report_records_is_active", "scheduled_report_records", ["is_active"])
    op.create_index("ix_scheduled_report_records_created_by", "scheduled_report_records", ["created_by"])

    # finding_workflow_records: finding state machine transition audit trail (BE-08/D-29)
    op.create_table(
        "finding_workflow_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("finding_id", sa.Text, nullable=False),
        sa.Column("module_id", sa.Text, nullable=False),
        sa.Column("current_state", sa.Text, nullable=False, server_default="new"),
        sa.Column("previous_state", sa.Text, nullable=True),
        sa.Column("transitioned_by", sa.Text, nullable=False),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_finding_workflow_records_finding_id", "finding_workflow_records", ["finding_id"])
    op.create_index("ix_finding_workflow_records_module_id", "finding_workflow_records", ["module_id"])
    op.create_index("ix_finding_workflow_records_current_state", "finding_workflow_records", ["current_state"])

    # asset_tag_vocab_records: admin-managed tag key vocabulary (BE-07/D-40)
    op.create_table(
        "asset_tag_vocab_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tag_key", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("is_system_default", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_asset_tag_vocab_records_tag_key", "asset_tag_vocab_records", ["tag_key"], unique=True)


def downgrade() -> None:
    op.drop_table("asset_tag_vocab_records")
    op.drop_table("finding_workflow_records")
    op.drop_table("scheduled_report_records")
    op.drop_table("saved_filter_records")
    op.drop_table("widget_layout_records")
    op.drop_table("notification_records")
