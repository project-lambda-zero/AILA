"""Investigation-message table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.message_base``; the
concrete below sets ``__tablename__``, ``__investigation_tablename__``,
and ``__branch_tablename__``.

Demonstrates the module-specific Index override: ``auto_steering_key``
is a plain column on the base (index shape differs per module), so the
subclass appends its flavor to ``__table_args__``. The malware full-
column form is used here (vr uses a composite ``(investigation_id,
auto_steering_key)`` instead); pick whichever matches your dedup query.
"""
from __future__ import annotations

from typing import ClassVar

from sqlalchemy import Index

from aila.platform.contracts.message_base import MessageRecordBase

__all__ = ["TemplateInvestigationMessageRecord"]


class TemplateInvestigationMessageRecord(MessageRecordBase, table=True):
    """Scaffold: one message in an investigation conversation."""

    __tablename__ = "template_investigation_messages"
    __investigation_tablename__: ClassVar[str] = "template_investigations"
    __branch_tablename__: ClassVar[str] = "template_investigation_branches"

    # Splice ahead of the base's foreign-key markers so
    # ``__init_subclass__`` still resolves them at class-creation time.
    __table_args__ = (
        *MessageRecordBase.__table_args__,
        Index(
            "ix_template_investigation_messages_auto_steering_key",
            "auto_steering_key",
        ),
    )
