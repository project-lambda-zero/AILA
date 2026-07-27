"""Panel investigation message -- forensics concrete (#18).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.message_base`. The panel setup + emit states
post system-authored messages here (draft-review requests, quorum outcomes)
so operators watching one branch see decisions posted by siblings.

Unlike VR, no auto-steering dedup composite index is needed yet -- the
forensics module has no auto-steering rules wired for the panel path.
The single-column ``payload_kind`` index inherited from the base is
sufficient.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.message_base import MessageRecordBase

__all__ = ["ForensicsInvestigationMessageRecord"]


class ForensicsInvestigationMessageRecord(MessageRecordBase, table=True):
    """One message in a forensics panel investigation conversation."""

    __tablename__ = "forensics_investigation_messages"
    __investigation_tablename__: ClassVar[str] = "forensics_investigations"
    __branch_tablename__: ClassVar[str] = "forensics_investigation_branches"
