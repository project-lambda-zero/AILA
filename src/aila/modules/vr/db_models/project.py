"""Project table definition for the vulnerability research module."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["VRProjectRecord"]


class VRProjectRecord(SQLModel, table=True):
    """A vulnerability research project tracking a single target binary or codebase.

    Written by: POST /vr/projects, vr.state_intake workflow state.
    Consumed by: project listing, finding triage, advisory builder.

    Stores both immutable identification (CVE id, target path) and mutable runtime
    state (status, budget snapshot, obligation snapshot) so the workflow engine can
    rehydrate a paused run from the row alone.
    """

    __tablename__ = "vr_projects"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    team_id: str | None = Field(default=None, index=True)
    name: str = Field(index=True, max_length=255)
    cve_id: str | None = Field(default=None, index=True, max_length=32)
    target_class: str = Field(default="native", index=True, max_length=32)
    target_path: str | None = Field(default=None, sa_column=Column(Text))
    binary_id: str | None = Field(default=None, max_length=128)
    patched_path: str | None = Field(default=None, sa_column=Column(Text))
    patched_binary_id: str | None = Field(default=None, max_length=128)
    source_available: bool = Field(default=False)
    input_source: str = Field(default="upload", max_length=32)
    target_format: str | None = Field(default=None, max_length=32)
    repo_url: str | None = Field(default=None, sa_column=Column(Text))
    vulnerable_ref: str | None = Field(default=None, max_length=255)
    patched_ref: str | None = Field(default=None, max_length=255)
    build_command: str | None = Field(default=None, sa_column=Column(Text))
    build_artifact: str | None = Field(default=None, max_length=512)
    upload_filename: str | None = Field(default=None, max_length=512)
    upload_sha256: str | None = Field(default=None, max_length=128)
    download_url: str | None = Field(default=None, sa_column=Column(Text))
    analysis_system_id: int | None = Field(default=None)
    poc_system_id: int | None = Field(default=None)
    context_notes: str = Field(default="", sa_column=Column(Text))
    status: str = Field(default="created", index=True, max_length=32)
    mitigations_json: str = Field(default="{}", sa_column=Column(Text))
    budget_json: str = Field(default="{}", sa_column=Column(Text))
    obligations_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
