"""Target table definitions for the vulnerability research module.

Per D-49/D-50: VRTargetRecord is a first-class persistent target identity
that lives inside a workspace. Investigations, fuzzing campaigns,
findings, and disclosures all reference target_id.

Per D-51: capability_profile_json is populated by M3.T-2 through M3.T-4
enrichment pipeline.

Per D-52: VRTargetTagIndexRecord denormalizes tags for fast multi-tag
filter queries from the workspace dashboard.

Written by: POST /api/vr/targets, M3.T enrichment workers.
Consumed by: workspace + per-target dashboards, investigation creation,
fuzzing campaign creation, pattern retrieval applicability filter,
disclosure orchestrator default-track suggester.

The shared columns live on the platform bases (RFC-01); this module only
sets the concrete table + foreign-key target names. VR carries no
target residue.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.target_base import TargetRecordBase, TargetTagIndexBase

__all__ = ["VRTargetRecord", "VRTargetTagIndexRecord"]


class VRTargetRecord(TargetRecordBase, table=True):
    """A persistent target identity owned by a workspace (D-49/D-50/D-51)."""

    __tablename__ = "vr_targets"
    __workspace_tablename__: ClassVar[str] = "vr_workspaces"


class VRTargetTagIndexRecord(TargetTagIndexBase, table=True):
    """Denormalized tag-to-target index for fast filter queries (D-52)."""

    __tablename__ = "vr_target_tag_index"
    __target_tablename__: ClassVar[str] = "vr_targets"
    __workspace_tablename__: ClassVar[str] = "vr_workspaces"
