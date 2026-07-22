"""Cross-module workspace constraint-name test (#56 / CLAUDE.md #21).

Postgres constraint names are unique per schema, not per table. The malware
and vr workspace models both declared uq_workspace_team_slug, so create_all
(which uses model names, unlike migrations) collided with DuplicateTable when
both modules loaded. Both the malware model (migration 068) and the vr model (migration 081)
now use module-prefixed constraint names, so no two workspace/tag models
share an unqualified name.

RFC-01 Phase 2 (#26, migration 084) derives every constraint name from the
concrete ``__tablename__`` via ``TabledUq``, so the workspace name became
``uq_<module>_workspaces_team_slug`` and the tag-index name became
``uq_<module>_target_tag_index_target_tag_source``. Both are still
module-prefixed and disjoint across modules.
"""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

from aila.modules.malware.db_models.target import MalwareTargetTagIndexRecord
from aila.modules.malware.db_models.workspace import MalwareWorkspaceRecord
from aila.modules.vr.db_models.target import VRTargetTagIndexRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord


def _unique_constraint_names(model) -> set[str]:
    return {
        c.name
        for c in model.__table__.constraints
        if isinstance(c, UniqueConstraint) and c.name
    }


def test_malware_workspace_uses_module_prefixed_name() -> None:
    names = _unique_constraint_names(MalwareWorkspaceRecord)
    assert "uq_malware_workspaces_team_slug" in names
    assert "uq_workspace_team_slug" not in names


def test_vr_workspace_uses_module_prefixed_name() -> None:
    names = _unique_constraint_names(VRWorkspaceRecord)
    assert "uq_vr_workspaces_team_slug" in names
    assert "uq_workspace_team_slug" not in names


def test_vr_tag_index_uses_module_prefixed_name() -> None:
    names = _unique_constraint_names(VRTargetTagIndexRecord)
    assert "uq_vr_target_tag_index_target_tag_source" in names
    assert "uq_target_tag_source" not in names


def test_workspace_unique_constraint_names_do_not_collide() -> None:
    mal = _unique_constraint_names(MalwareWorkspaceRecord)
    vr = _unique_constraint_names(VRWorkspaceRecord)
    assert mal.isdisjoint(vr), f"colliding constraint names: {mal & vr}"


def test_malware_tag_index_uses_module_prefixed_name() -> None:
    names = _unique_constraint_names(MalwareTargetTagIndexRecord)
    assert "uq_malware_target_tag_index_target_tag_source" in names
    assert "uq_target_tag_source" not in names


def test_tag_index_unique_constraint_names_do_not_collide() -> None:
    mal = _unique_constraint_names(MalwareTargetTagIndexRecord)
    vr = _unique_constraint_names(VRTargetTagIndexRecord)
    assert mal.isdisjoint(vr), f"colliding constraint names: {mal & vr}"
