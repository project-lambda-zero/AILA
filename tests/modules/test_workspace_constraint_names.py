"""Cross-module workspace constraint-name test (#56 / CLAUDE.md #21).

Postgres constraint names are unique per schema, not per table. The malware
and vr workspace models both declared uq_workspace_team_slug, so create_all
(which uses model names, unlike migrations) collided with DuplicateTable when
both modules loaded. The malware model now uses its module-prefixed name,
matching migration 068.
"""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

from aila.modules.malware.db_models.workspace import MalwareWorkspaceRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord


def _unique_constraint_names(model) -> set[str]:
    return {
        c.name
        for c in model.__table__.constraints
        if isinstance(c, UniqueConstraint) and c.name
    }


def test_malware_workspace_uses_module_prefixed_name() -> None:
    names = _unique_constraint_names(MalwareWorkspaceRecord)
    assert "uq_malware_workspace_team_slug" in names
    assert "uq_workspace_team_slug" not in names


def test_workspace_unique_constraint_names_do_not_collide() -> None:
    mal = _unique_constraint_names(MalwareWorkspaceRecord)
    vr = _unique_constraint_names(VRWorkspaceRecord)
    assert mal.isdisjoint(vr), f"colliding constraint names: {mal & vr}"
