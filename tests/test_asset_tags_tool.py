"""Tests for AssetTagsTool (ENT-05 / plan 27-01, Task 1)."""
from __future__ import annotations

import pytest


def _make_tool(tmp_path):
    from aila.config import Settings
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return AssetTagsTool(settings=settings)


def test_upsert_creates_new_tag(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="prod")
    assert result["count"] == 1
    assert result["tags"][0]["tag_key"] == "env"
    assert result["tags"][0]["tag_value"] == "prod"


def test_upsert_updates_existing_tag(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="prod")
    result = tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="staging")
    assert result["count"] == 1
    assert result["tags"][0]["tag_value"] == "staging"


def test_list_returns_all_tags_for_system(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="upsert", system_id=2, tag_key="env", tag_value="prod")
    tool.forward(action="upsert", system_id=2, tag_key="role", tag_value="web")
    tool.forward(action="upsert", system_id=3, tag_key="env", tag_value="dev")
    result = tool.forward(action="list", system_id=2)
    assert result["count"] == 2
    keys = {t["tag_key"] for t in result["tags"]}
    assert keys == {"env", "role"}


def test_delete_removes_tag(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="upsert", system_id=4, tag_key="env", tag_value="prod")
    result = tool.forward(action="delete", system_id=4, tag_key="env")
    assert result["deleted_keys"] == ["env"]
    listed = tool.forward(action="list", system_id=4)
    assert listed["count"] == 0


def test_unknown_action_raises(tmp_path):
    tool = _make_tool(tmp_path)
    with pytest.raises(ValueError):
        tool.forward(action="explode", system_id=1)
