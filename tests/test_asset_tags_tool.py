"""Tests for AssetTagsTool (ENT-05 / plan 27-01, Task 1)."""
from __future__ import annotations

import pytest


async def test_upsert_creates_new_tag(test_db):
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    tool = AssetTagsTool()
    result = await tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="prod")
    assert result["count"] == 1
    assert result["tags"][0]["tag_key"] == "env"
    assert result["tags"][0]["tag_value"] == "prod"


async def test_upsert_updates_existing_tag(test_db):
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    tool = AssetTagsTool()
    await tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="prod")
    result = await tool.forward(action="upsert", system_id=1, tag_key="env", tag_value="staging")
    assert result["count"] == 1
    assert result["tags"][0]["tag_value"] == "staging"


async def test_list_returns_all_tags_for_system(test_db):
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    tool = AssetTagsTool()
    await tool.forward(action="upsert", system_id=2, tag_key="env", tag_value="prod")
    await tool.forward(action="upsert", system_id=2, tag_key="role", tag_value="web")
    await tool.forward(action="upsert", system_id=3, tag_key="env", tag_value="dev")
    result = await tool.forward(action="list", system_id=2)
    assert result["count"] == 2
    keys = {t["tag_key"] for t in result["tags"]}
    assert keys == {"env", "role"}


async def test_delete_removes_tag(test_db):
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    tool = AssetTagsTool()
    await tool.forward(action="upsert", system_id=4, tag_key="env", tag_value="prod")
    result = await tool.forward(action="delete", system_id=4, tag_key="env")
    assert result["deleted_keys"] == ["env"]
    listed = await tool.forward(action="list", system_id=4)
    assert listed["count"] == 0


async def test_unknown_action_raises(test_db):
    from aila.modules.vulnerability.tools.asset_tags import AssetTagsTool

    tool = AssetTagsTool()
    with pytest.raises(ValueError):
        await tool.forward(action="explode", system_id=1)
