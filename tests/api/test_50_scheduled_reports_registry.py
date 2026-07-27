"""#50 -- ``scheduled_reports.py`` uses the injected ConfigRegistry.

The trigger handler previously constructed a bare :class:`ConfigRegistry`
inside the ARQ enqueue path, which broke env-first + request threading:
a runtime-owned registry with warmed cache and per-request overrides was
bypassed for a fresh detached instance whose reads always hit the DB or
default. This test locks in the fix on two fronts:

1. Source-level: no bare ``ConfigRegistry()`` construction survives in
   the router module. A future edit that reintroduces one flips this
   test red before it reaches production.
2. Behavioural: when the trigger endpoint reaches the enqueue path, it
   pulls Redis config from the registry attached to the request (via
   ``get_config_registry``), not from an ad-hoc instance.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import ScheduledReportRecord


ROUTER_PATH = Path(__file__).resolve().parents[2] / "src/aila/api/routers/scheduled_reports.py"


def test_router_has_no_bare_config_registry_construction() -> None:
    """Guard against a regression to the pre-#50 bare-instance pattern."""
    tree = ast.parse(ROUTER_PATH.read_text(encoding="utf-8"))
    offending: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "ConfigRegistry":
                offending.append(node.lineno)
            elif isinstance(func, ast.Attribute) and func.attr == "ConfigRegistry":
                offending.append(node.lineno)
    assert not offending, (
        f"scheduled_reports.py must not construct ConfigRegistry; "
        f"got offending lines: {offending}"
    )


def test_router_imports_canonical_accessor() -> None:
    """The router pulls the registry via the dependency, not a raw class."""
    src = ROUTER_PATH.read_text(encoding="utf-8")
    assert "get_config_registry" in src
    assert "from aila.storage.registry import" not in src, (
        "scheduled_reports must not import ConfigRegistry directly"
    )


@pytest.mark.asyncio
async def test_trigger_reads_redis_url_via_injected_registry(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """Triggering a scheduled report reads redis_url from the injected registry.

    The trigger handler enters an ``except Exception`` block whose payload
    starts with ``registry = get_config_registry(request)`` and ends with
    ``registry.get(\"platform\", \"redis_url\")``. Patching that get() to
    record the call proves the request-scoped registry is the one being
    consulted (a bare ``ConfigRegistry()`` would never see this patch).
    """
    async with async_session_scope() as session:
        record = ScheduledReportRecord(
            name="daily-inventory",
            report_type="inventory",
            cron_expression="0 9 * * MON",
            recipient_emails_json="[]",
            config_json="{}",
            is_active=True,
            created_by="test",
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        report_id = record.id

    with patch(
        "aila.storage.registry.ConfigRegistry.get",
        new=AsyncMock(return_value="redis://localhost:6379"),
    ) as mock_get:
        resp = await async_client_with_registries.post(
            f"/scheduled-reports/{report_id}/trigger",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, resp.text
        # The trigger handler queries the platform namespace for redis_url;
        # an unrelated call would still count, but the specific pair proves
        # the code path was reached.
        call_args = [call.args for call in mock_get.call_args_list]
        assert ("platform", "redis_url") in call_args, (
            f"expected registry.get(platform, redis_url); got {call_args}"
        )
