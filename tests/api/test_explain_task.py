"""Explain route and task: cache hit 200, queued 202 with dedupe, prompt contents (API-10, D-17)."""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlmodel import select

from aila.api.app import create_app
from aila.modules.vulnerability import module as vulnerability_module  # noqa: F401 -- registers run-findings query
from aila.modules.vulnerability.db_models import PrioritizedFindingRecord
from aila.modules.vulnerability.workflow import task as explain_task
from aila.modules.vulnerability.workflow.task import _build_explain_prompt
from aila.platform.contracts._common import utc_now
from aila.platform.llm.client import LLMResponse
from aila.storage.database import async_session_scope
from aila.storage.db_models import ExplainCacheRecord
from aila.storage.registry import ConfigRegistry

EXPLAIN_URL_TEMPLATE = "/vulnerability/reports/{run_id}/explain"


def test_explain_prompt_lists_each_finding_and_discloses_omitted_count() -> None:
    """The prompt names every shown CVE and states how many findings were left out."""
    findings = [
        {
            "cve_id": "CVE-2024-1111",
            "criticality": "critical",
            "host": "web01",
            "package_name": "openssl",
            "fixed_version": "3.0.14",
            "rationale": "remote code execution",
        },
        {
            "cve_id": "CVE-2024-2222",
            "criticality": "low",
            "host": "db01",
            "package_name": "zlib",
            "fixed_version": None,
            "rationale": None,
        },
    ]

    prompt = _build_explain_prompt("run-abc", findings, total=5)

    assert "Run run-abc has 5 finding(s)" in prompt
    assert "the 2 highest-scoring are listed below" in prompt
    assert "CVE-2024-1111 | criticality=critical | host=web01 | package=openssl" in prompt
    assert "fixed_version=3.0.14" in prompt
    assert "CVE-2024-2222 | criticality=low | host=db01 | package=zlib" in prompt
    assert "fixed_version=none" in prompt
    assert "rationale=none" in prompt


@pytest_asyncio.fixture(scope="function")
async def queue_client(
    test_db, monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[tuple[AsyncClient, list[dict[str, Any]]], None]:
    """Real app with a real TaskQueue; only the Redis/ARQ enqueue is stubbed.

    ``submit`` still persists TaskRecord rows and runs its hash-based dedupe
    against Postgres. The ARQ enqueue is the broker boundary, and Redis is not
    available to the test run, so the stub records each enqueue instead.
    """
    enqueued: list[dict[str, Any]] = []

    async def _record_enqueue(
        track: str,
        task_id: str,
        fn_name: str,
        kwargs: dict[str, object],
        **_broker_options: object,
    ) -> bool:
        enqueued.append({"track": track, "task_id": task_id, "fn_name": fn_name, "kwargs": kwargs})
        return True

    monkeypatch.setattr("aila.platform.tasks.queue._enqueue_arq_job", _record_enqueue)

    stub_runtime = MagicMock()
    stub_runtime.config_registry = ConfigRegistry()
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client, enqueued


@pytest.mark.asyncio
async def test_explain_miss_returns_202_then_repeat_miss_dedupes_to_same_task(
    queue_client: tuple[AsyncClient, list[dict[str, Any]]],
    operator_token: str,
    seeded_run,
) -> None:
    """Cache miss returns 202 with a task id; a repeat miss while queued returns the same id."""
    client, enqueued = queue_client
    headers = {"Authorization": f"Bearer {operator_token}"}
    url = EXPLAIN_URL_TEMPLATE.format(run_id=seeded_run.id)

    first = await client.get(url, headers=headers)
    assert first.status_code == 202
    first_data = first.json()["data"]
    assert first_data["run_id"] == seeded_run.id
    assert first_data["status"] == "queued"
    assert first_data["task_id"]

    second = await client.get(url, headers=headers)
    assert second.status_code == 202
    assert second.json()["data"]["task_id"] == first_data["task_id"]

    assert len(enqueued) == 1
    assert enqueued[0]["track"] == "vulnerability"
    assert enqueued[0]["task_id"] == first_data["task_id"]
    assert enqueued[0]["fn_name"].endswith("run_cve_explain")
    assert enqueued[0]["kwargs"]["run_id"] == seeded_run.id


@pytest.mark.asyncio
async def test_explain_hit_returns_200_with_cached_content(
    queue_client: tuple[AsyncClient, list[dict[str, Any]]],
    operator_token: str,
    seeded_run,
) -> None:
    """Once the explanation is cached, the route returns 200 with that content and enqueues nothing."""
    client, enqueued = queue_client
    async with async_session_scope() as session:
        session.add(
            ExplainCacheRecord(
                run_id=seeded_run.id,
                content="CVE-2024-1111 is critical because of RCE.",
                cached_at=utc_now(),
            )
        )
        await session.commit()

    response = await client.get(
        EXPLAIN_URL_TEMPLATE.format(run_id=seeded_run.id),
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["cached"] is True
    assert "CVE-2024-1111" in data["content"]
    assert enqueued == []


@pytest.mark.asyncio
@pytest.mark.parametrize("team_id", [None, "team-explain"])
async def test_explain_task_writes_cache_row_from_llm_response(
    test_db,
    seeded_run,
    monkeypatch: pytest.MonkeyPatch,
    team_id: str | None,
) -> None:
    """The explain task reads the run's findings, asks the LLM once, and upserts the cache row.

    The team-scoped case proves run_findings keeps rows whose ``team_id`` matches the task's team.
    """
    explanation = "CVE-2024-1111 is critical: remote code execution; upgrade to 3.0.14."
    async with async_session_scope() as session:
        session.add(
            PrioritizedFindingRecord(
                run_id=seeded_run.id,
                team_id=team_id,
                system_id=1,
                host="web01",
                package_name="openssl",
                installed_version="3.0.1",
                cve_id="CVE-2024-1111",
                criticality="critical",
                score=9.8,
                rationale="remote code execution",
                fixed_version="3.0.14",
                nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1111",
            )
        )
        await session.commit()

    llm_calls: list[dict[str, Any]] = []

    class _StubLLMClient:
        """Stands in for the LLM boundary only; the task's DB reads and writes are real."""

        def __init__(self, **_kwargs: object) -> None:
            pass

        async def chat(
            self,
            task_type: str,
            messages: list[dict[str, Any]],
            **kwargs: object,
        ) -> LLMResponse:
            llm_calls.append({"task_type": task_type, "messages": messages, "kwargs": kwargs})
            return LLMResponse(content=explanation)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(explain_task, "AilaLLMClient", _StubLLMClient)

    # ``__wrapped__`` is the raw coroutine behind @platform_task (no DB-backed TaskContext).
    result = await explain_task.run_cve_explain.__wrapped__(
        SimpleNamespace(), run_id=seeded_run.id, team_id=team_id,
    )

    assert len(llm_calls) == 1
    assert llm_calls[0]["task_type"] == explain_task.EXPLAIN_TASK_TYPE
    assert "CVE-2024-1111" in llm_calls[0]["messages"][0]["content"]
    assert result == {
        "run_id": seeded_run.id,
        "findings_explained": 1,
        "findings_total": 1,
        "content_chars": len(explanation),
    }
    async with async_session_scope() as session:
        rows = (
            await session.exec(select(ExplainCacheRecord).where(ExplainCacheRecord.run_id == seeded_run.id))
        ).all()
    assert [row.content for row in rows] == [explanation]


@pytest.mark.asyncio
async def test_explain_unknown_run_is_404_before_enqueue(
    queue_client: tuple[AsyncClient, list[dict[str, Any]]],
    operator_token: str,
) -> None:
    """A cache miss for a run that does not exist returns 404 and never reaches the queue."""
    client, enqueued = queue_client
    response = await client.get(
        EXPLAIN_URL_TEMPLATE.format(run_id="run-does-not-exist"),
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404
    assert enqueued == []
