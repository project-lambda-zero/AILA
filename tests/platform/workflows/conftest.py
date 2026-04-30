"""Fixtures for the durable workflows engine tests.

Reuses the session-scoped ``test_db`` fixture from
``tests/platform/conftest.py`` so every test runs against real Postgres
(no SQLite fallback per project policy).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest_asyncio

from aila.platform.workflows import (
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord

# ---- Toy services ----------------------------------------------------------


@dataclass
class ToyServices:
    """Minimal WorkflowServices impl with per-build call counters."""

    run_id: str
    build_count: int = 0
    handler_calls: dict[str, int] = field(default_factory=dict)

    @classmethod
    async def build(cls, run_id: str) -> ToyServices:
        return cls(run_id=run_id, build_count=1)


async def toy_services_factory(run_id: str) -> WorkflowServices:
    return await ToyServices.build(run_id)


# ---- Toy 3-state workflow: start -> work -> __succeeded__ -----------------


async def _start_handler(
    state_input: dict[str, Any], services: ToyServices
) -> StateResult:
    n = int(state_input.get("n", 0)) + 1
    return StateResult(next_state="work", output={"n": n})


async def _work_handler(
    state_input: dict[str, Any], services: ToyServices
) -> StateResult:
    n = int(state_input.get("n", 0)) + 1
    return StateResult(next_state="__succeeded__", output={"n": n, "done": True})


@pytest_asyncio.fixture
async def toy_definition() -> WorkflowDefinition:
    return WorkflowDefinition(
        definition_id="test.toy.v1",
        start_state="start",
        states={
            "start": StateSpec(handler=_start_handler),
            "work": StateSpec(handler=_work_handler),
        },
        services_factory=toy_services_factory,
    )


# ---- workflow_run_id fixture (creates a WorkflowRunRecord) ----------------


@pytest_asyncio.fixture
async def workflow_run_id(test_db: None) -> str:  # noqa: ARG001 — uses fixture
    """Create a WorkflowRunRecord row and return its id.

    Cleanup is delegated to the ``test_db`` TRUNCATE at teardown.
    """
    rid = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=rid,
                query_text="test",
                action_id="test",
                module_id="test",
            )
        )
        await session.commit()
    return rid
