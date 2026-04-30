"""Integration tests for the SbD NFR assist service.

Uses real PostgreSQL (via test_db / async_db_session fixtures) and real
AilaLLMClient. Tests are skipped when no LLM API key is configured.

No mocking of ServiceFactory, AilaLLMClient, UnitOfWork, or AsyncSession.
The test_db fixture sets AILA_DATABASE_URL so ServiceFactory resolves to
the test database.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aila.modules.sbd_nfr.contracts.resolution import AssistRequest, AssistResponse
from aila.modules.sbd_nfr.db_models import (
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrSchemaVersionRecord,
    SbdNfrSectionRecord,
    SbdNfrSubgroupRecord,
)
from aila.modules.sbd_nfr.services.assist_service import handle_assist
from aila.platform.exceptions import NotFoundError

# ---------------------------------------------------------------------------
# LLM availability guard
# ---------------------------------------------------------------------------


def _llm_key_available() -> bool:
    return bool(
        os.environ.get("AILA_OPENAI_KEY")
        or os.environ.get("OPENROUTER_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )


pytestmark = pytest.mark.skipif(
    not _llm_key_available(),
    reason="No LLM API key configured — set AILA_OPENAI_KEY or OPENROUTER_API_KEY",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_assist_returns_reply(async_db_session):
    """handle_assist returns an AssistResponse with a non-empty reply.

    Seeds a real question, option, and section into the test DB.
    Calls handle_assist with real AilaLLMClient. Asserts reply is non-empty.
    """

    db = async_db_session

    # Seed schema version
    db.add(SbdNfrSchemaVersionRecord(
        id=str(uuid4()), version=1, change_summary="seed", changed_by="test",
    ))

    # Seed section
    section = SbdNfrSectionRecord(
        id=str(uuid4()),
        schema_version=1,
        section_key="data_classification",
        label="Data Classification",
        guideline="Follow GDPR Article 5.",
        display_order=0,
        is_active=True,
    )
    db.add(section)

    # Seed subgroup
    sg = SbdNfrSubgroupRecord(
        id=str(uuid4()),
        schema_version=1,
        section_id=section.id,
        subgroup_key="pii_handling",
        label="PII Handling",
        display_order=0,
        is_active=True,
    )
    db.add(sg)

    # Seed question
    question = SbdNfrQuestionRecord(
        id="ASSIST-Q-01",
        schema_version=1,
        subgroup_id=sg.id,
        section_id=section.id,
        question_type="scope",
        depth_level="standard",
        answer_type="single_choice",
        label="Does the service process PII?",
        help_text="Consider GDPR implications.",
        instruction="Select Yes if any personal data is processed.",
        is_required=True,
        is_active=True,
        display_order=0,
    )
    db.add(question)

    # Seed options
    db.add(SbdNfrQuestionOptionRecord(
        id=str(uuid4()),
        question_id="ASSIST-Q-01",
        value="yes",
        label="Yes, PII is processed",
        display_order=0,
    ))
    db.add(SbdNfrQuestionOptionRecord(
        id=str(uuid4()),
        question_id="ASSIST-Q-01",
        value="no",
        label="No PII",
        display_order=1,
    ))
    await db.commit()

    request = AssistRequest(
        message="What does PII mean in this context?",
        history=[],
        current_answer=None,
    )

    result = await handle_assist("ASSIST-Q-01", request, "user-001")

    assert isinstance(result, AssistResponse)
    assert isinstance(result.reply, str)
    assert len(result.reply) > 0


@pytest.mark.asyncio
async def test_handle_assist_raises_for_missing_question(async_db_session):
    """Missing questions raise NotFoundError instead of returning a canned reply."""

    request = AssistRequest(
        message="Help me understand this question.",
        history=[],
    )

    with pytest.raises(NotFoundError, match="Question 'NONEXISTENT-Q-99' not found"):
        await handle_assist("NONEXISTENT-Q-99", request, "user-001")
