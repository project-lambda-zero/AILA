"""Per-question conversational LLM assistant for the SbD NFR module.

Design references: D-14, D-15, D-16.

Provides ephemeral per-question help: no server-side chat history is stored.
The caller sends the full conversation history on each request (client-owned).

Threat mitigations:
  T-135-03: Assist context is limited to the specific question's data; no
            cross-session data is exposed in the prompt.
  T-135-05: User message is placed in the 'user' role only (never injected
            into the system prompt).  history is validated as list[dict[str,str]]
            by Pydantic on AssistRequest.
"""

from __future__ import annotations

import logging

from aila.modules.sbd_nfr.contracts.resolution import AssistRequest, AssistResponse
from aila.modules.sbd_nfr.db_models import (
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrSectionRecord,
    SbdNfrSubgroupRecord,
 )
from aila.platform.exceptions import NotFoundError
from aila.platform.services.factory import ServiceFactory

__all__ = ["handle_assist"]

_log = logging.getLogger(__name__)

_ASSIST_TASK_TYPE: str = "assist"


async def handle_assist(
    question_id: str,
    request: AssistRequest,
    actor_id: str,
) -> AssistResponse:
    """Return a conversational LLM reply for a per-question assist request.

    Builds a context-rich system prompt from the question record, its available
    answer options, the section's guideline/policy reference, and the user's
    current answer.  The conversation history and the new user message are
    appended as user/assistant turns.

    Ephemeral: no server-side chat history is stored.

    Security (T-135-03): only data for the specific question_id is loaded.
    Security (T-135-05): user message placed in user role, never system prompt.

    Args:
        question_id: The NFR question the user needs help with.
        request: Validated assist request containing message, history, current_answer.
        actor_id: ApiKeyRecord.id of the authenticated caller (for logging).

    Returns:
        AssistResponse with the model reply. Missing questions and upstream LLM
        failures propagate truthfully instead of being flattened into canned text.
    """
    _log.info(
        "handle_assist invoked: question_id=%r actor_id=%r",
        question_id,
        actor_id,
    )
    svc = ServiceFactory()
    llm_client = svc.llm_client

    # --- Load question record ---
    question = await svc.storage.fetch_one(
        SbdNfrQuestionRecord, SbdNfrQuestionRecord.id == question_id
    )
    if question is None:
        raise NotFoundError(f"Question '{question_id}' not found")

    # --- Load available options for this question ---
    options = await svc.storage.fetch_all(
        SbdNfrQuestionOptionRecord,
        SbdNfrQuestionOptionRecord.question_id == question_id,
    )
    # Sort by display_order in Python (replaces SQL ORDER BY)
    options.sort(key=lambda o: o.display_order or 0)

    # --- Load section for guideline/policy reference ---
    section = None
    subgroup = await svc.storage.fetch_one(
        SbdNfrSubgroupRecord,
        SbdNfrSubgroupRecord.id == question.subgroup_id,
    )
    if subgroup is not None:
        section = await svc.storage.fetch_one(
            SbdNfrSectionRecord,
            SbdNfrSectionRecord.id == subgroup.section_id,
        )
    # --- Build system prompt (D-15) ---
    system_prompt = _build_assist_system_prompt(question, options, section, request.current_answer)

    # --- Build messages list (T-135-05: user message in user role only) ---
    messages: list[dict[str, str]] = [
        {"role": "system", "content": system_prompt},
    ]

    # Append conversation history turns
    for turn in request.history:
        role = turn.get("role", "user")
        content = turn.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})

    # Append the new user message
    messages.append({"role": "user", "content": request.message})

    # --- Call LLM (regular chat — free text response, not structured) ---
    llm_response = await llm_client.chat(
        task_type=_ASSIST_TASK_TYPE,
        messages=messages,
    )
    if llm_response.disabled:
        _log.warning("handle_assist: LLM disabled for question %r", question_id)
    return AssistResponse(reply=llm_response.content)


# ---------------------------------------------------------------------------
# Prompt building helper
# ---------------------------------------------------------------------------


def _build_assist_system_prompt(
    question: SbdNfrQuestionRecord,
    options: list[SbdNfrQuestionOptionRecord],
    section: SbdNfrSectionRecord | None,
    current_answer: str | None,
) -> str:
    """Build the assist system prompt for a specific question.

    Includes question text, available options, section guideline/policy
    reference, help_text, instruction, and the user's current answer.

    Security (T-135-05): user input (current_answer) is safely embedded in
    the system prompt as a quoted field label, not executed or interpreted.

    Args:
        question: The question record being asked about.
        options: Available answer options for the question.
        section: The section this question belongs to (may be None).
        current_answer: The requester's currently selected answer (may be None).

    Returns:
        Formatted system prompt string.
    """
    lines = [
        "You are a Security by Design (SbD) consultant helping a requester "
        "understand and answer an NFR (Non-Functional Requirements) assessment question.",
        "You have deep knowledge of the AILA NFR Security Framework "
        "and security engineering best practices.",
        "",
        "Your role is to provide clear, concise, helpful guidance — not to answer "
        "on behalf of the requester.",
        "",
        "=== CURRENT QUESTION ===",
        f"Question: {question.label}",
    ]

    if question.instruction:
        lines.append(f"Instruction: {question.instruction}")

    if question.help_text:
        lines.append(f"Help text: {question.help_text}")

    if options:
        lines.append("")
        lines.append("Available answers:")
        for opt in options:
            if opt.label and opt.label != opt.value:
                lines.append(f"  - {opt.value}: {opt.label}")
            else:
                lines.append(f"  - {opt.value}")

    if section is not None:
        lines.append("")
        lines.append(f"Section: {section.label}")
        if section.description:
            lines.append(f"Section description: {section.description}")

    if current_answer is not None:
        lines.append("")
        lines.append(f"Requester's current answer: {current_answer}")

    lines.append("")
    lines.append(
        "Provide a clear, practical explanation that helps the requester "
        "decide how to answer this question for their specific project."
    )

    return "\n".join(lines)
