"""Retired: StructuredAgent session-memory accumulation is gone.

Issue #62 migration. The tests that lived here (AGENT-08) targeted a
per-agent ``SessionMemory`` object accessed as ``agent._session_memory`` that
appended a summary of every ``run_structured()`` result and prepended prior
entries into the next prompt under a "Prior calls in this session:" header,
plus ``agent.reset_session()`` that cleared both the memory and the output
cache.

The current production agent (src/aila/platform/routing/agent.py) has no
session-memory attribute, no reset hook, no per-call summary accumulator, and
no prompt prefix mechanism. Cross-run persistence lives in
``PermanentMemoryStore`` (see tests/test_memory_store.py); ephemeral per-run
state lives on ``RunState.events`` and is managed by the workflow engine, not
the agent.

Every test formerly in this file only exercised behavior that no longer
exists, so they were deleted rather than reworked. Retained as an empty
module so pytest collection succeeds cleanly and the deletion is
self-documenting.
"""
from __future__ import annotations
