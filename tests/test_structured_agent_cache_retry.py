"""Retired: StructuredAgent output cache + in-agent retry loop are gone.

Issue #62 migration. The tests that lived here targeted three removed
internals on aila.platform.routing.agent.StructuredAgent:

- ``agent._output_cache`` (in-process dict caching prompt -> validated model).
- The in-agent retry loop that re-invoked the LLM with an appended parse
  error on JSON/schema failure.
- ``aila.platform.llm.cache_key`` helper for keying the cache.

The current production agent (src/aila/platform/routing/agent.py) is a thin
"build prompt -> await model.chat_structured -> json.loads -> model_validate ->
log" shim. Retry, JSON-parse recovery, and structured-output enforcement now
live inside ``AilaLLMClient.chat_structured`` and are covered by the platform
LLM test suite. There is no output cache on the agent; every call goes to the
model. The scoped-cache concern shifted to the module-owned caches
(``CacheRecord`` for scoring reviews, OSV cache tables, etc.), not to a
per-agent dict.

Every test formerly in this file only exercised behavior that no longer
exists, so they were deleted rather than reworked. Retained as an empty
module so pytest collection succeeds cleanly and the deletion is
self-documenting.
"""
from __future__ import annotations
