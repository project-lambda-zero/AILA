"""System prompt loader for the dante console assistant.

dante is the operator-facing conversational agent that runs behind the
AILA console chat. It interviews the operator, explains what the
platform and its modules do, and -- when the operator's message maps
onto one of dante's four real capabilities -- returns a proposed
DanteAction that the frontend renders as a confirm/open button.

Structural honesty (repo rule 2 / 3): dante claims only the four
capabilities enumerated in ``prompts/system_dante.md``. Every proposed
action is inert on the backend; the frontend performs the mutation via
an existing endpoint after the operator confirms.

RFC-09 / req 20: the prompt body is the DB-only single source of truth.
At import time dante exposes the static text (``DANTE_PROMPT_TEXT``) for
backward compatibility, but the live turn path resolves the prompt from
the version store each call via ``_REGISTRY.resolve("dante")`` so a
released / canary version is honoured and the cost / seal rows for a
console turn carry a prompt_content_hash + prompt_version stamp instead
of NULL attribution.
"""
from __future__ import annotations

from aila.platform.prompts import PromptRegistry
from aila.platform.prompts.seeds import DANTE_TEXT
from aila.platform.prompts.version_store import PromptVersionStore

__all__ = ["DANTE_PROMPT_VERSION", "DANTE_SYSTEM_PROMPT"]

# Version label stamped onto the correlation scope for every dante turn.
# Bump when the prompt body changes so the (cost, prompt) join can tell one
# prompt generation from the next.
DANTE_PROMPT_VERSION = "dante:v1"

_REGISTRY = PromptRegistry(
    module="platform",
    version_store=PromptVersionStore(),
)

# Backward-compatible static body. The live turn path in ``dante/agent.py``
# resolves the prompt from the version store each call via
# ``_REGISTRY.resolve("dante")`` so a released version is honoured; this
# constant is the seeded baseline (identical to ``DANTE_TEXT``).
DANTE_SYSTEM_PROMPT: str = DANTE_TEXT
