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

RFC-09: the prompt body lives in a versioned ``.md`` file resolved
through :class:`PromptRegistry` (mirroring the claim-verifier prompts)
so the cost / seal rows for a console turn carry a prompt_content_hash
+ prompt_version stamp instead of NULL attribution.
"""
from __future__ import annotations

from pathlib import Path

from aila.platform.prompts import PromptRegistry

__all__ = ["DANTE_PROMPT_VERSION", "DANTE_SYSTEM_PROMPT"]

# Version label stamped onto the correlation scope for every dante turn.
# Bump when the prompt body in ``prompts/system_dante.md`` changes so the
# (cost, prompt) join can tell one prompt generation from the next.
DANTE_PROMPT_VERSION = "dante:v1"

_PROMPT_DIR = Path(__file__).parent / "prompts"
_REGISTRY = PromptRegistry(
    _PROMPT_DIR,
    module="platform",
    fallback_base="system_dante.md",
)

# Resolved once at import from the versioned ``system_dante.md`` file. dante
# has no bound version store, so the file body is the single source of truth;
# the strategy leaf ``dante`` falls back to that file through the registry.
DANTE_SYSTEM_PROMPT: str = _REGISTRY.load("dante")
