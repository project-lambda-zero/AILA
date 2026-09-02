"""dante -- platform-owned console conversational agent (req 25)."""
from __future__ import annotations

from aila.platform.agents.dante.agent import (
    DanteAgent,
    DanteReply,
    validate_dante_actions,
)
from aila.platform.agents.dante.prompt import (
    DANTE_PROMPT_VERSION,
    DANTE_SYSTEM_PROMPT,
)

__all__ = [
    "DANTE_PROMPT_VERSION",
    "DANTE_SYSTEM_PROMPT",
    "DanteAgent",
    "DanteReply",
    "validate_dante_actions",
]
