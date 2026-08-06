"""Tool implementations for the hello_world module.

Minimal tool for platform contract smoke testing.
"""
from __future__ import annotations

from aila.config import Settings, get_settings
from aila.platform.tools import Tool

__all__ = ["HelloGreetTool"]


class HelloGreetTool(Tool):
    """Minimal greeting tool for hello_world smoke testing.

    Single-action tool: validates the action string in forward(),
    then delegates to _execute().
    """

    name = "hello_world_greet"
    description = "Returns a greeting from the hello_world module."
    inputs = {
        "action": {
            "type": "string",
            "description": "Must be 'greet'.",
        },
        "query": {
            "type": "string",
            "description": "Optional query string.",
            "nullable": True,
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    _action = "greet"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def forward(self, action: str | None = None, **kwargs) -> dict:  # type: ignore[override]
        """Route the action and delegate to _execute().

        Args:
            action: Action name string. Must match _action.
            **kwargs: Passed through to _execute().

        Returns:
            Dict result from _execute().

        Raises:
            ValueError: If action does not match the supported action.
        """
        effective = str(action or self._action).strip().lower()
        if effective != self._action:
            raise ValueError(
                f"{type(self).__name__} does not support action '{action}'. "
                f"Only '{self._action}' is supported."
            )
        return self._execute(**kwargs)

    def _execute(self, query: str | None = None, **kwargs) -> dict:
        """Execute the greet action.

        Args:
            query: Optional query string.
            **kwargs: Additional keyword arguments ignored by this action.

        Returns:
            A dict with a greeting message.
        """
        return {"greeting": f"Hello from hello_world module! query={query}"}
