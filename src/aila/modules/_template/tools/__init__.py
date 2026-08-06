"""Tool implementations for the template module.

Demonstrates the single-action tool pattern using the platform Tool base.
Replace TemplateSampleTool with your real tool implementation.
"""
from __future__ import annotations

from aila.config import Settings, get_settings
from aila.platform.tools import Tool

__all__ = ["TemplateSampleTool"]


class TemplateSampleTool(Tool):
    """Example tool demonstrating the single-action tool pattern.

    For tools that expose exactly one action: validate the action string
    in forward(), then delegate to a private _execute() method.

    Do not call init_db here. The platform startup path (FastAPI lifespan)
    handles schema bootstrap.
    """

    name = "template_sample_tool"
    description = "Replace with a concrete description of what this tool does."
    inputs = {
        "action": {
            "type": "string",
            "description": "Must be 'sample_query'. Replace with your action name.",
        },
        "query": {
            "type": "string",
            "description": "Replace with real input fields.",
            "nullable": True,
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    _action = "sample_query"

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
        """Execute the sample query action.

        Args:
            query: Optional query string. Replace with real parameters.
            **kwargs: Additional keyword arguments ignored by this action.

        Returns:
            A dict with a 'result' key. Replace with the actual return schema.
        """
        return {"result": f"template result for query={query!r}"}
