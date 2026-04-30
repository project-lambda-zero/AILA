"""Tool API request/response schemas."""
from __future__ import annotations

from pydantic import Field

from .common import APIModel

__all__ = ["ToolDetailResponse", "ToolInvokeRequest", "ToolInvokeResponse", "ToolSummaryResponse"]


class ToolSummaryResponse(APIModel):
    """Summary view of a registered tool.

    Returned in GET /tools list. Includes identifying info but not the
    full input schema -- use GET /tools/{tool_key} for that.
    """

    tool_key: str = Field(description="Registry key for this tool (e.g. 'vuln.query_cves')")
    name: str = Field(description="Human-readable tool name")
    description: str = Field(description="What this tool does")
    module_id: str = Field(description="Module that registered this tool")


class ToolDetailResponse(ToolSummaryResponse):
    """Full detail view of a registered tool including its input schema.

    Returned by GET /tools/{tool_key}.
    """

    inputs: dict[str, object] = Field(
        default_factory=dict,
        description="JSON Schema object describing forward() kwargs",
    )
    output_type: str = Field(default="string", description="Return type name for tool.forward()")


class ToolInvokeRequest(APIModel):
    """Request body for POST /tools/{tool_key}.

    kwargs are passed directly to tool.forward(**kwargs). The platform
    validates that all required inputs are present before invoking.
    """

    kwargs: dict[str, object] = Field(
        default_factory=dict,
        description="Keyword arguments passed to tool.forward()",
    )


class ToolInvokeResponse(APIModel):
    """Response from POST /tools/{tool_key}.

    result is the raw return value from tool.forward(). error is set if
    the tool raised an exception; result is null when error is present.
    """

    tool_key: str = Field(description="Tool that was invoked")
    result: object = Field(default=None, description="Return value from tool.forward()")
    error: str | None = Field(default=None, description="Error message if invocation failed")
