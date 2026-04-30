"""Error response schemas for AILA REST API."""
from __future__ import annotations

from .common import APIModel

__all__ = ["ErrorResponse"]


class ErrorResponse(APIModel):
    """Standard error response body returned on 4xx and 5xx responses.

    All HTTP error responses from AILA use this shape. Clients should
    check the `detail` field for a human-readable error message. The
    optional `code` field provides a machine-readable error identifier
    for programmatic handling. The optional `errors` list carries
    per-field validation failure details on 422 responses.

    Fields:
        detail: Human-readable description of the error.
        code: Optional machine-readable error code (e.g. "KEY_NOT_FOUND").
        errors: Optional list of per-field validation failure dicts.
    """

    detail: str
    code: str | None = None
    errors: list[dict[str, str]] | None = None
