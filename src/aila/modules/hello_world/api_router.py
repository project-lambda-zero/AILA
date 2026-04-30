"""FastAPI router factory for hello_world module endpoints.

Auto-discovered by the platform via HelloWorldModule.route_specs().
The platform calls create_hello_world_router() and mounts the router
at /hello_world.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import Field

from aila.api.schemas.common import APIModel
from aila.platform.contracts.auth import AuthContext, require_auth

__all__ = ["HelloWorldStatusResponse", "create_hello_world_router"]


class HelloWorldStatusResponse(APIModel):
    """Response for GET /hello_world/status."""

    module: str = Field(description="Module identifier")
    status: str = Field(description="Module health status")


def create_hello_world_router() -> APIRouter:
    """Create and return the hello_world module router.

    Returns:
        A FastAPI APIRouter with one GET /status endpoint.
    """
    router = APIRouter(tags=["hello_world"])
    status_payload = HelloWorldStatusResponse(module="hello_world", status="ok")

    @router.get("/status", response_model=HelloWorldStatusResponse)
    async def hello_status(
        # PROTECTED ENDPOINT — Rule 57 compliance: module health info must not
        # leak to anonymous callers. Unauthenticated requests receive HTTP 401.
        _auth: AuthContext = Depends(require_auth),
    ) -> HelloWorldStatusResponse:
        """Return hello_world module status."""
        return status_payload

    return router
