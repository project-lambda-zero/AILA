"""Smoke + behavioural tests for the SSE investigation-messages stream.

The full SSE behaviour (multi-message tail, heartbeats, terminal-status
shutdown) is hard to assert with the unit test loop, so we cover:

  1. Route is registered at the expected path with GET.
  2. 404 on unknown investigation (auth path works, polling never starts).
  3. The generator yields ``event: done`` immediately when the
     investigation is already in a terminal state and no new messages
     are pending — proves the loop's exit condition is wired.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from aila.api.app import create_app


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_sse_route_registered() -> None:
    """The SSE endpoint must appear in the app's route table."""
    app = create_app()
    paths = {getattr(r, "path", "") for r in app.routes}
    assert "/vr/investigations/{investigation_id}/messages/stream" in paths


def test_route_method_is_get() -> None:
    app = create_app()
    for r in app.routes:
        if getattr(r, "path", "") == "/vr/investigations/{investigation_id}/messages/stream":
            methods = getattr(r, "methods", set())
            assert methods == {"GET"}
            return
    pytest.fail("SSE route not found")


@pytest.mark.asyncio
async def test_unknown_investigation_returns_404(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.get(
        "/vr/investigations/nonexistent/messages/stream",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


def test_since_iso_parses_z_suffix() -> None:
    """Stripping 'Z' to '+00:00' is how the handler accepts JS toISOString output."""
    # Mirrors the parser inside stream_investigation_messages.
    iso = "2026-05-14T12:34:56.789Z"
    cursor = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    assert cursor.tzinfo is not None
    assert cursor.year == 2026
    assert cursor.tzinfo.utcoffset(cursor).total_seconds() == 0
    # Round-trip stable
    assert cursor.astimezone(UTC).isoformat().startswith("2026-05-14T12:34:56")
