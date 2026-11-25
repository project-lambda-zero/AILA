from __future__ import annotations

from aila.config import get_settings
from aila.platform.services.sandbox.backends.oci import OciBackend
from aila.platform.services.sandbox.backends.oci_flow import (
    OciFlowContext,
    OciFlowTelemetry,
    OciTelemetryMode,
)
from aila.platform.services.sandbox.service import SandboxService


class _NullSink:
    async def record_oci_flow(self, _event: object) -> None:
        return None

    async def record_oci_flow_health(self, _health: object) -> None:
        return None


def _telemetry() -> OciFlowTelemetry:
    return OciFlowTelemetry(
        context=OciFlowContext(
            fingerprint="fp-test",
            campaign_id="camp-1",
            action_id="act-1",
            request_id="req-1",
            destination_asset_id="asset-1",
            sandbox_identity="sbx-1",
        ),
        sink=_NullSink(),
        mode=OciTelemetryMode.ENFORCE,
    )


def test_sandbox_service_injects_flow_telemetry_into_oci_backend() -> None:
    telemetry = _telemetry()
    service = SandboxService(get_settings(), oci_flow_telemetry=telemetry)
    backend = service._backends[OciBackend.name]
    assert isinstance(backend, OciBackend)
    assert backend._flow_telemetry is telemetry


def test_sandbox_service_defaults_to_telemetry_off() -> None:
    service = SandboxService(get_settings())
    backend = service._backends[OciBackend.name]
    assert isinstance(backend, OciBackend)
    assert backend._flow_telemetry is None
