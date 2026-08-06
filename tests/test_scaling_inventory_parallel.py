"""Tests for parallel inventory collection.

Originally SCALE-01 (Phase 21 Plan 01) mandated a ThreadPoolExecutor around a
sync `_collect_one_system`. Subsequent refactors converted the whole path to
`asyncio.gather` over async coroutines -- SSHCommandTool is natively async, so
the thread pool is gone and `_collect_one_system` is now an async coroutine.
Tests here reflect the current async implementation:

- `_collect_and_record_inventory` fans out via `asyncio.gather`.
- `_collect_one_system` is async and returns `(InventoryArtifact|None, InventoryFailure|None)`.
- Nothing in the signature takes a session -- workers stay out of the DB.
"""
from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

from aila.modules.vulnerability.services.inventory import InventoryService


def _make_inventory_service() -> InventoryService:
    """Return an InventoryService with fully mocked dependencies."""
    return InventoryService(
        registry_tool=MagicMock(),
        profile_tool=MagicMock(),
        ssh_tool=MagicMock(),
        adapters=MagicMock(),
        settings=MagicMock(ssh_max_workers=10),
    )


def test_collect_and_record_inventory_parallelizes_via_asyncio_gather():
    """_collect_and_record_inventory source must reference asyncio.gather.

    The SCALE-01 ThreadPoolExecutor mechanism was removed when the SSH path became
    fully async; parallel fan-out is now expressed via `asyncio.gather`.
    """
    service = _make_inventory_service()
    src = inspect.getsource(service._collect_and_record_inventory)
    assert "asyncio.gather" in src, (
        "_collect_and_record_inventory must fan out via asyncio.gather; "
        "the ThreadPoolExecutor variant was replaced by the async SSH path."
    )


def test_collect_one_system_method_exists():
    """InventoryService must expose a _collect_one_system private method."""
    service = _make_inventory_service()
    assert hasattr(service, "_collect_one_system"), "_collect_one_system not found on InventoryService"


async def test_collect_one_system_returns_tuple():
    """_collect_one_system must return a (inventory|None, failure|None) tuple on the happy path."""
    from aila.modules.vulnerability.contracts import InventoryArtifact

    service = _make_inventory_service()

    # Build minimal mocks for a successful path. `_resolve_profile` and
    # `adapter.collect_inventory` are both awaited inside `_collect_one_system`,
    # so they must be AsyncMocks that resolve to the intended values.
    mock_profile = MagicMock()
    mock_inventory = MagicMock(spec=InventoryArtifact)
    mock_adapter = MagicMock()
    mock_adapter.collect_inventory = AsyncMock(return_value=mock_inventory)

    profiles = {"ubuntu": mock_profile}

    mock_system = MagicMock()
    mock_system.distro = "ubuntu"

    with patch.object(service, "_resolve_profile", new=AsyncMock(return_value=mock_profile)):
        with patch(
            "aila.modules.vulnerability.services.inventory.find_distribution_adapter",
            return_value=mock_adapter,
        ):
            result = await service._collect_one_system(mock_system, profiles)

    assert isinstance(result, tuple), "_collect_one_system must return a tuple"
    assert len(result) == 2, "_collect_one_system must return a 2-tuple"
    inventory, failure = result
    assert inventory is mock_inventory
    assert failure is None


async def test_collect_one_system_returns_failure_on_exception():
    """_collect_one_system must catch expected transport-level exceptions and return
    (None, InventoryFailure).

    The source catches (AILAError, paramiko.ssh_exception.SSHException, OSError) --
    OSError is the closest fit for a real SSH transport failure and is what a live
    SSH error surfaces as.
    """
    from aila.modules.vulnerability.contracts import InventoryFailure

    service = _make_inventory_service()

    mock_system = MagicMock()
    mock_system.distro = "ubuntu"
    mock_system.id = 1
    mock_system.name = "test-host"
    mock_system.host = "192.168.1.1"
    profiles = {"ubuntu": MagicMock()}

    with patch.object(
        service,
        "_resolve_profile",
        new=AsyncMock(side_effect=OSError("SSH error")),
    ):
        result = await service._collect_one_system(mock_system, profiles)

    assert isinstance(result, tuple)
    inventory, failure = result
    assert inventory is None
    assert isinstance(failure, InventoryFailure)
    assert "SSH error" in failure.reason


def test_session_not_passed_to_worker():
    """_collect_one_system must not accept a session parameter (no DB writes in workers)."""
    service = _make_inventory_service()
    sig = inspect.signature(service._collect_one_system)
    assert "session" not in sig.parameters, "session must not be passed to _collect_one_system"


def test_ssh_max_workers_declared_in_vulnerability_config_schema():
    """The `ssh_max_workers` config field must remain declared on the vulnerability config schema.

    The current async implementation does NOT consult this value (asyncio.gather is
    unbounded), so this is a safety net on the configuration surface only. See yield
    report for the production divergence -- the field is declared but no longer honored.
    """
    from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema

    assert "ssh_max_workers" in VulnerabilityConfigSchema.model_fields, (
        "ssh_max_workers must remain declared on VulnerabilityConfigSchema; removing "
        "it is a breaking change to the config surface."
    )

