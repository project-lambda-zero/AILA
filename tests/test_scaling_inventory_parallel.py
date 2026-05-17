"""Tests for SCALE-01: ThreadPoolExecutor-based parallel inventory collection (Phase 21 Plan 01)."""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock

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


def test_collect_and_record_inventory_uses_thread_pool_executor():
    """_collect_and_record_inventory source must reference ThreadPoolExecutor."""
    service = _make_inventory_service()
    src = inspect.getsource(service._collect_and_record_inventory)
    assert "ThreadPoolExecutor" in src


def test_collect_one_system_method_exists():
    """InventoryService must expose a _collect_one_system private method."""
    service = _make_inventory_service()
    assert hasattr(service, "_collect_one_system"), "_collect_one_system not found on InventoryService"


def test_collect_one_system_returns_tuple():
    """_collect_one_system must return a (inventory|None, failure|None) tuple."""
    from aila.modules.vulnerability.contracts import InventoryArtifact

    service = _make_inventory_service()

    # Build minimal mocks for a successful path
    mock_profile = MagicMock()
    mock_inventory = MagicMock(spec=InventoryArtifact)
    mock_adapter = MagicMock()
    mock_adapter.collect_inventory.return_value = mock_inventory

    profiles = {"ubuntu": mock_profile}

    mock_system = MagicMock()
    mock_system.distro = "ubuntu"

    # Patch find_distribution_adapter and _resolve_profile
    from unittest.mock import patch
    with patch.object(service, "_resolve_profile", return_value=mock_profile):
        with patch(
            "aila.modules.vulnerability.services.inventory.find_distribution_adapter",
            return_value=mock_adapter,
        ):
            result = service._collect_one_system(mock_system, profiles)

    assert isinstance(result, tuple), "_collect_one_system must return a tuple"
    assert len(result) == 2, "_collect_one_system must return a 2-tuple"
    inventory, failure = result
    assert inventory is mock_inventory
    assert failure is None


def test_collect_one_system_returns_failure_on_exception():
    """_collect_one_system must catch exceptions and return (None, InventoryFailure)."""
    from aila.modules.vulnerability.contracts import InventoryFailure

    service = _make_inventory_service()

    mock_system = MagicMock()
    mock_system.distro = "ubuntu"
    mock_system.id = 1
    mock_system.name = "test-host"
    mock_system.host = "192.168.1.1"
    profiles = {"ubuntu": MagicMock()}

    from unittest.mock import patch
    with patch.object(service, "_resolve_profile", side_effect=RuntimeError("SSH error")):
        result = service._collect_one_system(mock_system, profiles)

    assert isinstance(result, tuple)
    inventory, failure = result
    assert inventory is None
    assert isinstance(failure, InventoryFailure)
    assert "SSH error" in failure.reason


def test_session_not_passed_to_worker():
    """_collect_one_system must not accept a session parameter (no DB writes in threads)."""
    service = _make_inventory_service()
    sig = inspect.signature(service._collect_one_system)
    assert "session" not in sig.parameters, "session must not be passed to _collect_one_system"


def test_ssh_max_workers_used_from_settings():
    """_collect_and_record_inventory must read ssh_max_workers from self.settings via getattr fallback."""
    src = inspect.getsource(InventoryService._collect_and_record_inventory)
    assert "ssh_max_workers" in src, "ssh_max_workers not referenced in _collect_and_record_inventory"
