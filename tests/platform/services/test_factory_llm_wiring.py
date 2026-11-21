from __future__ import annotations

from aila.platform.events.bus import default_bus
from aila.platform.llm.cost import CostTracker
from aila.platform.runtime.shared import get_shared_run_memory
from aila.platform.services.factory import ServiceFactory
from aila.storage.secrets import SecretStore


def test_llm_client_is_memoized_per_factory() -> None:
    factory = ServiceFactory()
    assert factory.llm_client is factory.llm_client


def test_llm_client_is_wired_to_cost_tracker_and_default_bus() -> None:
    client = ServiceFactory().llm_client
    assert isinstance(client.cost_tracker, CostTracker)
    assert client.bus is default_bus()


def test_llm_clients_share_the_published_run_memory() -> None:
    first = ServiceFactory().llm_client
    second = ServiceFactory().llm_client
    assert first is not second
    # CostTracker keeps its RunMemory in ``_mem``; the factory publishes one shared instance.
    assert first.cost_tracker._mem is second.cost_tracker._mem
    assert first.cost_tracker._mem is get_shared_run_memory()


def test_secret_store_is_memoized_per_factory() -> None:
    factory = ServiceFactory()
    assert isinstance(factory.secret_store, SecretStore)
    assert factory.secret_store is factory.secret_store


def test_injected_secret_store_is_returned_unchanged() -> None:
    store = SecretStore()
    assert ServiceFactory(secret_store=store).secret_store is store


def test_injected_llm_client_overrides_the_wired_one() -> None:
    injected = ServiceFactory().llm_client
    assert ServiceFactory(llm_client=injected).llm_client is injected
