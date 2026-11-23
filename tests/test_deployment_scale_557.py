"""Deployment prerequisites for scaling workers (#557 Phase 0)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = "docker-compose.full.yml"
DEV_COMPOSE = "docker-compose.full.dev.yml"
SHARED_VOLUMES = ["aila_data", "aila_reports", "aila_backups"]
SHARED_MOUNTS = [
    "aila_data:/app/data",
    "aila_reports:/app/reports",
    "aila_backups:/app/backups",
]
IN_CLUSTER_DEFAULTS = {
    "AILA_DATABASE_URL": "postgresql+asyncpg://postgres:changeme@postgres:5432/aila",
    "AILA_PLATFORM_REDIS_URL": "redis://redis:6379/0",
}
_INTERPOLATION = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):-([^}]*)\}")


def _compose(name: str) -> dict[str, Any]:
    path = REPO_ROOT / "infra" / "utilities" / name
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _interpolate(value: str, env: Mapping[str, str]) -> str:
    """Resolve Compose ``${VAR:-default}`` the way ``docker compose`` does."""
    return _INTERPOLATION.sub(lambda match: env.get(match.group(1)) or match.group(2), value)


def _backend_services(compose: dict[str, Any]) -> set[str]:
    """Services built from the repo Dockerfile: the API and every worker."""
    return {name for name, service in compose["services"].items() if "build" in service}


def test_full_compose_services_support_replicas() -> None:
    services = _compose(BASE_COMPOSE)["services"]

    assert all("container_name" not in service for service in services.values())


def test_full_compose_uses_application_environment_names() -> None:
    environment = _compose(BASE_COMPOSE)["x-aila-env"]

    assert _interpolate(environment["AILA_DATABASE_URL"], {}).startswith("postgresql+asyncpg://")
    assert environment["AILA_API_HOST"] == "0.0.0.0"
    assert environment["AILA_API_PORT"] == "8000"


def test_full_compose_postgres_connection_ceiling_matches_development() -> None:
    development = _compose("docker-compose.yml")["services"]["postgres"]["command"]
    production = _compose(BASE_COMPOSE)["services"]["postgres"]["command"]

    assert production == development
    assert "max_connections=200" in production


@pytest.mark.parametrize("name", sorted(IN_CLUSTER_DEFAULTS))
def test_base_endpoints_are_interpolated_with_in_cluster_defaults(name: str) -> None:
    raw = _compose(BASE_COMPOSE)["x-aila-env"][name]
    default = IN_CLUSTER_DEFAULTS[name]
    external = {
        "AILA_DATABASE_URL": "postgresql+asyncpg://aila:secret@db.internal:5432/aila",
        "AILA_PLATFORM_REDIS_URL": "redis://cache.internal:6379/1",
    }[name]

    assert raw == f"${{{name}:-{default}}}"
    assert _interpolate(raw, {}) == default
    assert _interpolate(raw, {name: external}) == external


def test_backend_services_receive_interpolated_endpoints() -> None:
    compose = _compose(BASE_COMPOSE)
    shared = compose["x-aila-env"]
    backends = _backend_services(compose)

    assert backends == {"api"} | {n for n in compose["services"] if n.startswith("worker-")}
    for name in backends:
        environment = compose["services"][name]["environment"]
        assert environment["AILA_DATABASE_URL"] == shared["AILA_DATABASE_URL"]
        assert environment["AILA_PLATFORM_REDIS_URL"] == shared["AILA_PLATFORM_REDIS_URL"]


def test_every_backend_mounts_shared_volumes() -> None:
    compose = _compose(BASE_COMPOSE)

    for name in _backend_services(compose):
        assert compose["services"][name]["volumes"] == SHARED_MOUNTS, name


def test_shared_volumes_are_declared() -> None:
    volumes = _compose(BASE_COMPOSE)["volumes"]

    for volume in SHARED_VOLUMES:
        assert volumes[volume] == {"name": volume}


def test_base_compose_publishes_no_host_ports() -> None:
    services = _compose(BASE_COMPOSE)["services"]

    for name, service in services.items():
        assert "ports" not in service, name
    assert services["api"]["expose"] == ["8000"]
    assert services["frontend"]["expose"] == ["3000"]
    assert services["postgres"]["expose"] == ["5432"]
    assert services["redis"]["expose"] == ["6379"]


def test_dev_override_publishes_development_ports() -> None:
    services = _compose(DEV_COMPOSE)["services"]

    assert {name: service["ports"] for name, service in services.items()} == {
        "postgres": ["127.0.0.1:5432:5432"],
        "redis": ["127.0.0.1:6379:6379"],
        "api": ["8000:8000"],
        "frontend": ["3000:3000"],
    }
