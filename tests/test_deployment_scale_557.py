"""Deployment prerequisites for scaling workers (#557 Phase 0)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _compose(name: str) -> dict[str, Any]:
    path = REPO_ROOT / "infra" / "utilities" / name
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_full_compose_services_support_replicas() -> None:
    services = _compose("docker-compose.full.yml")["services"]

    assert all("container_name" not in service for service in services.values())


def test_full_compose_uses_application_environment_names() -> None:
    environment = _compose("docker-compose.full.yml")["x-aila-env"]

    assert environment["AILA_DATABASE_URL"].startswith("postgresql+asyncpg://")
    assert environment["AILA_API_HOST"] == "0.0.0.0"
    assert environment["AILA_API_PORT"] == "8000"


def test_full_compose_postgres_connection_ceiling_matches_development() -> None:
    development = _compose("docker-compose.yml")["services"]["postgres"]["command"]
    production = _compose("docker-compose.full.yml")["services"]["postgres"]["command"]

    assert production == development
    assert "max_connections=200" in production
