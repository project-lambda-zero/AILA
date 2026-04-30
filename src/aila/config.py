"""Infrastructure settings for the AILA platform.

Settings carries exactly 8 infrastructure fields:
- database_url: PostgreSQL URL (via asyncpg driver) for the platform DB.
- report_dir: Directory where workflow report files are written.
- secret_keyring_path: Path to the JSON keyring file for AES-256-GCM secrets.
- secret_active_key_version: Key version label used for new encryptions.
- request_timeout_seconds: Default HTTP timeout for provider clients.
- jwt_secret_key: HS256 signing secret for JWT tokens.  Defaults to a random
  32-byte hex value regenerated each process start.  Operators MUST set
  AILA_JWT_SECRET_KEY in production to ensure token stability across restarts.
- api_host: Host to bind uvicorn to (default 127.0.0.1 or AILA_API_HOST).
- api_port: Port to bind uvicorn to (default 8000 or AILA_API_PORT).

All module-specific configs (e.g. VulnerabilityConfigSchema fields) are stored
in ConfigRegistry, NOT in Settings.  Settings is intentionally slim so tests and
container deployments can override it with a single env var per field.

Tilde (~) paths are rejected with a ValueError pointing to the relevant AILA_*
env var (Phase 46 SRV-02 fix: server/container environments cannot expand
home-directory paths; operators must use absolute paths or env vars).

Field isolation for test isolation: secret_active_key_version and
request_timeout_seconds use field(default_factory=lambda) so that calling
_build_settings.cache_clear() and setting env vars before re-importing produces
a fresh Settings with the new values (Phase 46 SRV-02 fix).
"""

from __future__ import annotations

import functools
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Settings", "get_settings", "init_directories", "PROJECT_ROOT"]

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _resolve_project_path(value: str | Path) -> Path:
    """Resolve a path relative to PROJECT_ROOT, rejecting ~ paths.

    Absolute paths are returned as-is (resolved).  Relative paths are resolved
    relative to PROJECT_ROOT so that default values like "reports" work in both
    development (relative to the repo root) and Docker (absolute via env var).

    Args:
        value: A path string or Path object.

    Returns:
        An absolute Path.

    Raises:
        ValueError: If the path starts with "~" — container/server environments
            cannot expand home-directory paths.  Set an absolute path via the
            relevant AILA_* environment variable instead.
    """
    path = Path(value)
    if str(path).startswith("~"):
        raise ValueError(
            f"Path {str(value)!r} starts with '~' which is not supported in server/container mode. "
            f"Set an absolute path via the relevant AILA_* environment variable."
        )
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _resolve_database_url(value: str | None = None) -> str:
    """Resolve the database URL from the given value or AILA_DATABASE_URL env var.

    PostgreSQL is the only supported database.  The asyncpg driver prefix is
    automatically applied when a bare ``postgresql://`` URL is provided.

    Raises:
        ValueError: If AILA_DATABASE_URL is unset/empty or points to SQLite.
    """
    normalized = str(value or os.getenv("AILA_DATABASE_URL") or "").strip()
    if not normalized:
        raise ValueError(
            "AILA_DATABASE_URL must be set. PostgreSQL is the only supported database. "
            "Example: postgresql+asyncpg://user:pass@localhost:5432/aila"
        )
    if normalized.startswith("sqlite:"):
        raise ValueError(
            "SQLite is no longer supported. Set AILA_DATABASE_URL to a PostgreSQL URL."
        )
    # Rewrite bare postgresql:// to postgresql+asyncpg:// for the async driver.
    if normalized.startswith("postgresql://"):
        normalized = "postgresql+asyncpg://" + normalized[len("postgresql://"):]
    return normalized


@dataclass(slots=True)
class Settings:
    """Infrastructure-only settings for the AILA platform.

    Carries 8 fields — the minimum needed to locate the database, report files,
    secret keyring, active key version, HTTP timeout, and API server bindings.
    Nothing module-specific lives here (Phase 40 HONEST-01 fix: Settings was
    previously bloated with module-config fields that belonged in ConfigRegistry).

    Fields:
        database_url: PostgreSQL URL via asyncpg driver.  Resolved from
            AILA_DATABASE_URL (required).  No default -- fails if unset.
        report_dir: Directory for workflow report files.  Defaults to
            <PROJECT_ROOT>/reports or AILA_REPORT_DIR.
        secret_keyring_path: Path to the AES keyring JSON file.  Defaults to
            <PROJECT_ROOT>/data/secrets/keyring.json or AILA_SECRET_KEYRING_PATH.
        secret_active_key_version: Key version for new encryptions (e.g. "v1").
            Uses default_factory=lambda so cache_clear() + env var yields a fresh
            value in tests (Phase 46 SRV-02 fix).
        request_timeout_seconds: Default HTTP timeout in seconds.  Defaults to 20.0
            or AILA_TIMEOUT.  Uses default_factory=lambda for the same reason.
        jwt_secret_key: HS256 signing secret for JWT tokens.  Defaults to a random
            32-byte hex value (regenerated each process start unless AILA_JWT_SECRET_KEY
            is set).  Operators MUST set this env var in production.
        api_host: Host to bind uvicorn to.  Defaults to 127.0.0.1 or AILA_API_HOST.
        api_port: Port to bind uvicorn to.  Defaults to 8000 or AILA_API_PORT.

    Do not add module-specific config fields here.  Use ConfigRegistry instead.
    """
    database_url: str = field(default_factory=_resolve_database_url)
    report_dir: Path = field(default_factory=lambda: _resolve_project_path(os.getenv("AILA_REPORT_DIR", "reports")))
    secret_keyring_path: Path = field(
        default_factory=lambda: _resolve_project_path(
            os.getenv("AILA_SECRET_KEYRING_PATH") or "data/secrets/keyring.json"
        )
    )
    secret_active_key_version: str = field(
        default_factory=lambda: os.getenv("AILA_SECRET_ACTIVE_KEY_VERSION", "v1")
    )
    request_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("AILA_TIMEOUT", "20"))
    )
    jwt_secret_key: str = field(
        default_factory=lambda: os.getenv("AILA_JWT_SECRET_KEY", secrets.token_hex(32))
    )
    api_host: str = field(default_factory=lambda: os.getenv("AILA_API_HOST", "127.0.0.1"))
    api_port: int = field(default_factory=lambda: int(os.getenv("AILA_API_PORT", "8000")))


# For test isolation: call _build_settings.cache_clear() then set AILA_DATABASE_URL before importing.
@functools.lru_cache(maxsize=1)
def _build_settings() -> Settings:
    return Settings()


def init_directories(settings: Settings | None = None) -> None:
    """Create the directories required by the platform before first use.

    Creates report_dir, the data/ directory, and the secret_keyring_path parent.
    This is intentionally separated from Settings construction (Phase 41 STD-09 fix:
    build_platform_settings() must NOT call mkdir — that caused side effects during
    config inspection and test setup).

    Call init_directories() once during platform startup (e.g. in the CLI entrypoint)
    before running any workflow.  Do not call it from Settings or get_settings().

    Args:
        settings: Optional Settings instance.  Falls back to get_settings().
    """
    active = settings or _build_settings()
    active.report_dir.mkdir(parents=True, exist_ok=True)
    _resolve_project_path("data").mkdir(parents=True, exist_ok=True)
    active.secret_keyring_path.parent.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    """Return the cached Settings singleton.

    Backed by _build_settings() which is an lru_cache(maxsize=1) function.
    The same Settings instance is returned on every call in a process.

    For test isolation: call _build_settings.cache_clear() then set the
    required AILA_* environment variables before calling get_settings() again.
    This pattern ensures each test starts with fresh Settings that read the
    current env vars (required because default_factory=lambda captures env vars
    at call time, not at import time).

    Returns:
        The cached Settings instance for the current process.
    """
    return _build_settings()
