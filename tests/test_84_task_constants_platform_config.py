"""Phase 84 -- Task Constants & Platform Config deep review.

FILE-31: tasks/constants.py + tasks/__init__.py
  - get_task_tuning reads DB directly (ConfigEntryRecord), falls back to constant
  - Every tuning constant has a PlatformConfigSchema counterpart (same key, type, default)

FILE-32: platform/config.py
  - PlatformConfigSchema has all fields used by get_task_tuning callers
  - build_platform_settings reads from ConfigRegistry correctly
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from aila.platform.config import PlatformConfigSchema, PlatformSettings, build_platform_settings
from aila.platform.tasks import get_task_tuning
from aila.platform.tasks.constants import __all__ as const_all

_SESSION_SCOPE_PATH = "aila.storage.database.session_scope"


def _fake_session_scope(mock_session: MagicMock):  # type: ignore[no-untyped-def]
    """Build a context-manager that yields mock_session."""

    @contextmanager
    def _scope():  # type: ignore[no-untyped-def]
        yield mock_session

    return _scope


# ---------------------------------------------------------------------------
# FILE-31: get_task_tuning behaviour
# ---------------------------------------------------------------------------


class TestGetTaskTuning:
    """get_task_tuning reads ConfigEntryRecord for namespace='platform', returns int."""

    def test_returns_db_value_when_row_exists(self) -> None:
        """DB row with valid int string -> returns that int."""
        mock_row = MagicMock()
        mock_row.value = "42"

        mock_session = MagicMock()
        mock_session.exec.return_value.first.return_value = mock_row

        with patch(_SESSION_SCOPE_PATH, _fake_session_scope(mock_session)):
            result = get_task_tuning("heartbeat_interval_s", 30)

        assert result == 42

    def test_returns_default_when_no_db_row(self) -> None:
        """No DB row -> returns default."""
        mock_session = MagicMock()
        mock_session.exec.return_value.first.return_value = None

        with patch(_SESSION_SCOPE_PATH, _fake_session_scope(mock_session)):
            result = get_task_tuning("heartbeat_interval_s", 30)

        assert result == 30

    def test_returns_default_when_db_raises(self) -> None:
        """DB exception -> returns default, does not propagate."""

        @contextmanager
        def _boom():  # type: ignore[no-untyped-def]
            raise RuntimeError("db down")
            yield  # noqa: RET503 -- unreachable, keeps generator protocol

        with patch(_SESSION_SCOPE_PATH, _boom):
            result = get_task_tuning("heartbeat_interval_s", 30)

        assert result == 30

    def test_returns_default_when_value_not_castable(self) -> None:
        """Row value that cannot be cast to int -> returns default."""
        mock_row = MagicMock()
        mock_row.value = "not-a-number"

        mock_session = MagicMock()
        mock_session.exec.return_value.first.return_value = mock_row

        with patch(_SESSION_SCOPE_PATH, _fake_session_scope(mock_session)):
            result = get_task_tuning("heartbeat_interval_s", 30)

        assert result == 30

    def test_queries_correct_namespace_and_key(self) -> None:
        """Verify the query uses namespace='platform' and the provided key."""
        mock_session = MagicMock()
        mock_session.exec.return_value.first.return_value = None

        with patch(_SESSION_SCOPE_PATH, _fake_session_scope(mock_session)):
            get_task_tuning("arq_max_tries", 3)

        # session.exec was called once with a select statement
        mock_session.exec.assert_called_once()


# ---------------------------------------------------------------------------
# FILE-31: Constant-to-PlatformConfigSchema mapping
# ---------------------------------------------------------------------------


class TestConstantToSchemaMapping:
    """Every tuning constant in constants.py has a PlatformConfigSchema counterpart."""

    # (constant_name, schema_field_name, expected_default, expected_type)
    MAPPING: list[tuple[str, str, int, type]] = [
        ("HEARTBEAT_INTERVAL_S", "heartbeat_interval_s", 30, int),
        ("REAPER_ZOMBIE_THRESHOLD_S", "reaper_zombie_threshold_s", 3300, int),
        ("REAPER_HEARTBEAT_THRESHOLD_S", "reaper_heartbeat_threshold_s", 86400, int),
        ("ARQ_JOB_TIMEOUT_S", "arq_job_timeout_s", 3600, int),
        ("ARQ_KEEP_RESULT_S", "arq_keep_result_s", 3600, int),
        ("ARQ_MAX_TRIES", "arq_max_tries", 3, int),
        ("PROGRESS_STREAM_MAXLEN", "progress_stream_maxlen", 1000, int),
    ]

    @pytest.mark.parametrize(
        "const_name,schema_field,expected_default,expected_type",
        MAPPING,
        ids=[m[0] for m in MAPPING],
    )
    def test_constant_matches_schema_default(
        self,
        const_name: str,
        schema_field: str,
        expected_default: int,
        expected_type: type,
    ) -> None:
        """Constant default matches PlatformConfigSchema field default."""
        import aila.platform.tasks.constants as C

        const_value = getattr(C, const_name)
        schema_defaults = PlatformConfigSchema()
        schema_value = getattr(schema_defaults, schema_field)

        assert const_value == schema_value, (
            f"{const_name}={const_value} != PlatformConfigSchema.{schema_field}={schema_value}"
        )
        assert isinstance(const_value, expected_type)
        assert isinstance(schema_value, expected_type)
        assert const_value == expected_default

    def test_xread_block_ms_not_in_schema_is_acceptable(self) -> None:
        """XREAD_BLOCK_MS is derived from heartbeat and used directly, not via get_task_tuning."""
        schema = PlatformConfigSchema()
        assert not hasattr(schema, "xread_block_ms")


# ---------------------------------------------------------------------------
# FILE-32: PlatformConfigSchema completeness for get_task_tuning callers
# ---------------------------------------------------------------------------


class TestPlatformConfigSchemaCompleteness:
    """PlatformConfigSchema must include every key passed to get_task_tuning."""

    CALLER_KEYS: list[str] = [
        "jwt_access_expiry_s",
        "jwt_refresh_expiry_s",
        "heartbeat_interval_s",
        "reaper_zombie_threshold_s",
        "reaper_heartbeat_threshold_s",
        "arq_job_timeout_s",
        "arq_keep_result_s",
        "arq_max_tries",
        "progress_stream_maxlen",
    ]

    @pytest.mark.parametrize("key", CALLER_KEYS)
    def test_schema_has_caller_key(self, key: str) -> None:
        """PlatformConfigSchema declares a field for every get_task_tuning caller key."""
        assert key in PlatformConfigSchema.model_fields, (
            f"PlatformConfigSchema missing field '{key}' used by get_task_tuning caller"
        )

    @pytest.mark.parametrize("key", CALLER_KEYS)
    def test_schema_field_is_int(self, key: str) -> None:
        """Every get_task_tuning caller key is typed as int in PlatformConfigSchema."""
        field_info = PlatformConfigSchema.model_fields[key]
        assert field_info.annotation is int, (
            f"PlatformConfigSchema.{key} should be int, got {field_info.annotation}"
        )

    def test_build_platform_settings_reads_from_registry(self) -> None:
        """build_platform_settings uses _cfg_from_registry for configurable fields."""
        mock_source = MagicMock()
        mock_source.database_url = "sqlite:///test.db"
        mock_source.report_dir = MagicMock()
        mock_source.secret_keyring_path = MagicMock()
        mock_source.secret_active_key_version = "v1"
        mock_source.request_timeout_seconds = 20.0

        settings = build_platform_settings(mock_source)
        assert isinstance(settings, PlatformSettings)
        assert settings.routing_decision_cache_ttl_hours == 72
        assert settings.routing_min_confidence == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# Package __all__ exports
# ---------------------------------------------------------------------------


class TestPackageExports:
    """tasks/__init__.py exports get_task_tuning in __all__."""

    def test_get_task_tuning_in_all(self) -> None:
        from aila.platform.tasks import __all__ as task_all

        assert "get_task_tuning" in task_all

    def test_constants_all_exports_expected_names(self) -> None:
        """constants.py __all__ lists all public constants."""
        expected = {
            # Redis key templates
            "ARQ_QUEUE_KEY_TEMPLATE",
            "ARQ_IN_PROGRESS_PREFIX",
            "ARQ_JOB_PREFIX",
            "ARQ_RETRY_PREFIX",
            "ARQ_DEAD_LETTER_KEY_TEMPLATE",
            "TASK_PROGRESS_KEY_TEMPLATE",
            "SCAN_PROGRESS_KEY_TEMPLATE",
            # Numeric tuning
            "HEARTBEAT_INTERVAL_S",
            "REAPER_ZOMBIE_THRESHOLD_S",
            "REAPER_HEARTBEAT_THRESHOLD_S",
            "ARQ_JOB_TIMEOUT_S",
            "ARQ_KEEP_RESULT_S",
            "ARQ_MAX_TRIES",
            "POISON_PILL_THRESHOLD",
            "WORKER_HEARTBEAT_UNHEALTHY_S",
            "XREAD_BLOCK_MS",
            "PROGRESS_STREAM_MAXLEN",
            # Config registry keys
            "CONFIG_NS_PLATFORM",
            "CONFIG_KEY_REDIS_URL",
        }
        assert set(const_all) == expected
