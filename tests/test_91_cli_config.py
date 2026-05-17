"""Phase 91 deep review tests for cli.py and config.py.

Tests cover:
- serve command constructs correct uvicorn.run arguments
- create-api-key command creates key and prints output
- worker command constructs WorkerSettings and calls arq.run_worker
- config.py Settings has exactly 8 fields
- config.py jwt_secret_key random default behavior
- config.py __all__ exports
- cli.py __all__ exports
"""
from __future__ import annotations

import dataclasses
import os
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from aila.cli import app
from aila.config import Settings
from aila.config import __all__ as config_all

runner = CliRunner()


# ---------------------------------------------------------------------------
# config.py: Settings field count and shape
# ---------------------------------------------------------------------------

class TestSettingsFields:
    """Verify Settings has exactly 8 fields and each is documented."""

    def test_settings_has_exactly_8_fields(self):
        fields = dataclasses.fields(Settings)
        field_names = [f.name for f in fields]
        assert len(fields) == 8, f"Expected 8 fields, got {len(fields)}: {field_names}"

    def test_settings_field_names(self):
        field_names = {f.name for f in dataclasses.fields(Settings)}
        expected = {
            "database_url",
            "report_dir",
            "secret_keyring_path",
            "secret_active_key_version",
            "request_timeout_seconds",
            "jwt_secret_key",
            "api_host",
            "api_port",
        }
        assert field_names == expected

    def test_jwt_secret_key_random_default(self):
        """jwt_secret_key defaults to a random 32-byte hex string when
        AILA_JWT_SECRET_KEY is unset.  Each Settings instance gets its own
        random value (via default_factory)."""
        from aila.config import _build_settings

        _build_settings.cache_clear()
        env = {
            k: v for k, v in os.environ.items()
            if not k.startswith("AILA_")
        }
        with patch.dict(os.environ, env, clear=True):
            s1 = Settings()
            s2 = Settings()
        # Both should be 64 hex characters (32 bytes)
        assert len(s1.jwt_secret_key) == 64
        assert len(s2.jwt_secret_key) == 64
        # Should differ (random) -- extremely unlikely to collide
        assert s1.jwt_secret_key != s2.jwt_secret_key

    def test_jwt_secret_key_from_env(self):
        """AILA_JWT_SECRET_KEY env var overrides the random default."""
        from aila.config import _build_settings

        _build_settings.cache_clear()
        with patch.dict(os.environ, {"AILA_JWT_SECRET_KEY": "my-fixed-secret"}):
            s = Settings()
        assert s.jwt_secret_key == "my-fixed-secret"

    def test_api_host_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AILA_API_HOST", None)
            s = Settings()
        assert s.api_host == "127.0.0.1"

    def test_api_port_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AILA_API_PORT", None)
            s = Settings()
        assert s.api_port == 8000


class TestConfigExports:
    """Verify config.py __all__ exports."""

    def test_config_all_contains_public_names(self):
        assert "Settings" in config_all
        assert "get_settings" in config_all
        assert "init_directories" in config_all
        assert "PROJECT_ROOT" in config_all

    def test_config_all_does_not_export_private(self):
        for name in config_all:
            assert not name.startswith("_"), f"{name} is private but exported"


# ---------------------------------------------------------------------------
# cli.py: __all__ exports
# ---------------------------------------------------------------------------

class TestCliExports:
    def test_cli_all_contains_app_and_main(self):
        from aila.cli import __all__ as cli_all
        assert "app" in cli_all
        assert "main" in cli_all


# ---------------------------------------------------------------------------
# cli.py: serve command
# ---------------------------------------------------------------------------

class TestServeCommand:
    @patch("aila.cli.get_settings")
    def test_serve_calls_uvicorn_run(self, mock_settings):
        """serve command calls uvicorn.run with correct arguments."""
        mock_settings.return_value = MagicMock(api_host="127.0.0.1", api_port=8000)

        with patch("uvicorn.run") as mock_uvicorn:
            result = runner.invoke(app, ["serve"])

        assert result.exit_code == 0
        mock_uvicorn.assert_called_once_with(
            "aila.api.app:app",
            host="127.0.0.1",
            port=8000,
            reload=False,
            workers=1,
        )

    @patch("aila.cli.get_settings")
    def test_serve_host_port_override(self, mock_settings):
        """--host and --port flags override Settings defaults."""
        mock_settings.return_value = MagicMock(api_host="127.0.0.1", api_port=8000)

        with patch("uvicorn.run") as mock_uvicorn:
            result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9090"])

        assert result.exit_code == 0
        mock_uvicorn.assert_called_once_with(
            "aila.api.app:app",
            host="0.0.0.0",
            port=9090,
            reload=False,
            workers=1,
        )

    @patch("aila.cli.get_settings")
    def test_serve_reload_flag(self, mock_settings):
        """--reload flag is passed through to uvicorn."""
        mock_settings.return_value = MagicMock(api_host="127.0.0.1", api_port=8000)

        with patch("uvicorn.run") as mock_uvicorn:
            result = runner.invoke(app, ["serve", "--reload"])

        assert result.exit_code == 0
        mock_uvicorn.assert_called_once_with(
            "aila.api.app:app",
            host="127.0.0.1",
            port=8000,
            reload=True,
            workers=1,
        )


# ---------------------------------------------------------------------------
# cli.py: create-api-key command
# ---------------------------------------------------------------------------

class TestCreateApiKeyCommand:
    @patch("aila.cli.session_scope")
    def test_create_api_key_outputs_key(self, mock_scope):
        """create-api-key prints key info to stdout."""
        mock_session = MagicMock()
        mock_scope.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_scope.return_value.__exit__ = MagicMock(return_value=False)

        # Mock the record to have an id after refresh
        def fake_refresh(record):
            record.id = "test-key-id-123"

        mock_session.refresh.side_effect = fake_refresh

        with patch("aila.api.auth.generate_api_key", return_value="aila_ak_test1234567890abcdef"):
            with patch("aila.api.auth.hash_api_key", return_value="hashed_value"):
                result = runner.invoke(app, ["create-api-key", "--label", "test-label"])

        assert result.exit_code == 0
        assert "API key created:" in result.output
        assert "aila_ak_test" in result.output
        assert "admin" in result.output
        assert "test-label" in result.output
        assert "Store this key securely" in result.output

    @patch("aila.cli.session_scope")
    def test_create_api_key_persists_record(self, mock_scope):
        """create-api-key adds ApiKeyRecord to session and commits."""
        mock_session = MagicMock()
        mock_scope.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_scope.return_value.__exit__ = MagicMock(return_value=False)

        def fake_refresh(record):
            record.id = "persisted-id"

        mock_session.refresh.side_effect = fake_refresh

        with patch("aila.api.auth.generate_api_key", return_value="aila_ak_0123456789abcdef0123"):
            with patch("aila.api.auth.hash_api_key", return_value="hash"):
                runner.invoke(app, ["create-api-key"])

        # session.add called twice: ApiKeyRecord + AuditEventRecord
        assert mock_session.add.call_count == 2
        api_key_record = mock_session.add.call_args_list[0][0][0]
        assert api_key_record.role == "admin"
        assert api_key_record.created_by == "cli"
        # Two commits: one for record+refresh, one after audit event
        assert mock_session.commit.call_count == 2


# ---------------------------------------------------------------------------
# cli.py: worker command
# ---------------------------------------------------------------------------

class TestWorkerCommand:
    @patch("aila.cli.get_settings")
    def test_worker_calls_arq_run_worker(self, mock_settings):
        """worker command creates a WorkerSettings subclass and runs arq.run_worker."""
        mock_settings.return_value = MagicMock()

        with patch("arq.run_worker") as mock_run:
            with patch("aila.platform.tasks.get_task_tuning", side_effect=lambda k, d: d):
                result = runner.invoke(app, ["worker", "--queue", "test_queue"])

        assert result.exit_code == 0
        assert "Starting ARQ worker" in result.output
        assert "test_queue" in result.output
        mock_run.assert_called_once()
        # The argument should be a class (WorkerSettings subclass)
        settings_cls = mock_run.call_args[0][0]
        assert settings_cls.queue_name == "arq:queue:test_queue"

    @patch("aila.cli.get_settings")
    def test_worker_default_queue(self, mock_settings):
        """worker command defaults to queue='default'."""
        mock_settings.return_value = MagicMock()

        with patch("arq.run_worker") as mock_run:
            with patch("aila.platform.tasks.get_task_tuning", side_effect=lambda k, d: d):
                result = runner.invoke(app, ["worker"])

        assert result.exit_code == 0
        assert "default" in result.output
        settings_cls = mock_run.call_args[0][0]
        assert settings_cls.queue_name == "arq:queue:default"

    @patch("aila.cli.get_settings")
    def test_worker_custom_redis_url(self, mock_settings):
        """worker command parses custom --redis-url for host and port."""
        mock_settings.return_value = MagicMock()

        with patch("arq.run_worker") as mock_run:
            with patch("aila.platform.tasks.get_task_tuning", side_effect=lambda k, d: d):
                result = runner.invoke(app, ["worker", "--redis-url", "redis://10.0.0.1:6380"])

        assert result.exit_code == 0
        assert "10.0.0.1:6380" in result.output


# ---------------------------------------------------------------------------
# cli.py: lazy import audit
# ---------------------------------------------------------------------------

class TestLazyImportJustification:
    """Verify that lazy imports in cli.py are justified and no redundant
    lazy imports remain in create-api-key."""

    def test_create_api_key_no_redundant_session_scope_import(self):
        """create-api-key should use the top-level session_scope import,
        not re-import it lazily inside the function."""
        import ast
        import inspect

        from aila.cli import create_api_key

        source = inspect.getsource(create_api_key)
        tree = ast.parse(source)

        lazy_imports = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and node.module:
                    names = [alias.name for alias in node.names]
                    lazy_imports.append((node.module, names))

        # session_scope should NOT appear as a lazy import
        for module, names in lazy_imports:
            assert "session_scope" not in names, (
                f"session_scope lazily imported from {module} -- "
                "already at module top level"
            )
        # record_audit_event should NOT appear as a lazy import
        for module, names in lazy_imports:
            assert "record_audit_event" not in names, (
                f"record_audit_event lazily imported from {module} -- "
                "already at module top level"
            )

    def test_serve_lazy_uvicorn_justified(self):
        """serve lazily imports uvicorn -- justified because uvicorn
        is not needed for CLI-only commands."""
        import ast
        import inspect

        from aila.cli import serve

        source = inspect.getsource(serve)
        tree = ast.parse(source)

        has_uvicorn = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "uvicorn":
                        has_uvicorn = True
        assert has_uvicorn, "serve should lazily import uvicorn"

    def test_worker_lazy_arq_justified(self):
        """worker lazily imports arq -- justified because arq
        is not needed for non-worker CLI commands."""
        import ast
        import inspect

        from aila.cli import worker_start

        source = inspect.getsource(worker_start)
        tree = ast.parse(source)

        has_arq = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "arq":
                        has_arq = True
        assert has_arq, "worker_start should lazily import arq"
