"""Phase 91 deep review tests for cli.py and config.py.

Tests cover:
- serve command constructs correct uvicorn.run arguments
- create-api-key command creates key and prints output
- worker command constructs WorkerSettings and calls arq.run_worker
- config.py Settings has exactly 8 fields
- config.py jwt_secret_key random default behavior
- config.py __all__ exports
- cli.py __all__ exports

Contract updates
----------------
- Settings.database_url has no default anymore; its ``default_factory`` reads
  AILA_DATABASE_URL and raises ``ValueError('AILA_DATABASE_URL must be set')``
  when unset. The Settings-construction tests now pass an explicit
  ``database_url`` so they can exercise the other default_factory fields
  (jwt_secret_key, api_host, api_port) without depending on the ambient env.
- ``create-api-key`` used to call ``session.add(AuditEventRecord)`` directly.
  It now delegates to ``record_audit_event_sync`` which writes to the
  hash-chained platform journal. The two create-api-key tests patch that
  boundary at ``aila.cli.record_audit_event_sync`` -- otherwise the journal's
  ``bytes.fromhex(prev_hash)`` call blows up on the MagicMock session's
  MagicMock return values and the command exits nonzero.
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
    """Verify Settings has exactly 9 fields and each is documented."""

    def test_settings_has_exactly_9_fields(self):
        fields = dataclasses.fields(Settings)
        field_names = [f.name for f in fields]
        assert len(fields) == 9, f"Expected 9 fields, got {len(fields)}: {field_names}"

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
            "oidc_cookie_secure",
        }
        assert field_names == expected

    def test_jwt_secret_key_random_default(self):
        """jwt_secret_key defaults to a random 32-byte hex string when
        AILA_JWT_SECRET_KEY is unset.  Each Settings instance gets its own
        random value (via default_factory).

        ``database_url`` is passed explicitly because its default_factory
        requires AILA_DATABASE_URL to be set (SQLite is no longer supported).
        """
        from aila.config import _build_settings

        _build_settings.cache_clear()
        env = {
            k: v for k, v in os.environ.items()
            if not k.startswith("AILA_")
        }
        _dsn = "postgresql+asyncpg://x@localhost/test"
        with patch.dict(os.environ, env, clear=True):
            s1 = Settings(database_url=_dsn)
            s2 = Settings(database_url=_dsn)
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
            s = Settings(database_url="postgresql+asyncpg://x@localhost/test")
        assert s.jwt_secret_key == "my-fixed-secret"

    def test_api_host_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AILA_API_HOST", None)
            s = Settings(database_url="postgresql+asyncpg://x@localhost/test")
        assert s.api_host == "127.0.0.1"

    def test_api_port_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AILA_API_PORT", None)
            s = Settings(database_url="postgresql+asyncpg://x@localhost/test")
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
    @patch("aila.cli.record_audit_event_sync")
    @patch("aila.cli.session_scope")
    def test_create_api_key_outputs_key(self, mock_scope, _mock_audit):
        """create-api-key prints key info to stdout.

        ``record_audit_event_sync`` is patched to a no-op: the real journal
        write calls ``bytes.fromhex(prev_hash)`` on the mock session's
        MagicMock return value and would raise TypeError, exiting nonzero
        before any assertions run.
        """
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

        assert result.exit_code == 0, result.output
        assert "API key created:" in result.output
        assert "aila_ak_test" in result.output
        assert "admin" in result.output
        assert "test-label" in result.output
        assert "Store this key securely" in result.output

    @patch("aila.cli.record_audit_event_sync")
    @patch("aila.cli.session_scope")
    def test_create_api_key_persists_record(self, mock_scope, mock_audit):
        """create-api-key adds ApiKeyRecord to session, delegates audit to journal.

        Contract change: audit persistence moved from a direct
        ``session.add(AuditEventRecord)`` inside ``create_api_key`` to a
        delegated call to ``record_audit_event_sync`` (which internally uses
        the hash-chained platform journal). With that delegate patched out,
        ``session.add`` is invoked exactly once -- for the ApiKeyRecord.
        ``record_audit_event_sync`` still fires once so the audit trail
        surface stays covered here.
        """
        mock_session = MagicMock()
        mock_scope.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_scope.return_value.__exit__ = MagicMock(return_value=False)

        def fake_refresh(record):
            record.id = "persisted-id"

        mock_session.refresh.side_effect = fake_refresh

        with patch("aila.api.auth.generate_api_key", return_value="aila_ak_0123456789abcdef0123"):
            with patch("aila.api.auth.hash_api_key", return_value="hash"):
                runner.invoke(app, ["create-api-key"])

        # session.add called once: ApiKeyRecord only. Audit persistence is
        # delegated to record_audit_event_sync (mocked out above).
        assert mock_session.add.call_count == 1
        api_key_record = mock_session.add.call_args_list[0][0][0]
        assert api_key_record.role == "admin"
        assert api_key_record.created_by == "cli"
        # Audit still fires exactly once via the delegated boundary.
        assert mock_audit.call_count == 1
        assert mock_audit.call_args.kwargs.get("action") == "create_api_key"
        assert mock_audit.call_args.kwargs.get("stage") == "auth"
        # Two commits: one for record+refresh, one after audit event.
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

        with patch("arq.run_worker"):
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
