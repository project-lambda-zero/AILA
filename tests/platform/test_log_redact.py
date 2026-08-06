"""Secret-redaction boundary tests for C6 (#42 / #50)."""
from __future__ import annotations

from aila.platform.services.log_redact import redact_command_line


def test_redacts_short_password_flag() -> None:
    out = redact_command_line("mysql -u root -p hunter2 -h db")
    assert "hunter2" not in out
    assert "[REDACTED]" in out
    assert out == "mysql -u root -p [REDACTED] -h db"


def test_redacts_inline_password_assignment() -> None:
    out = redact_command_line("psql password=hunter2 host=db")
    assert out == "psql password=[REDACTED] host=db"


def test_redacts_bearer_token() -> None:
    out = redact_command_line("curl -H 'authorization: bearer abc123def'")
    assert "abc123def" not in out
    assert "[REDACTED]" in out


def test_redacts_multiple_markers() -> None:
    out = redact_command_line("run password=p1 then token=t2 done")
    assert "p1" not in out
    assert "t2" not in out
    assert out.count("[REDACTED]") == 2


def test_value_at_end_of_line_is_redacted() -> None:
    assert redact_command_line("mysql -p secret") == "mysql -p [REDACTED]"


def test_no_secret_marker_unchanged() -> None:
    assert redact_command_line("ls -la /tmp/output") == "ls -la /tmp/output"


def test_empty_input_unchanged() -> None:
    assert redact_command_line("") == ""


def test_long_flag_forms() -> None:
    out = redact_command_line("tool --token deadbeef --api-key cafef00d")
    assert "deadbeef" not in out
    assert "cafef00d" not in out
    assert out.count("[REDACTED]") == 2
