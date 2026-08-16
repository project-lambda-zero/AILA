"""Issue #183 -- ``_read_reproducer_head`` MUST confine reads to the
operator-configured local staging root and refuse traversal / escape.

The historical open followed any absolute path the API caller supplied,
so an authenticated caller who could POST ``/vr/fuzz/crashes`` could
read up to 4 KiB of any file the backend process was allowed to read
and receive it hex-encoded in the crash summary. The fix:

  1. Adds an operator-tunable ``fuzz_reproducer_local_root`` config.
  2. Fail-closes with ``(None, None)`` when the root is unset.
  3. When set, resolves ``reproducer_path`` via ``Path.resolve()`` so
     symlink escapes are followed BEFORE the containment check and
     refuses anything not under the resolved allowed root.

These tests assert the traversal + escape paths are refused without
requiring the real ConfigRegistry (they monkeypatch the root resolver
directly, keeping the test DB-light per the workstream rules).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aila.modules.vr.services import fuzz_service


def _patch_root(monkeypatch, allowed_root: Path | None) -> None:
    """Force :func:`fuzz_service._resolve_reproducer_allowed_root` to return
    ``allowed_root`` so the tests do not need a live ConfigRegistry / DB."""
    monkeypatch.setattr(
        fuzz_service,
        "_resolve_reproducer_allowed_root",
        lambda: allowed_root,
    )


def test_read_reproducer_head_disabled_when_no_root_configured(tmp_path, monkeypatch):
    """Fail-closed when ``fuzz_reproducer_local_root`` is unset -- the
    hex preview simply goes empty; the crash still records upstream."""
    _patch_root(monkeypatch, None)
    stage = tmp_path / "not_used"
    stage.write_bytes(b"AAAA")
    hex_str, size = fuzz_service._read_reproducer_head(str(stage))
    assert hex_str is None and size is None


def test_read_reproducer_head_accepts_path_inside_root(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    _patch_root(monkeypatch, stage.resolve())
    repro = stage / "crash.bin"
    repro.write_bytes(b"CRASH_INPUT_BYTES")
    hex_str, size = fuzz_service._read_reproducer_head(str(repro))
    assert hex_str == b"CRASH_INPUT_BYTES".hex()
    assert size == len(b"CRASH_INPUT_BYTES")


def test_read_reproducer_head_refuses_dotdot_traversal(tmp_path, monkeypatch, caplog):
    """Even when the lexical prefix looks like it lives inside the root,
    a ``..`` segment MUST be refused pre-resolution -- a permissive
    resolver could otherwise normalize ``stage/../etc/passwd`` to
    ``etc/passwd`` and slip past.
    """
    stage = tmp_path / "stage"
    stage.mkdir()
    _patch_root(monkeypatch, stage.resolve())
    # Attacker-crafted traversal starting from inside the allowed root.
    escape = f"{stage}/../outside/etc_shadow"
    hex_str, size = fuzz_service._read_reproducer_head(escape)
    assert hex_str is None and size is None


def test_read_reproducer_head_refuses_path_outside_root(tmp_path, monkeypatch):
    """A resolvable absolute path that lands outside the allowed root
    (typical exfiltration case: ``/etc/passwd`` when the AILA process
    can read it) MUST be refused without opening the file.
    """
    stage = tmp_path / "stage"
    stage.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "secret.env"
    victim.write_bytes(b"SUPABASE_KEY=hunter2\n")
    _patch_root(monkeypatch, stage.resolve())
    hex_str, size = fuzz_service._read_reproducer_head(str(victim))
    assert hex_str is None and size is None


def test_read_reproducer_head_follows_symlink_escape_and_refuses(tmp_path, monkeypatch):
    """A symlink that lives inside the allowed root but points at a file
    outside MUST be refused. ``Path.resolve()`` follows the link so the
    real-path containment check catches the escape.
    """
    stage = tmp_path / "stage"
    stage.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "secret.env"
    victim.write_bytes(b"AWS_SECRET=xyz\n")
    link = stage / "innocent.bin"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        # Windows without SeCreateSymbolicLink -- resolve() still refuses
        # a missing target below, but this specific escape shape cannot
        # be exercised. Skip rather than false-negative.
        pytest.skip("symlink creation not permitted on this host")
    _patch_root(monkeypatch, stage.resolve())
    hex_str, size = fuzz_service._read_reproducer_head(str(link))
    assert hex_str is None and size is None


def test_read_reproducer_head_refuses_relative_path(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    _patch_root(monkeypatch, stage.resolve())
    hex_str, size = fuzz_service._read_reproducer_head("crash.bin")
    assert hex_str is None and size is None


def test_read_reproducer_head_refuses_missing_path(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    _patch_root(monkeypatch, stage.resolve())
    missing = stage / "does_not_exist.bin"
    hex_str, size = fuzz_service._read_reproducer_head(str(missing))
    assert hex_str is None and size is None


def test_read_reproducer_head_refuses_none_and_non_string(tmp_path, monkeypatch):
    _patch_root(monkeypatch, tmp_path.resolve())
    assert fuzz_service._read_reproducer_head(None) == (None, None)
    assert fuzz_service._read_reproducer_head("") == (None, None)
    assert fuzz_service._read_reproducer_head(b"/tmp/x") == (None, None)  # type: ignore[arg-type]
