"""Unit tests for aila.platform.llm.run_memory."""

from __future__ import annotations

import threading

import pytest

from aila.platform.llm.run_memory import RunMemory


class TestPutGet:
    """Basic put/get operations."""

    def test_put_and_get(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "host", "10.0.0.1")
        assert mem.get("run-1", "host") == "10.0.0.1"

    def test_get_default(self) -> None:
        mem = RunMemory()
        assert mem.get("run-1", "missing") is None
        assert mem.get("run-1", "missing", "fallback") == "fallback"

    def test_get_missing_run(self) -> None:
        mem = RunMemory()
        assert mem.get("nonexistent", "key") is None

    def test_overwrite(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "score", 5.0)
        mem.put("run-1", "score", 9.0)
        assert mem.get("run-1", "score") == 9.0

    def test_isolation_between_runs(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "host", "alpha")
        mem.put("run-2", "host", "beta")
        assert mem.get("run-1", "host") == "alpha"
        assert mem.get("run-2", "host") == "beta"


class TestAppend:
    """Append to list values."""

    def test_append_creates_list(self) -> None:
        mem = RunMemory()
        mem.append("run-1", "findings", "CVE-2024-0001")
        assert mem.get("run-1", "findings") == ["CVE-2024-0001"]

    def test_append_extends_list(self) -> None:
        mem = RunMemory()
        mem.append("run-1", "findings", "CVE-2024-0001")
        mem.append("run-1", "findings", "CVE-2024-0002")
        assert mem.get("run-1", "findings") == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_append_to_non_list_raises(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "score", 5.0)
        with pytest.raises(TypeError, match="non-list"):
            mem.append("run-1", "score", 6.0)


class TestKeys:
    """keys() method."""

    def test_keys_empty_run(self) -> None:
        mem = RunMemory()
        assert mem.keys("run-1") == []

    def test_keys_returns_all(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "a", 1)
        mem.put("run-1", "b", 2)
        assert sorted(mem.keys("run-1")) == ["a", "b"]


class TestClear:
    """clear() removes all entries for a run."""

    def test_clear_removes_run(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "host", "alpha")
        mem.clear("run-1")
        assert mem.get("run-1", "host") is None
        assert mem.keys("run-1") == []

    def test_clear_no_op_for_missing_run(self) -> None:
        mem = RunMemory()
        mem.clear("nonexistent")  # should not raise

    def test_clear_does_not_affect_other_runs(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "a", 1)
        mem.put("run-2", "b", 2)
        mem.clear("run-1")
        assert mem.get("run-2", "b") == 2


class TestActiveRuns:
    """active_runs() method."""

    def test_empty(self) -> None:
        mem = RunMemory()
        assert mem.active_runs() == []

    def test_returns_active(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "a", 1)
        mem.put("run-2", "b", 2)
        assert sorted(mem.active_runs()) == ["run-1", "run-2"]

    def test_cleared_run_not_active(self) -> None:
        mem = RunMemory()
        mem.put("run-1", "a", 1)
        mem.clear("run-1")
        assert mem.active_runs() == []


class TestThreadSafety:
    """Concurrent access does not corrupt state."""

    def test_concurrent_puts(self) -> None:
        mem = RunMemory()
        errors: list[Exception] = []

        def writer(run_id: str, count: int) -> None:
            try:
                for i in range(count):
                    mem.put(run_id, f"key-{i}", i)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=(f"run-{t}", 100))
            for t in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for t in range(5):
            assert len(mem.keys(f"run-{t}")) == 100
