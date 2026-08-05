"""Tests for the read_lines basename auto-resolve + JADX-hint gating
added to :mod:`aila.platform.mcp.bridges.audit_mcp`.

Covers the three module-level helpers (``_search_by_basename``,
``_looks_like_jadx``, ``_WALK_SKIP_DIRS``) and the wired path through
``AuditMcpBridgeTool._read_lines_local``. The bridge instance is
constructed with an explicit ``base_url`` so no live audit-mcp is
required and ``_INDEX_ROOTS`` is populated directly so
``_refresh_index_roots`` is never called.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aila.platform.mcp.bridges import audit_mcp as bridge_mod
from aila.platform.mcp.bridges.audit_mcp import (
    _JADX_PREFIX_RE,
    _WALK_SKIP_DIRS,
    AuditMcpBridgeTool,
    _looks_like_jadx,
    _search_by_basename,
)

# ---------------------------------------------------------------------------
# _search_by_basename
# ---------------------------------------------------------------------------


class TestSearchByBasename:
    def test_returns_empty_for_empty_leaf(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        assert _search_by_basename(tmp_path, "") == []

    def test_single_match_returns_relpath_posix(self, tmp_path: Path) -> None:
        nested = tmp_path / "llm_sandbox"
        nested.mkdir()
        (nested / "interactive.py").write_text("x", encoding="utf-8")
        hits = _search_by_basename(tmp_path, "interactive.py")
        assert hits == ["llm_sandbox/interactive.py"]

    def test_multiple_matches_returned(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "dup.py").write_text("x", encoding="utf-8")
        (tmp_path / "b" / "dup.py").write_text("x", encoding="utf-8")
        hits = _search_by_basename(tmp_path, "dup.py")
        assert sorted(hits) == ["a/dup.py", "b/dup.py"]

    def test_no_match_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        assert _search_by_basename(tmp_path, "nope.py") == []

    def test_prunes_walk_skip_dirs(self, tmp_path: Path) -> None:
        # A basename hidden under every pruned dir stays invisible.
        for pruned in _WALK_SKIP_DIRS:
            d = tmp_path / pruned
            d.mkdir()
            (d / "target.py").write_text("x", encoding="utf-8")
        # And a real hit sits at the root.
        (tmp_path / "target.py").write_text("x", encoding="utf-8")
        hits = _search_by_basename(tmp_path, "target.py")
        assert hits == ["target.py"]

    def test_cap_enforced(self, tmp_path: Path) -> None:
        # 20 matches, cap=3.
        for i in range(20):
            d = tmp_path / f"pkg{i}"
            d.mkdir()
            (d / "leaf.py").write_text("x", encoding="utf-8")
        hits = _search_by_basename(tmp_path, "leaf.py", cap=3)
        assert len(hits) == 3

    def test_max_scan_bounds_walk(self, tmp_path: Path) -> None:
        # 10 non-matching files, max_scan=5 -- never finds anything but
        # returns without exhausting the tree.
        for i in range(10):
            (tmp_path / f"other{i}.txt").write_text("x", encoding="utf-8")
        hits = _search_by_basename(
            tmp_path, "leaf.py", cap=12, max_scan=5,
        )
        assert hits == []

    def test_oserror_returns_collected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (tmp_path / "a.py").write_text("x", encoding="utf-8")

        def _boom(_root: str) -> object:
            raise OSError("mocked walk failure")

        monkeypatch.setattr(bridge_mod.os, "walk", _boom)
        # No results collected before the raise -- returns [].
        assert _search_by_basename(tmp_path, "a.py") == []


# ---------------------------------------------------------------------------
# _looks_like_jadx
# ---------------------------------------------------------------------------


class TestLooksLikeJadx:
    def test_false_on_plain_python_tree(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x", encoding="utf-8")
        assert _looks_like_jadx(tmp_path) is False

    def test_true_when_resources_child(self, tmp_path: Path) -> None:
        (tmp_path / "resources").mkdir()
        (tmp_path / "sources").mkdir()  # equally valid
        assert _looks_like_jadx(tmp_path) is True

    def test_true_when_sources_only(self, tmp_path: Path) -> None:
        (tmp_path / "sources").mkdir()
        assert _looks_like_jadx(tmp_path) is True

    def test_true_when_p_prefixed_child(self, tmp_path: Path) -> None:
        (tmp_path / "p182ui").mkdir()
        assert _looks_like_jadx(tmp_path) is True
        assert _JADX_PREFIX_RE.match("p182ui") is not None

    def test_true_when_p_prefixed_one_level_down(self, tmp_path: Path) -> None:
        pkg = tmp_path / "com" / "example"
        pkg.mkdir(parents=True)
        (pkg / "p23do").mkdir()
        # ``com`` alone is not a signal; but scanning one level down
        # into ``com`` finds nothing p-prefixed. Scan should also try
        # ``com/example`` where p23do lives -- one level down from root
        # is ``com``, whose children include ``example``. Our helper
        # only looks one level down, so put a p-prefix at
        # tmp_path/<child>/<grandchild>.
        assert _looks_like_jadx(tmp_path) is False
        # Put the p-prefix directly one level down:
        (tmp_path / "com" / "p9C2D").mkdir()
        assert _looks_like_jadx(tmp_path) is True

    def test_true_when_resources_one_level_down(self, tmp_path: Path) -> None:
        workdir = tmp_path / "apk-unified-sha"
        workdir.mkdir()
        (workdir / "resources").mkdir()
        assert _looks_like_jadx(tmp_path) is True

    def test_false_on_missing_root(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        # iterdir raises OSError -- helper swallows and returns False.
        assert _looks_like_jadx(missing) is False

    def test_ignores_non_directory_children(self, tmp_path: Path) -> None:
        # A file named ``resources`` at the root is not a signal.
        (tmp_path / "resources").write_text("x", encoding="utf-8")
        (tmp_path / "sources").write_text("x", encoding="utf-8")
        assert _looks_like_jadx(tmp_path) is False


# ---------------------------------------------------------------------------
# _read_lines_local wiring
# ---------------------------------------------------------------------------


def _make_bridge(root: Path, index_id: str = "idx1") -> AuditMcpBridgeTool:
    """Construct a bridge with a fixed base_url and a pre-populated
    ``_INDEX_ROOTS`` so ``_refresh_index_roots`` never fires.

    ``_INDEX_ROOTS`` is class-level; each test overrides it wholesale
    so the previous test can't leak an index_id / root pair.
    """
    tool = AuditMcpBridgeTool(base_url="http://127.0.0.1:1", module_id="vr")
    AuditMcpBridgeTool._INDEX_ROOTS = {index_id: str(root)}
    return tool


class TestReadLinesResolution:
    async def test_correct_path_reads_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "a.py").write_text(
            "L1\nL2\nL3\n", encoding="utf-8",
        )
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "pkg/a.py",
            "start": 1,
            "end": 3,
        })
        assert result["status"] == "ready"
        assert result["file_path"] == "pkg/a.py"
        assert result["content"] == "L1\nL2\nL3\n"
        assert result["total_lines_in_file"] == 3

    async def test_unique_basename_auto_resolves(self, tmp_path: Path) -> None:
        # Real file at llm_sandbox/interactive.py; agent guesses
        # src/llm_sandbox/interactive.py.
        (tmp_path / "llm_sandbox").mkdir()
        (tmp_path / "llm_sandbox" / "interactive.py").write_text(
            "one\ntwo\nthree\n", encoding="utf-8",
        )
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "src/llm_sandbox/interactive.py",
            "start": 1,
            "end": 3,
        })
        assert result["status"] == "ready"
        assert result["file_path"] == "llm_sandbox/interactive.py"
        assert result["content"] == "one\ntwo\nthree\n"

    async def test_bare_leaf_auto_resolves(self, tmp_path: Path) -> None:
        (tmp_path / "deep" / "nested").mkdir(parents=True)
        (tmp_path / "deep" / "nested" / "unique.py").write_text(
            "hi\n", encoding="utf-8",
        )
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "unique.py",  # no dir prefix at all
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "ready"
        assert result["file_path"] == "deep/nested/unique.py"
        assert result["content"] == "hi\n"

    async def test_duplicate_basename_returns_error_with_both(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "dup.py").write_text("x", encoding="utf-8")
        (tmp_path / "b" / "dup.py").write_text("x", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "elsewhere/dup.py",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "a/dup.py" in err
        assert "b/dup.py" in err
        assert "NEAREST INDEXED PATHS" in err

    async def test_non_jadx_tree_omits_jadx_sentence(
        self, tmp_path: Path,
    ) -> None:
        # Plain python tree, non-unique basename so error path fires.
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        (tmp_path / "x" / "z.py").write_text("x", encoding="utf-8")
        (tmp_path / "y" / "z.py").write_text("x", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "nope/z.py",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "JADX" not in err
        assert "USE IT VERBATIM" in err

    async def test_jadx_tree_includes_jadx_sentence(
        self, tmp_path: Path,
    ) -> None:
        # Root has a ``resources/`` sibling -- flips _looks_like_jadx.
        (tmp_path / "resources").mkdir()
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        (tmp_path / "x" / "z.java").write_text("x", encoding="utf-8")
        (tmp_path / "y" / "z.java").write_text("x", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "nope/z.java",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "JADX" in err
        assert "p182ui" in err
        assert "USE IT VERBATIM" in err

    async def test_p_prefixed_tree_flips_jadx_sentence(
        self, tmp_path: Path,
    ) -> None:
        # No ``resources/``, but a p-prefixed package dir at the root.
        (tmp_path / "p182ui").mkdir()
        (tmp_path / "x").mkdir()
        (tmp_path / "y").mkdir()
        (tmp_path / "x" / "Same.java").write_text("x", encoding="utf-8")
        (tmp_path / "y" / "Same.java").write_text("x", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "com/example/Same.java",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        assert "JADX" in result["error"]

    async def test_no_hit_error_has_semantic_search_guidance(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "keepempty").mkdir()
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "nowhere/absent.py",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "No similar path exists in the index" in err
        assert "semantic_search" in err
        assert "JADX" not in err

    async def test_success_path_start_exceeds_total_still_errors(
        self, tmp_path: Path,
    ) -> None:
        # Auto-resolve resolves the file, then start>total triggers
        # the untouched read-side branch.
        (tmp_path / "deep").mkdir()
        (tmp_path / "deep" / "small.py").write_text("only\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "wrongdir/small.py",
            "start": 5,
            "end": 6,
        })
        assert result["status"] == "error"
        assert "exceeds file length" in result["error"]


# ---------------------------------------------------------------------------
# Structured signature errors -- feed the tool_execution classifier so the
# repeat-failure circuit breaker fires on identical malformed calls.
# ---------------------------------------------------------------------------


class TestReadLinesSignatureErrors:
    async def test_missing_index_id_flags_missing_required_kwarg(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "file_path": "a.py",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "missing required kwarg" in err
        assert "'index_id'" in err
        assert "audit_mcp.read_lines rejected" in err
        assert "Valid params" in err

    async def test_missing_file_path_flags_missing_required_kwarg(
        self, tmp_path: Path,
    ) -> None:
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "missing required kwarg" in err
        assert "'file_path'" in err

    async def test_missing_both_lists_both_kwargs(
        self, tmp_path: Path,
    ) -> None:
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "start": 1,
            "end": 1,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "missing required kwarg" in err
        # sorted list -> file_path before index_id.
        assert "['file_path', 'index_id']" in err

    async def test_non_integer_start_flags_must_be_integers(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "a.py",
            "start": "one",
            "end": 3,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "must be integers" in err
        assert "audit_mcp.read_lines rejected" in err
        assert "Required:" in err

    async def test_non_integer_end_flags_must_be_integers(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "a.py",
            "start": 1,
            "end": [3],
        })
        assert result["status"] == "error"
        assert "must be integers" in result["error"]

    async def test_zero_start_flags_invalid_range_and_1_indexed(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "a.py",
            "start": 0,
            "end": 5,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "invalid range" in err
        assert "must be 1-indexed" in err
        assert "start=0" in err
        assert "end=5" in err

    async def test_end_below_start_flags_invalid_range(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "a.py",
            "start": 10,
            "end": 5,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "invalid range" in err
        assert "must be 1-indexed" in err

    async def test_start_past_eof_flags_exceeds_file_length(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "tiny.py").write_text("only\n", encoding="utf-8")
        tool = _make_bridge(tmp_path)
        result = await tool._read_lines_local({
            "index_id": "idx1",
            "file_path": "tiny.py",
            "start": 500,
            "end": 501,
        })
        assert result["status"] == "error"
        err = result["error"]
        assert "exceeds file length" in err
        assert "start=500" in err
        assert "audit_mcp.read_lines rejected" in err
        assert "Valid params" in err
        assert "Required:" in err
