"""Unit tests for the aila_fuzz_reporter sidecar scrapers.

Covers the three engine readers with synthetic stats files +
synthetic crash directories. Each scraper is a stateless reader,
so the tests just craft input on disk via tmp_path and assert
the Sample / CrashRecord fields.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# The sidecar lives under tools/, not src/. Add it to sys.path so
# tests can import it without a package install.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "tools"))

from aila_fuzz_reporter.scrapers import (  # noqa: E402  (sys.path mutated above)
    AflPlusPlusScraper,
    FuzzilliScraper,
    LibFuzzerScraper,
)

__all__ = [
    "test_fuzzilli_poll_parses_stats_and_counts_crashes",
    "test_fuzzilli_poll_returns_none_when_missing",
    "test_fuzzilli_discover_crashes_emits_one_record_per_file",
    "test_afl_poll_parses_kv_stats",
    "test_afl_poll_returns_none_when_missing",
    "test_afl_discover_crashes_skips_readme",
    "test_libfuzzer_poll_parses_tail_stats",
    "test_libfuzzer_discover_artifacts_matches_kind_prefix",
]


# ── Fuzzilli ──────────────────────────────────────────────────────────


def test_fuzzilli_poll_parses_stats_and_counts_crashes(tmp_path: Path) -> None:
    (tmp_path / "stats.json").write_text(json.dumps({
        "totalExecs": 1_234_567,
        "execsPerSecond": 9876.5,
        "coverage": 0.42,
        "corpusSize": 88,
    }))
    (tmp_path / "crashes").mkdir()
    (tmp_path / "crashes" / "crash-001.js").write_text("// poc 1")
    (tmp_path / "crashes" / "crash-002.js").write_text("// poc 2")

    sample = FuzzilliScraper(tmp_path).poll()
    assert sample is not None
    assert sample.total_execs == 1_234_567
    assert sample.execs_per_sec == 9876.5
    assert sample.corpus_size == 88
    # Coverage 0.42 fraction → 42.0 percent.
    assert sample.coverage_pct == 42.0
    # crashes_found populated from the crash-dir count when stats.json
    # didn't carry an explicit field.
    assert sample.crashes_found == 2


def test_fuzzilli_poll_returns_none_when_missing(tmp_path: Path) -> None:
    # No stats.json → None (telemetry skipped this iteration).
    assert FuzzilliScraper(tmp_path).poll() is None


def test_fuzzilli_discover_crashes_emits_one_record_per_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "stats.json").write_text("{}")
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash-abc.js").write_text("Math.imul(2,3);")
    (crashes / "crash-def.js").write_text("var x = [];")
    distinct = tmp_path / "distinct_crashes"
    distinct.mkdir()
    (distinct / "crash-ghi.js").write_text("({}).toString();")

    records = FuzzilliScraper(tmp_path).discover_crashes()
    # 3 files across the two crash dirs → 3 records.
    assert len(records) == 3
    names = {r.crash_signature for r in records}
    assert names == {"crash-abc.js", "crash-def.js", "crash-ghi.js"}
    # Stack hashes are deterministic per filename.
    assert all(len(r.stack_hash) == 64 for r in records)
    # Each carries an engine tag.
    assert all(r.extra.get("engine") == "fuzzilli" for r in records)


# ── AFL++ ─────────────────────────────────────────────────────────────


def test_afl_poll_parses_kv_stats(tmp_path: Path) -> None:
    default = tmp_path / "default"
    default.mkdir()
    (default / "fuzzer_stats").write_text(
        "start_time        : 1715000000\n"
        "execs_done        : 4200000\n"
        "execs_per_sec     : 1450.20\n"
        "paths_total       : 312\n"
        "unique_crashes    : 7\n"
        "bitmap_cvg        : 32.45%\n",
    )

    sample = AflPlusPlusScraper(tmp_path).poll()
    assert sample is not None
    assert sample.total_execs == 4_200_000
    assert sample.execs_per_sec == 1450.20
    assert sample.corpus_size == 312
    assert sample.crashes_found == 7
    assert sample.coverage_pct == 32.45


def test_afl_poll_returns_none_when_missing(tmp_path: Path) -> None:
    assert AflPlusPlusScraper(tmp_path).poll() is None


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason=(
        "AFL++ filenames carry ':' separators that Windows rejects at "
        "the file-system layer. The sidecar runs on Linux workstations "
        "only (D-33) so the parser only needs to work there."
    ),
)
def test_afl_discover_crashes_skips_readme(tmp_path: Path) -> None:
    default = tmp_path / "default"
    default.mkdir()
    (default / "fuzzer_stats").write_text("")
    crashes = default / "crashes"
    crashes.mkdir()
    (crashes / "README.txt").write_text("AFL++ readme")
    (crashes / "id:000001,sig:11,src:000040,op:havoc,rep:8").write_bytes(b"\xaa")
    (crashes / "id:000002,sig:11,src:000041,op:splice,rep:1").write_bytes(b"\xbb")

    records = AflPlusPlusScraper(tmp_path).discover_crashes()
    assert len(records) == 2
    # README is skipped.
    assert all("README" not in (r.crash_signature or "") for r in records)
    # op suffix surfaced as crash_type.
    assert {r.crash_type for r in records} == {"afl++_op_havoc", "afl++_op_splice"}
    # AFL++ engine tag present.
    assert all(r.extra.get("engine") == "afl++" for r in records)


# ── libFuzzer ─────────────────────────────────────────────────────────


def test_libfuzzer_poll_parses_tail_stats(tmp_path: Path) -> None:
    log_path = tmp_path / "fuzzer.log"
    artifacts = tmp_path / "art"
    artifacts.mkdir()
    log_path.write_text(
        "INFO: Seed: 0\n"
        "#100  INITED cov: 12 ft: 14 corp: 1/1b lim: 4096 exec/s: 0 rss: 25Mb\n"
        "#1024 NEW    cov: 88 ft: 102 corp: 22/512b lim: 4096 exec/s: 2048 rss: 110Mb\n"
        "#9999 pulse  cov: 256 ft: 311 corp: 64/2Kb lim: 4096 exec/s: 4096 rss: 200Mb\n",
    )

    sample = LibFuzzerScraper(log_path, artifacts).poll()
    assert sample is not None
    # The MOST RECENT matching line drives the sample.
    assert sample.total_execs == 9999
    assert sample.corpus_size == 64
    assert sample.execs_per_sec == 4096.0
    # libFuzzer doesn't ship a percentage — left as None.
    assert sample.coverage_pct is None
    # No artifact files yet.
    assert sample.crashes_found == 0


def test_libfuzzer_discover_artifacts_matches_kind_prefix(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "fuzzer.log"
    log_path.write_text("")  # log empty is fine
    artifacts = tmp_path / "art"
    artifacts.mkdir()
    (artifacts / "crash-aabbccdd").write_bytes(b"\x01\x02")
    (artifacts / "leak-eeff0011").write_bytes(b"\x03")
    (artifacts / "oom-22334455").write_bytes(b"\x04\x05\x06")
    (artifacts / "timeout-66778899").write_bytes(b"\x07")
    # A non-artifact file is ignored.
    (artifacts / "fuzz.log").write_text("noise")

    records = LibFuzzerScraper(log_path, artifacts).discover_crashes()
    assert len(records) == 4
    kinds = {r.crash_type for r in records}
    assert kinds == {
        "libfuzzer_crash",
        "libfuzzer_leak",
        "libfuzzer_oom",
        "libfuzzer_timeout",
    }
    # Severity floor: real crashes are medium, the others low.
    by_kind = {r.crash_type: r.severity for r in records}
    assert by_kind["libfuzzer_crash"] == "medium"
    assert by_kind["libfuzzer_leak"] == "low"
