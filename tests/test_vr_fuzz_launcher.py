"""Unit tests for ``aila.modules.vr.services.fuzz_launcher``.

Covers the per-engine command builders. The launcher itself is pure
shell-string construction — no SSH, no subprocess, no DB — so tests
just assert the strings it produces are well-formed and reject bad
config explicitly.
"""
from __future__ import annotations

import json

import pytest

from aila.modules.vr.contracts.fuzz import FuzzEngineId
from aila.modules.vr.services.fuzz_launcher import (
    FuzzLauncherError,
    build_launch_command,
    serialize_for_log,
)

__all__ = [
    "test_fuzzilli_requires_three_keys",
    "test_fuzzilli_command_shapes_workdir_and_profile",
    "test_afl_plus_plus_native_vs_qemu",
    "test_libfuzzer_includes_artifact_prefix",
    "test_unsupported_engine_raises",
    "test_serialize_for_log_is_valid_json",
]


def test_fuzzilli_requires_three_keys() -> None:
    """Missing fuzzilli_path / profile / v8_path → FuzzLauncherError."""
    with pytest.raises(FuzzLauncherError, match="fuzzilli_path is required"):
        build_launch_command(
            campaign_id="c1",
            engine_id=FuzzEngineId.FUZZILLI_V8,
            engine_config={"profile": "v8MapInference", "v8_path": "/d8"},
            strategy_config={},
        )
    with pytest.raises(FuzzLauncherError, match="profile is required"):
        build_launch_command(
            campaign_id="c1",
            engine_id=FuzzEngineId.FUZZILLI_V8,
            engine_config={"fuzzilli_path": "/f", "v8_path": "/d8"},
            strategy_config={},
        )


def test_fuzzilli_command_shapes_workdir_and_profile() -> None:
    cmd = build_launch_command(
        campaign_id="9c1f-abcd",
        engine_id=FuzzEngineId.FUZZILLI_V8,
        engine_config={
            "fuzzilli_path": "/opt/fuzzilli/.build/release/FuzzilliCli",
            "profile": "v8MapInference",
            "v8_path": "/opt/v8/d8",
        },
        strategy_config={},
    )
    assert cmd.workdir == "~/.aila/fuzz/9c1f-abcd"
    assert cmd.corpus_dir == "~/.aila/fuzz/9c1f-abcd/corpus"
    assert "v8MapInference" in cmd.run_in_background
    assert "FuzzilliCli" in cmd.run_in_background
    # nohup wrapper captures PID into fuzzer.pid.
    assert "fuzzer.pid" in cmd.run_in_background
    assert cmd.description == "fuzzilli (v8MapInference)"


def test_afl_plus_plus_native_vs_qemu() -> None:
    native = build_launch_command(
        campaign_id="c2",
        engine_id=FuzzEngineId.AFL_PLUSPLUS,
        engine_config={
            "target_binary": "/usr/local/bin/harness",
            "seed_dir": "/tmp/seeds",
        },
        strategy_config={},
    )
    qemu = build_launch_command(
        campaign_id="c3",
        engine_id=FuzzEngineId.AFL_PLUSPLUS_QEMU,
        engine_config={
            "target_binary": "/closed/source/binary",
            "seed_dir": "/tmp/seeds",
        },
        strategy_config={},
    )
    # afl-fuzz invoked in both cases.
    assert "afl-fuzz" in native.run_in_background
    assert "afl-fuzz" in qemu.run_in_background
    # -Q flag only in qemu variant.
    assert "-Q " not in native.run_in_background
    assert "-Q " in qemu.run_in_background
    # Crashes dir matches AFL++ default sub-path.
    assert native.crashes_dir.endswith("/out/default/crashes")


def test_libfuzzer_includes_artifact_prefix() -> None:
    cmd = build_launch_command(
        campaign_id="c4",
        engine_id=FuzzEngineId.LIBFUZZER,
        engine_config={
            "target_binary": "/build/libfuzzer_harness",
            "dict_path": "/dicts/png.dict",
        },
        strategy_config={},
    )
    assert "-artifact_prefix=" in cmd.run_in_background
    assert "-dict=" in cmd.run_in_background
    assert cmd.description == "libfuzzer"


def test_unsupported_engine_raises() -> None:
    with pytest.raises(FuzzLauncherError, match="does not yet support"):
        build_launch_command(
            campaign_id="c5",
            engine_id=FuzzEngineId.JAZZER,
            engine_config={},
            strategy_config={},
        )


def test_serialize_for_log_is_valid_json() -> None:
    cmd = build_launch_command(
        campaign_id="c6",
        engine_id=FuzzEngineId.FUZZILLI_V8,
        engine_config={
            "fuzzilli_path": "/f",
            "profile": "p",
            "v8_path": "/d8",
        },
        strategy_config={},
    )
    payload = json.loads(serialize_for_log(cmd))
    assert payload["description"] == "fuzzilli (p)"
    assert payload["workdir"] == "~/.aila/fuzz/c6"
    assert isinstance(payload["setup"], list)
    assert payload["run"].endswith("cat ~/.aila/fuzz/c6/fuzzer.pid")
