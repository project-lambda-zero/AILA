"""Fuzz launcher — translates a campaign's engine_id + engine_config
into a shell command, SSHes to the workstation, starts the fuzzer in
the background, and records the remote PID + corpus/crashes dirs.

Architecture (D-33):
  AILA never runs the fuzzer in-process. The launcher opens an SSH
  session to the campaign's ``analysis_system_id`` workstation,
  prepares a per-campaign workdir at ``~/.aila/fuzz/<campaign_id>/``,
  starts the chosen engine under ``nohup`` so it survives the SSH
  channel closing, and captures the remote PID for later observability
  (status checks, kill, log tail).

  The fuzzer's actual output (crashes, corpus, telemetry) is reported
  back into AILA by the sidecar at ``tools/aila_fuzz_reporter/``, which
  the operator runs on the same workstation alongside the fuzzer.
"""
from __future__ import annotations

import json
import logging
import shlex
from dataclasses import dataclass
from typing import Any

from aila.modules.vr.contracts.fuzz import FuzzEngineId

__all__ = [
    "FuzzLauncherError",
    "LaunchCommand",
    "build_launch_command",
]

_log = logging.getLogger(__name__)


class FuzzLauncherError(Exception):
    """Raised when the launcher cannot construct or execute a command."""


@dataclass(frozen=True)
class LaunchCommand:
    """Result of resolving an engine_id + config into a runnable shell.

    The launcher SSHes to the workstation and runs the ``setup``
    commands first (mkdir, cp seeds, etc.), then starts the fuzzer
    via ``run_in_background`` which captures the PID into
    ``${workdir}/fuzzer.pid``.
    """

    workdir: str
    corpus_dir: str
    crashes_dir: str
    setup_commands: tuple[str, ...]
    run_in_background: str
    description: str


def _need(config: dict[str, Any], key: str) -> str:
    val = config.get(key)
    if not val:
        raise FuzzLauncherError(
            f"engine_config.{key} is required for this engine",
        )
    return str(val)


def build_launch_command(
    *,
    campaign_id: str,
    engine_id: FuzzEngineId,
    engine_config: dict[str, Any],
    strategy_config: dict[str, Any],  # currently unused; reserved for grammar / dict files
) -> LaunchCommand:
    """Map (engine_id, engine_config) → LaunchCommand for SSH execution.

    Required engine_config keys per engine:

    - **fuzzilli_v8**: ``fuzzilli_path`` (FuzzIlli binary),
      ``profile`` (e.g. ``v8MapInference``), ``v8_path``
      (path to d8 with --reprl).
    - **afl++ / afl++_qemu**: ``target_binary`` (path to harness),
      ``seed_dir`` (initial seed corpus). For qemu mode the binary
      may be non-instrumented.
    - **libfuzzer**: ``target_binary`` (libFuzzer-linked binary).
      Optional ``seed_dir``, ``dict_path``.
    - **honggfuzz**: ``target_binary``, ``seed_dir``.
    - **jazzer / cargo-fuzz / go-fuzz / atheris**: ``target_spec``
      (engine-specific identifier — fully-qualified class name for
      jazzer, package::target for cargo-fuzz, etc.).
    - **v8_d8_sbx**: ``d8_path``, ``poc_path`` (single PoC file to
      replay rather than a fuzzing campaign).

    `strategy_config` is reserved for future use (grammar files,
    mutator weights). Currently unused — strategy is encoded in
    engine_config when needed.
    """
    del strategy_config  # reserved
    workdir = f"~/.aila/fuzz/{campaign_id}"
    corpus_dir = f"{workdir}/corpus"
    crashes_dir = f"{workdir}/crashes"
    common_setup = (
        f"mkdir -p {workdir} {corpus_dir} {crashes_dir}",
    )

    if engine_id == FuzzEngineId.FUZZILLI_V8:
        fuzzilli_path = _need(engine_config, "fuzzilli_path")
        profile = _need(engine_config, "profile")
        v8_path = _need(engine_config, "v8_path")
        cmd = (
            f"{shlex.quote(fuzzilli_path)} "
            f"--storagePath={shlex.quote(workdir)} "
            f"--profile={shlex.quote(profile)} "
            f"{shlex.quote(v8_path)}"
        )
        return LaunchCommand(
            workdir=workdir,
            corpus_dir=corpus_dir,
            crashes_dir=f"{workdir}/crashes",
            setup_commands=common_setup,
            run_in_background=_wrap_nohup(cmd, workdir),
            description=f"fuzzilli ({profile})",
        )

    if engine_id in (FuzzEngineId.AFL_PLUSPLUS, FuzzEngineId.AFL_PLUSPLUS_QEMU):
        target_binary = _need(engine_config, "target_binary")
        seed_dir = _need(engine_config, "seed_dir")
        afl_flags = ""
        if engine_id == FuzzEngineId.AFL_PLUSPLUS_QEMU:
            afl_flags = "-Q "
        copy_seeds = (
            f"cp -r {shlex.quote(seed_dir)}/. {corpus_dir}/ 2>/dev/null || true",
        )
        cmd = (
            f"afl-fuzz {afl_flags}-i {shlex.quote(corpus_dir)} "
            f"-o {shlex.quote(workdir)}/out -- {shlex.quote(target_binary)} @@"
        )
        return LaunchCommand(
            workdir=workdir,
            corpus_dir=corpus_dir,
            crashes_dir=f"{workdir}/out/default/crashes",
            setup_commands=common_setup + copy_seeds,
            run_in_background=_wrap_nohup(cmd, workdir),
            description=f"afl++ ({'qemu' if afl_flags else 'native'})",
        )

    if engine_id == FuzzEngineId.LIBFUZZER:
        target_binary = _need(engine_config, "target_binary")
        seed_dir = engine_config.get("seed_dir")
        dict_path = engine_config.get("dict_path")
        flags = ""
        if dict_path:
            flags += f"-dict={shlex.quote(str(dict_path))} "
        seed_arg = shlex.quote(str(seed_dir)) if seed_dir else corpus_dir
        cmd = (
            f"{shlex.quote(target_binary)} {flags}"
            f"-artifact_prefix={shlex.quote(crashes_dir)}/ "
            f"{shlex.quote(corpus_dir)} {seed_arg}"
        )
        return LaunchCommand(
            workdir=workdir,
            corpus_dir=corpus_dir,
            crashes_dir=crashes_dir,
            setup_commands=common_setup,
            run_in_background=_wrap_nohup(cmd, workdir),
            description="libfuzzer",
        )

    if engine_id == FuzzEngineId.HONGGFUZZ:
        target_binary = _need(engine_config, "target_binary")
        seed_dir = _need(engine_config, "seed_dir")
        cmd = (
            f"honggfuzz --input {shlex.quote(seed_dir)} "
            f"--output {shlex.quote(workdir)}/out "
            f"--crashdir {shlex.quote(crashes_dir)} "
            f"-- {shlex.quote(target_binary)} ___FILE___"
        )
        return LaunchCommand(
            workdir=workdir,
            corpus_dir=corpus_dir,
            crashes_dir=crashes_dir,
            setup_commands=common_setup,
            run_in_background=_wrap_nohup(cmd, workdir),
            description="honggfuzz",
        )

    if engine_id == FuzzEngineId.V8_D8_SBX:
        d8_path = _need(engine_config, "d8_path")
        poc_path = _need(engine_config, "poc_path")
        cmd = (
            f"{shlex.quote(d8_path)} --sandbox-testing "
            f"--expose-gc --allow-natives-syntax "
            f"{shlex.quote(poc_path)}"
        )
        # Not really a campaign — single PoC replay. Still goes through
        # nohup so we can capture exit code + stdout/err for the
        # operator.
        return LaunchCommand(
            workdir=workdir,
            corpus_dir=corpus_dir,
            crashes_dir=crashes_dir,
            setup_commands=common_setup,
            run_in_background=_wrap_nohup(cmd, workdir),
            description="v8 d8 sandbox replay",
        )

    raise FuzzLauncherError(
        f"launcher does not yet support engine_id={engine_id.value}. "
        f"Supported: fuzzilli_v8, afl++, afl++_qemu, libfuzzer, "
        f"honggfuzz, v8_d8_sbx",
    )


def _wrap_nohup(cmd: str, workdir: str) -> str:
    """Wrap a fuzzer command in nohup so it survives SSH channel close
    and capture the PID for later observability + kill.

    Writes:
      ${workdir}/fuzzer.pid    — backgrounded process id
      ${workdir}/fuzzer.log    — combined stdout + stderr
    """
    return (
        f"cd {workdir} && "
        f"nohup sh -c {shlex.quote(cmd)} "
        f">{workdir}/fuzzer.log 2>&1 & "
        f"echo $! > {workdir}/fuzzer.pid && "
        f"sleep 1 && cat {workdir}/fuzzer.pid"
    )


def serialize_for_log(launch: LaunchCommand) -> str:
    """Compact human-readable summary persisted to launch_log column."""
    return json.dumps(
        {
            "description": launch.description,
            "workdir": launch.workdir,
            "corpus_dir": launch.corpus_dir,
            "crashes_dir": launch.crashes_dir,
            "setup": list(launch.setup_commands),
            "run": launch.run_in_background,
        },
        indent=2,
    )
