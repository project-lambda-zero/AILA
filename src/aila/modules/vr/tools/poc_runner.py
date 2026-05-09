"""PoC runner — uploads, compiles, and executes vulnerability PoCs over SSH.

v0.1 sandbox: PoCs run inside ``/tmp/aila_vr/`` fenced by GNU ``timeout`` and
``ulimit -v``. The wrapper always exits 0 and embeds the real PoC exit code
between ``__AILA_POC_*__`` markers so paramiko's non-zero-raises path doesn't
swallow legitimate crash signals (139/134/136).
"""
from __future__ import annotations

import os
import re
import shlex
import tempfile
from pathlib import PurePosixPath
from typing import Any

from aila.config import Settings
from aila.platform.config import build_platform_settings
from aila.platform.services import SSHService
from aila.platform.tools._common import Tool

__all__ = ["PoCRunnerTool"]

_REMOTE_DIR = "/tmp/aila_vr"
_EXIT_MARKER = "__AILA_POC_EXIT__:"
_OUT_BEGIN = "__AILA_POC_OUT_BEGIN__"
_OUT_END = "__AILA_POC_OUT_END__"
_ERR_BEGIN = "__AILA_POC_ERR_BEGIN__"
_ERR_END = "__AILA_POC_ERR_END__"
_TAIL_LIMIT = 2000
# 128 + signal: SIGABRT=6, SIGFPE=8, SIGSEGV=11. 124 is GNU timeout's hit code.
_CRASH_EXIT_CODES = frozenset({134, 136, 139})
_TIMEOUT_EXIT_CODE = 124


def _between(text: str, begin: str, end: str) -> str:
    a = text.find(begin)
    if a < 0:
        return ""
    start = a + len(begin)
    b = text.find(end, start)
    return (text[start:b] if b >= 0 else text[start:]).strip("\n")


def _parse_exit(text: str) -> int | None:
    m = re.search(rf"{re.escape(_EXIT_MARKER)}(-?\d+)", text)
    return int(m.group(1)) if m else None


def _err(message: str) -> dict:
    return {"status": "error", "error": message}


class PoCRunnerTool(Tool):
    name = "vr.poc_runner"
    description = (
        "Upload, compile, and execute vulnerability PoC scripts on the research "
        "workstation. Verifies crash on vulnerable version and clean exit on "
        "patched version."
    )
    inputs = {"action": {"type": "string", "description": "compile_poc, run_poc, verify_reliability"}}
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        if not action:
            return _err("action is required")
        integration = kwargs.pop("integration", None)
        if not isinstance(integration, dict) or not integration:
            return _err("integration (SSH config) is required")
        ssh = SSHService(build_platform_settings(self.settings))
        handlers = {"compile_poc": self._compile, "run_poc": self._run, "verify_reliability": self._reliability}
        handler = handlers.get(action)
        if handler is None:
            return _err(f"unknown action: {action}")
        return await handler(ssh, integration, **kwargs)

    async def _compile(
        self, ssh: SSHService, integration: dict,
        code: str | None = None, language: str = "python",
        filename: str | None = None, **_extra: Any,
    ) -> dict:
        if not isinstance(code, str) or not code:
            return _err("code is required")
        if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
            return _err("filename must be a bare basename")
        if language not in ("python", "c"):
            return _err(f"unsupported language: {language}")

        remote_src = f"{_REMOTE_DIR}/{filename}"
        await ssh.run_command(integration, f"mkdir -p {shlex.quote(_REMOTE_DIR)}", timeout_seconds=30.0)

        local_fd, local_path = tempfile.mkstemp(prefix="aila_vr_", suffix=f"_{filename}")
        os.close(local_fd)
        try:
            with open(local_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            await ssh.upload_file(integration, local_path, remote_src, timeout_seconds=120.0)
        finally:
            try:
                os.unlink(local_path)
            except OSError:
                pass

        if language == "python":
            return {"status": "ready", "language": "python", "script_path": remote_src}

        binary_path = f"{_REMOTE_DIR}/{PurePosixPath(filename).stem or 'poc'}"
        compile_cmd = (f"{{ gcc -o {shlex.quote(binary_path)} {shlex.quote(remote_src)} -lpthread; }} "
                       f'2>&1; printf "{_EXIT_MARKER}%s\\n" "$?"')
        output = await ssh.run_command(integration, compile_cmd, timeout_seconds=180.0)
        exit_code = _parse_exit(output)
        compile_output = re.sub(rf"\n?{re.escape(_EXIT_MARKER)}-?\d+\s*$", "", output).rstrip("\n")
        compile_output = compile_output[-_TAIL_LIMIT:]
        if exit_code != 0:
            return {"status": "error", "error": "compilation failed",
                    "exit_code": exit_code, "compile_output": compile_output,
                    "source_path": remote_src}
        return {"status": "ready", "language": "c",
                "binary_path": binary_path, "compile_output": compile_output,
                "source_path": remote_src}

    async def _run(
        self, ssh: SSHService, integration: dict,
        poc_path: str | None = None, target_binary: str | None = None,
        timeout_seconds: float = 30.0, memory_limit_mb: int = 2048,
        **_extra: Any,
    ) -> dict:
        if not isinstance(poc_path, str) or not poc_path:
            return _err("poc_path is required")
        if not isinstance(target_binary, str) or not target_binary:
            return _err("target_binary is required")
        try:
            timeout = float(timeout_seconds)
            mem_kb = max(int(memory_limit_mb), 256) * 1024
        except (TypeError, ValueError):
            return _err("invalid timeout/memory args")

        invoke = (
            f"python3 {shlex.quote(poc_path)} {shlex.quote(target_binary)}"
            if poc_path.endswith(".py")
            else f"{shlex.quote(poc_path)} {shlex.quote(target_binary)}"
        )
        wrapper = (
            "so=$(mktemp); se=$(mktemp); "
            f'{{ ulimit -v {mem_kb}; timeout {timeout:g}s {invoke}; }} >"$so" 2>"$se"; ec=$?; '
            f'printf "{_EXIT_MARKER}%s\\n" "$ec"; '
            f'printf "{_OUT_BEGIN}\\n"; cat "$so"; printf "\\n{_OUT_END}\\n"; '
            f'printf "{_ERR_BEGIN}\\n"; cat "$se"; printf "\\n{_ERR_END}\\n"; '
            'rm -f "$so" "$se"'
        )
        cmd = f"bash -lc {shlex.quote(wrapper)}"
        ssh_idle_timeout = max(timeout + 30.0, 60.0)
        output = await ssh.run_command(integration, cmd, timeout_seconds=ssh_idle_timeout)

        exit_code = _parse_exit(output)
        stdout_text = _between(output, _OUT_BEGIN, _OUT_END)
        stderr_text = _between(output, _ERR_BEGIN, _ERR_END)
        asan_report = "ERROR: AddressSanitizer" in stderr_text or "ERROR: AddressSanitizer" in stdout_text
        return {
            "status": "ready",
            "exit_code": exit_code,
            "crash_detected": bool(exit_code in _CRASH_EXIT_CODES or asan_report),
            "clean_exit": bool(exit_code == 0 and not asan_report),
            "timeout": bool(exit_code == _TIMEOUT_EXIT_CODE),
            "asan_report": asan_report,
            "stderr_tail": stderr_text[-_TAIL_LIMIT:],
            "stdout_tail": stdout_text[-_TAIL_LIMIT:],
        }

    async def _reliability(
        self, ssh: SSHService, integration: dict,
        poc_path: str | None = None, target_binary: str | None = None,
        runs: int = 5, timeout_seconds: float = 30.0,
        memory_limit_mb: int = 2048, **_extra: Any,
    ) -> dict:
        try:
            total = max(1, int(runs))
        except (TypeError, ValueError):
            return _err("runs must be an integer")

        all_results: list[dict] = []
        crashes = 0
        for _ in range(total):
            result = await self._run(ssh, integration, poc_path=poc_path, target_binary=target_binary,
                                     timeout_seconds=timeout_seconds, memory_limit_mb=memory_limit_mb)
            all_results.append(result)
            if result.get("crash_detected"):
                crashes += 1
        return {
            "status": "ready",
            "crashes": crashes,
            "total": total,
            "reliability": f"{crashes}/{total}",
            "all_results": all_results,
        }
