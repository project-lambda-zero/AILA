"""Log-file collector — basic preview + line count."""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.exceptions import AILAError

from ._helpers import safe_emit, sq, truncate

__all__ = ["collect_log_artifacts"]

_log = logging.getLogger(__name__)


async def collect_log_artifacts(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str = "linux",
    emitter: Any = None,
    on_artifact: Any = None,
) -> list[dict[str, Any]]:
    """Grab a 50-line head + line-count from a log file as a cheap preview."""
    qpath = sq(path, analyzer_os)
    if analyzer_os == "windows":
        cmd = (
            f'powershell -NoProfile -Command "'
            f"$c = Get-Content {qpath} -TotalCount 50; "
            f"Write-Output (\\\"Lines: \\\" + (Get-Content {qpath} | Measure-Object -Line).Lines); "
            f'$c"'
        )
    else:
        cmd = f"wc -l {qpath} 2>/dev/null; head -50 {qpath} 2>/dev/null"

    artifacts: list[dict[str, Any]] = []
    try:
        output = await ssh.run_command(integration, cmd, timeout_seconds=60.0)
        art = {
            "family": "log",
            "type": "log_preview",
            "source_tool": "coreutils" if analyzer_os != "windows" else "powershell",
            "data": {"raw_output": truncate(output, 4000), "evidence_path": path},
        }
        artifacts.append(art)
        if on_artifact:
            await on_artifact(art)
        await safe_emit(emitter, "artifact_added", f"log: preview ok for {path}", {"path": path, "type": "log_preview"})
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("log collection failed for %s: %s", path, exc, exc_info=True)
        await safe_emit(emitter, "query_failed", f"log preview failed: {exc}", {"path": path, "error": str(exc)[:200]})

    return artifacts
