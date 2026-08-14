"""Nightly + on-demand corpus export task (issue #158).

Wraps :func:`aila.platform.eval.corpus.export_corpus` in a
``@platform_task`` so the platform admin endpoint (and the automation
runner, if the operator seeds a schedule that targets this task's
qualified name) can enqueue it through the standard :class:`TaskQueue`
path.

Task name uniqueness (CLAUDE.md common mistake 19): the underlying
``@platform_task`` wrapper sets ``_wrapper.__name__ = fn.__name__``.
Two tasks named ``run_corpus_export`` would collide on ARQ's bare-name
lookup, so this file is the ONLY producer of a task by that name in
the codebase. Grep-verified before landing.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from aila.platform.eval.corpus import export_corpus
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_corpus_export"]

_log = logging.getLogger(__name__)


@platform_task(
    track="default",
    module_id="__platform__",
    max_tries=1,
    timeout_s=3600.0,
)
async def run_corpus_export(
    ctx: TaskContext,
    *,
    modules: list[str] | None = None,
    lookback_days: int | None = None,
) -> dict[str, Any]:
    """Mine the last ``lookback_days`` of trajectories into SFT + DPO jsonl.

    Args:
        ctx: Standard platform-task context (unused).
        modules: Optional override of the ``platform.corpus_modules``
            config value -- pass ``None`` to fall back to the
            configured list. An empty list is treated as "use
            configured".
        lookback_days: Optional window (in days) counted back from the
            current UTC wall-clock. ``None`` scans everything the
            outcome tables carry.

    Returns a small manifest dict the admin endpoint surfaces to the
    operator.
    """
    del ctx  # unused; required positional for the platform_task contract
    since: datetime | None = None
    if lookback_days is not None and lookback_days > 0:
        since = datetime.now(UTC) - timedelta(days=int(lookback_days))
    module_list = [m for m in (modules or []) if isinstance(m, str) and m.strip()]
    manifest = await export_corpus(
        modules=module_list or None,
        since=since,
    )
    _log.info(
        "run_corpus_export completed sft=%d dpo=%d modules=%s dir=%s",
        manifest.sft_count,
        manifest.dpo_count,
        ",".join(manifest.modules),
        manifest.corpus_dir,
    )
    return {
        "sft_count": manifest.sft_count,
        "dpo_count": manifest.dpo_count,
        "investigations": manifest.investigations,
        "modules": manifest.modules,
        "module_breakdown": manifest.module_breakdown,
        "corpus_dir": manifest.corpus_dir,
        "sft_path": manifest.sft_path,
        "dpo_path": manifest.dpo_path,
        "generated_at": manifest.generated_at.isoformat(),
        "skipped_short_branches": manifest.skipped_short_branches,
        "skipped_unparseable_decisions": manifest.skipped_unparseable_decisions,
    }
