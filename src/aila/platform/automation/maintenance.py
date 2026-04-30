"""Platform maintenance actions registered with AutomationRegistry.

These are platform-owned background jobs that run without team context
(team_id=None). They are submitted through the standard TaskQueue path
when their automation schedule fires.

AUTO-06: Platform maintenance jobs use module_id='platform'.
"""
from __future__ import annotations

__all__ = ["platform_health_check", "register_maintenance_actions"]

import logging

from aila.platform.automation.registry import AutomationRegistry

_log = logging.getLogger(__name__)


def platform_health_check(**kwargs: object) -> None:
    """Platform health check and stale task cleanup.

    Performs lightweight platform maintenance:
    - Logs that the health check ran (observable via structured logging)
    - Future: stale session cleanup, metric aggregation, etc.

    Called by AutomationRunner via TaskQueue when the schedule fires.
    The execution_context kwarg is injected by the task worker.
    """
    target = kwargs.get("target_name", "platform")
    _log.info("Platform health check executed (target=%s)", target)


def register_maintenance_actions(registry: AutomationRegistry) -> None:
    """Register all platform-owned maintenance actions.

    Called during app startup after the AutomationRegistry is created.
    Each action here runs with team_id=None (platform scope).
    """
    registry.register_action(
        action_id="platform.health_check",
        handler_fn=platform_health_check,
        description="Platform health check and cleanup",
        module_id="platform",
    )
    _log.info("Platform maintenance actions registered")
