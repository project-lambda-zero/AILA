"""Tests for SCALE-01 / SCALE-02 config schema fields (Phase 21 Plan 01)."""
from __future__ import annotations

from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema


def test_ssh_max_workers_zero_accepted():
    """ssh_max_workers=0 is accepted (ThreadPoolExecutor handles it via os.cpu_count)."""
    cfg = VulnerabilityConfigSchema(ssh_max_workers=0)
    assert cfg.ssh_max_workers == 0
