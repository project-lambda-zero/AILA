"""Tests for SCALE-01 / SCALE-02 config schema fields (Phase 21 Plan 01)."""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema


def test_ssh_max_workers_default():
    """VulnerabilityConfigSchema must expose ssh_max_workers with default 10."""
    cfg = VulnerabilityConfigSchema()
    assert cfg.ssh_max_workers == 10


def test_ssh_command_timeout_seconds_default():
    """VulnerabilityConfigSchema must expose ssh_command_timeout_seconds with default 300.0."""
    cfg = VulnerabilityConfigSchema()
    assert cfg.ssh_command_timeout_seconds == 300.0


def test_ssh_max_workers_override():
    """ssh_max_workers must accept any integer value (no ge constraint)."""
    cfg = VulnerabilityConfigSchema(ssh_max_workers=5)
    assert cfg.ssh_max_workers == 5


def test_ssh_command_timeout_seconds_override():
    """ssh_command_timeout_seconds must accept any float value."""
    cfg = VulnerabilityConfigSchema(ssh_command_timeout_seconds=60.0)
    assert cfg.ssh_command_timeout_seconds == 60.0


def test_ssh_max_workers_zero_accepted():
    """ssh_max_workers=0 is accepted (ThreadPoolExecutor handles it via os.cpu_count)."""
    cfg = VulnerabilityConfigSchema(ssh_max_workers=0)
    assert cfg.ssh_max_workers == 0
