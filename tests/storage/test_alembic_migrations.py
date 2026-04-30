"""Tests for Alembic migration configuration and baseline stamp.

Covers: 124-02-01, 124-02-02, DB-02, DB-03, DB-06
TDD red phase -- these tests will fail until Plan 02 creates
the Alembic configuration and baseline stamp migration.
"""
from __future__ import annotations

import os

import pytest

__all__: list[str] = []


def test_alembic_ini_exists():
    """alembic.ini exists at src/aila/alembic.ini."""
    assert os.path.exists("src/aila/alembic.ini"), "alembic.ini not found"


def test_alembic_env_imports_models():
    """env.py imports all model modules for autogenerate."""
    env_path = "src/aila/alembic/env.py"
    assert os.path.exists(env_path), "env.py not found"
    content = open(env_path).read()
    assert "from aila.storage import db_models" in content
    assert "target_metadata" in content


def test_baseline_stamp_is_empty():
    """Baseline stamp migration has pass-only upgrade/downgrade."""
    stamp_path = "src/aila/alembic/versions/001_baseline_stamp.py"
    assert os.path.exists(stamp_path), "baseline stamp not found"
    content = open(stamp_path).read()
    assert "def upgrade" in content
    assert "def downgrade" in content


def test_env_uses_psycopg_for_sync(pg_url):
    """env.py converts asyncpg URL to psycopg for sync Alembic operations."""
    env_path = "src/aila/alembic/env.py"
    content = open(env_path).read()
    assert "psycopg" in content, "env.py must use psycopg sync driver"
    assert "asyncpg" in content, "env.py must reference asyncpg for URL conversion"
