"""Unit tests for :mod:`aila.tools.liveness_audit`.

Each rule is exercised via a small synthetic fixture written into
``tmp_path`` -- no dependence on the real ``src/aila`` tree so the test
stays fast and deterministic.
"""
from __future__ import annotations

from pathlib import Path

from aila.tools.liveness_audit import Finding, LivenessAuditor, load_whitelist

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, source: str) -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(source, encoding="utf-8")
    return p


def _audit(root: Path, whitelist_path: Path | None = None) -> list[Finding]:
    wl = load_whitelist(whitelist_path) if whitelist_path else set()
    return LivenessAuditor(whitelist=wl).audit_directory(root)


def _by_rule(findings: list[Finding], rule: str) -> list[Finding]:
    return [f for f in findings if f.rule == rule]


# ---------------------------------------------------------------------------
# R1 -- unread_config_key
# ---------------------------------------------------------------------------


class TestUnreadConfigKey:
    """Written-and-read keys are silent; written-never-read keys fire."""

    def test_read_key_is_not_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "schema.py",
            (
                "from pydantic import BaseModel\n"
                "class MyConfigSchema(BaseModel):\n"
                "    request_timeout_seconds: float = 20.0\n"
            ),
        )
        _write(
            tmp_path,
            "gate.py",
            (
                "def get_timeout(registry):\n"
                "    return registry.get('myns', 'request_timeout_seconds')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unread_config_key")
        assert not any(
            "request_timeout_seconds" in f.message for f in findings
        ), findings

    def test_unread_key_is_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "schema.py",
            (
                "from pydantic import BaseModel\n"
                "class MyConfigSchema(BaseModel):\n"
                "    dead_threshold: float = 0.5\n"
                "    live_threshold: float = 0.5\n"
            ),
        )
        _write(
            tmp_path,
            "gate.py",
            (
                "def get_live(registry):\n"
                "    return registry.get('myns', 'live_threshold')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unread_config_key")
        dead_hits = [f for f in findings if "dead_threshold" in f.message]
        live_hits = [f for f in findings if "live_threshold" in f.message]
        assert dead_hits, findings
        assert not live_hits, findings

    def test_dynamic_family_covered_by_templated_read(
        self, tmp_path: Path,
    ) -> None:
        """A DynamicKeyFamily prefix is covered by an f-string prefix read.

        Mirrors bug #104's shape: the write side uses
        ``DynamicKeyFamily("calibration_threshold_", float)`` and the read
        side uses ``registry.get(ns, f"calibration_threshold_{outcome_kind}")``.
        The auditor must NOT flag the family in this shape.
        """
        _write(
            tmp_path,
            "schema.py",
            (
                "from typing import ClassVar\n"
                "class DynamicKeyFamily:\n"
                "    def __init__(self, prefix, value_type=str,"
                " default=None, description=''):\n"
                "        self.prefix = prefix\n"
                "FAMS = (DynamicKeyFamily('calibration_threshold_', float),)\n"
            ),
        )
        _write(
            tmp_path,
            "gate.py",
            (
                "def resolve(registry, outcome_kind):\n"
                "    return registry.get('platform',"
                " f'calibration_threshold_{outcome_kind}')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unread_config_key")
        assert not any(
            "calibration_threshold_" in f.message for f in findings
        ), findings

    def test_dynamic_family_never_read_is_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A DynamicKeyFamily with no read anywhere fires the rule.

        This is bug #104 verbatim: the promotion writer stores under the
        family prefix but no gate ever reads it.
        """
        _write(
            tmp_path,
            "schema.py",
            (
                "class DynamicKeyFamily:\n"
                "    def __init__(self, prefix, value_type=str, "
                "default=None, description=''):\n"
                "        self.prefix = prefix\n"
                "FAMS = (DynamicKeyFamily('unread_family_', float),)\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unread_config_key")
        assert any(
            "unread_family_" in f.message for f in findings
        ), findings

    def test_whitelist_suppresses_finding(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "schema.py",
            (
                "from pydantic import BaseModel\n"
                "class MyConfigSchema(BaseModel):\n"
                "    intentionally_dynamic_key: float = 0.5\n"
            ),
        )
        wl = tmp_path / "wl.py"
        wl.write_text(
            (
                "LIVENESS_WHITELIST = [\n"
                "    ('intentionally_dynamic_key', 'unread_config_key',"
                " 'read via operator-supplied key at runtime'),\n"
                "]\n"
            ),
            encoding="utf-8",
        )
        findings = _by_rule(_audit(tmp_path, wl), "unread_config_key")
        assert not any(
            "intentionally_dynamic_key" in f.message for f in findings
        ), findings


# ---------------------------------------------------------------------------
# R3 -- unwritten_column
# ---------------------------------------------------------------------------


class TestUnwrittenColumn:
    """Columns with writers are silent; columns without writers fire."""

    def test_written_column_is_not_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    live_amount: float = 0.0\n"
            ),
        )
        _write(
            tmp_path,
            "writer.py",
            (
                "def bump(record):\n"
                "    record.live_amount = record.live_amount + 1.0\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        assert not any(
            "live_amount" in f.message for f in findings
        ), findings

    def test_unwritten_column_is_flagged(self, tmp_path: Path) -> None:
        """Bug #135 shape: a SQLModel column with no writer anywhere."""
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    dead_amount: float = 0.0\n"
                "    live_amount: float = 0.0\n"
            ),
        )
        _write(
            tmp_path,
            "writer.py",
            (
                "def bump(record):\n"
                "    record.live_amount = record.live_amount + 1.0\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        dead_hits = [f for f in findings if "dead_amount" in f.message]
        live_hits = [f for f in findings if "live_amount" in f.message]
        assert dead_hits, findings
        assert not live_hits, findings

    def test_constructor_keyword_counts_as_a_write(
        self, tmp_path: Path,
    ) -> None:
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    label: str = ''\n"
            ),
        )
        _write(
            tmp_path,
            "factory.py",
            (
                "def make(WidgetRecord):\n"
                "    return WidgetRecord(label='hello')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        assert not any(
            "label" in f.message for f in findings
        ), findings

    def test_values_kwarg_counts_as_a_write(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    amount: float = 0.0\n"
            ),
        )
        _write(
            tmp_path,
            "updater.py",
            (
                "def bump(session, WidgetRecord):\n"
                "    session.exec(update(WidgetRecord).values(amount=1.0))\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        assert not any(
            "amount" in f.message for f in findings
        ), findings

    def test_server_default_column_is_excluded(self, tmp_path: Path) -> None:
        """A column whose only write is a Postgres ``server_default`` MUST
        not be flagged even without a Python-side writer."""
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    generated_at: str = Field(server_default='now()')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        assert not any(
            "generated_at" in f.message for f in findings
        ), findings

    def test_pk_and_fk_columns_are_excluded(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "db_models.py",
            (
                "from sqlmodel import Field, SQLModel\n"
                "class WidgetRecord(SQLModel, table=True):\n"
                "    id: int | None = Field(default=None, primary_key=True)\n"
                "    parent_id: int = Field(foreign_key='parents.id')\n"
            ),
        )
        findings = _by_rule(_audit(tmp_path), "unwritten_column")
        assert not any("parent_id" in f.message for f in findings), findings
        assert not any(
            f.message.endswith("WidgetRecord.id ") for f in findings
        ), findings
