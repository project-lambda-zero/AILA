"""Tests for LLMCostRecord schema validation (Phase 175 / D-01).

Verifies the table definition, field presence, defaults, and mixin
integration without requiring a live database connection.
"""

from __future__ import annotations

from datetime import datetime


class TestLLMCostRecordSchema:
    """LLMCostRecord has all required fields per D-01."""

    def _get_model(self):
        from aila.platform.llm.cost_record import LLMCostRecord
        return LLMCostRecord


    def test_has_created_at(self) -> None:
        """created_at field exists and auto-populates."""
        model = self._get_model()
        assert "created_at" in model.model_fields
        record = model(model_id="gpt-4o")
        assert isinstance(record.created_at, datetime)

    def test_id_is_uuid_string(self) -> None:
        """id is auto-generated UUID string primary key."""
        model = self._get_model()
        record1 = model(model_id="m1")
        record2 = model(model_id="m2")
        assert isinstance(record1.id, str)
        assert len(record1.id) == 36  # UUID format
        assert record1.id != record2.id  # unique per instance

    def test_full_construction(self) -> None:
        """Can construct a fully populated record."""
        model = self._get_model()
        record = model(
            run_id="run-123",
            model_id="gpt-4o",
            task_type="scoring",
            team_id="team-abc",
            prompt_tokens=1000,
            completion_tokens=500,
            cost_usd=0.0125,
            human_cost_hours=2.5,
            human_cost_usd=375.0,
        )
        assert record.run_id == "run-123"
        assert record.model_id == "gpt-4o"
        assert record.task_type == "scoring"
        assert record.team_id == "team-abc"
        assert record.prompt_tokens == 1000
        assert record.completion_tokens == 500
        assert record.cost_usd == 0.0125
        assert record.human_cost_hours == 2.5
        assert record.human_cost_usd == 375.0

