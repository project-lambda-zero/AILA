"""Tests for LLMCostRecord schema validation (Phase 175 / D-01).

Verifies the table definition, field presence, defaults, and mixin
integration without requiring a live database connection.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone


class TestLLMCostRecordSchema:
    """LLMCostRecord has all required fields per D-01."""

    def _get_model(self):
        from aila.platform.llm.cost_record import LLMCostRecord
        return LLMCostRecord

    def test_table_name(self) -> None:
        """__tablename__ must be llm_cost_records."""
        model = self._get_model()
        assert model.__tablename__ == "llm_cost_records"

    def test_team_id_from_mixin(self) -> None:
        """team_id column comes from TeamScopedMixin."""
        from aila.storage.mixins import TeamScopedMixin
        from aila.platform.llm.cost_record import LLMCostRecord
        assert issubclass(LLMCostRecord, TeamScopedMixin)
        # team_id must be accessible on the model
        record = LLMCostRecord(model_id="gpt-4o")
        assert hasattr(record, "team_id")
        assert record.team_id is None  # nullable default

    def test_has_run_id(self) -> None:
        """run_id field exists with _no_run default."""
        model = self._get_model()
        fields = model.model_fields
        assert "run_id" in fields
        record = model(model_id="gpt-4o")
        assert record.run_id == "_no_run"

    def test_has_model_id(self) -> None:
        """model_id field exists."""
        model = self._get_model()
        assert "model_id" in model.model_fields

    def test_has_task_type(self) -> None:
        """task_type field exists with empty string default."""
        model = self._get_model()
        assert "task_type" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.task_type == ""

    def test_has_prompt_tokens(self) -> None:
        """prompt_tokens field exists with 0 default."""
        model = self._get_model()
        assert "prompt_tokens" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.prompt_tokens == 0

    def test_has_completion_tokens(self) -> None:
        """completion_tokens field exists with 0 default."""
        model = self._get_model()
        assert "completion_tokens" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.completion_tokens == 0

    def test_has_cost_usd(self) -> None:
        """cost_usd field exists with 0.0 default."""
        model = self._get_model()
        assert "cost_usd" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.cost_usd == 0.0

    def test_has_human_cost_hours_nullable(self) -> None:
        """human_cost_hours is nullable (reserved for Plan 175-03)."""
        model = self._get_model()
        assert "human_cost_hours" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.human_cost_hours is None

    def test_has_human_cost_usd_nullable(self) -> None:
        """human_cost_usd is nullable (reserved for Plan 175-03)."""
        model = self._get_model()
        assert "human_cost_usd" in model.model_fields
        record = model(model_id="gpt-4o")
        assert record.human_cost_usd is None

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

    def test_table_args_has_composite_indexes(self) -> None:
        """__table_args__ includes composite indexes for run_id+model_id and team_id+created_at."""
        from sqlalchemy import Index
        model = self._get_model()
        table_args = model.__table_args__
        index_names = {idx.name for idx in table_args if isinstance(idx, Index)}
        assert "ix_llmcostrecord_run_id_model_id" in index_names
        assert "ix_llmcostrecord_team_created" in index_names
