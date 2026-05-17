"""Tests for RiskScoringAgent prior assessment retrieval and injection."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
from aila.modules.vulnerability.contracts import SignalAssessment


def _make_model():
    model = MagicMock()
    model.model_id = "test-model"
    return model


def _make_candidate(**kwargs):
    defaults = dict(
        system_id=1,
        system_name="test-system",
        host="test-host",
        distribution="arch",
        package_name="openssh",
        installed_version="9.0",
        cve_id="CVE-2024-1234",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    )
    defaults.update(kwargs)
    return ScoringCandidate(**defaults)


def _make_agent(retrieve_tool=None):
    model = _make_model()
    # policy_tool required for scoring but not for isolated _retrieve_prior_assessments
    policy_tool = MagicMock()
    agent = RiskScoringAgent(
        model=model,
        policy_tool=policy_tool,
        knowledge_retrieve_tool=retrieve_tool,
    )
    return agent


def _make_retrieve_tool(results=None, count=None, raise_exc=None):
    tool = MagicMock()
    tool.name = "knowledge_retrieve"
    if raise_exc is not None:
        tool.forward = AsyncMock(side_effect=raise_exc)
        return tool
    if results is None:
        results = []
    actual_count = count if count is not None else len(results)
    tool.forward = AsyncMock(return_value={
        "status": "retrieved",
        "count": actual_count,
        "results": results,
    })
    return tool


# ---------------------------------------------------------------------------
# _retrieve_prior_assessments
# ---------------------------------------------------------------------------

class TestRetrievePriorAssessments:
    @pytest.mark.asyncio
    async def test_returns_empty_when_tool_is_none(self):
        agent = _make_agent(retrieve_tool=None)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert result == ""

    @pytest.mark.asyncio
    async def test_returns_empty_when_results_all_below_threshold(self):
        low_results = [
            {"content": "low score result", "score": 0.3, "source": "platform"},
            {"content": "another low", "score": 0.49, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=low_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert result == ""

    @pytest.mark.asyncio
    async def test_returns_prefix_with_high_score_results(self):
        high_results = [
            {"content": "first good result", "score": 0.9, "source": "platform"},
            {"content": "second good result", "score": 0.7, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=high_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert result.startswith("Prior assessments for this package/CVE:")
        assert "- first good result" in result
        assert "- second good result" in result

    @pytest.mark.asyncio
    async def test_threshold_is_inclusive_at_0_5(self):
        exact_threshold = [
            {"content": "exactly at threshold", "score": 0.5, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=exact_threshold)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert "Prior assessments for this package/CVE:" in result
        assert "- exactly at threshold" in result

    @pytest.mark.asyncio
    async def test_returns_at_most_3_results(self):
        many_results = [
            {"content": f"result {i}", "score": 0.9, "source": "platform"}
            for i in range(6)
        ]
        tool = _make_retrieve_tool(results=many_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        # Only first 3 results included
        assert "- result 0" in result
        assert "- result 1" in result
        assert "- result 2" in result
        assert "- result 3" not in result

    @pytest.mark.asyncio
    async def test_content_truncated_to_300_chars(self):
        long_content = "x" * 400
        tool = _make_retrieve_tool(results=[{"content": long_content, "score": 0.9, "source": "platform"}])
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert "x" * 300 in result
        assert "x" * 301 not in result

    @pytest.mark.asyncio
    async def test_returns_empty_on_tool_exception(self):
        tool = _make_retrieve_tool(raise_exc=RuntimeError("vector store unavailable"))
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()
        result = await agent._retrieve_prior_assessments(candidate)
        assert result == ""

    @pytest.mark.asyncio
    async def test_query_uses_package_cve_host(self):
        tool = _make_retrieve_tool(results=[])
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate(package_name="curl", cve_id="CVE-2023-9999", host="prod-server")
        await agent._retrieve_prior_assessments(candidate)
        tool.forward.assert_called_once()
        call_kwargs = tool.forward.call_args
        assert "curl" in str(call_kwargs)
        assert "CVE-2023-9999" in str(call_kwargs)
        assert "prod-server" in str(call_kwargs)


# ---------------------------------------------------------------------------
# _analyze_candidate with prior context injection
# ---------------------------------------------------------------------------

class TestAnalyzeCandidateWithPriorContext:
    def _make_signal_assessment(self):
        return SignalAssessment(
            exposure="internal_segmented",
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
            cve_detail_commentary="commentary text",
            environment_commentary="env text",
            operator_guidance="guidance text",
        )

    @pytest.mark.asyncio
    async def test_task_contains_prior_context_when_results_above_threshold(self):
        high_results = [
            {"content": "good prior assessment", "score": 0.85, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=high_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()

        captured_tasks = []

        async def mock_run_structured(task, response_model):
            captured_tasks.append(task)
            return self._make_signal_assessment()

        agent.run_structured = mock_run_structured

        await agent._analyze_candidate(candidate)
        assert len(captured_tasks) == 1
        assert "Prior assessments for this package/CVE:" in captured_tasks[0]
        assert "good prior assessment" in captured_tasks[0]

    @pytest.mark.asyncio
    async def test_task_does_not_contain_prior_context_when_all_below_threshold(self):
        low_results = [
            {"content": "low quality result", "score": 0.2, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=low_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()

        captured_tasks = []

        async def mock_run_structured(task, response_model):
            captured_tasks.append(task)
            return self._make_signal_assessment()

        agent.run_structured = mock_run_structured

        await agent._analyze_candidate(candidate)
        assert len(captured_tasks) == 1
        assert "Prior assessments" not in captured_tasks[0]

    @pytest.mark.asyncio
    async def test_no_crash_when_retrieve_tool_is_none(self):
        agent = _make_agent(retrieve_tool=None)
        candidate = _make_candidate()

        async def mock_run_structured(task, response_model):
            return self._make_signal_assessment()

        agent.run_structured = mock_run_structured

        # Should not raise
        result = await agent._analyze_candidate(candidate)
        assert result is not None

    @pytest.mark.asyncio
    async def test_scoring_continues_when_retrieve_raises(self):
        tool = _make_retrieve_tool(raise_exc=ConnectionError("network down"))
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()

        async def mock_run_structured(task, response_model):
            return self._make_signal_assessment()

        agent.run_structured = mock_run_structured

        # Should not raise — retrieval failure is silently swallowed
        result = await agent._analyze_candidate(candidate)
        assert result is not None

    @pytest.mark.asyncio
    async def test_prior_context_prepended_with_double_newline_separator(self):
        high_results = [
            {"content": "prior note", "score": 0.9, "source": "platform"},
        ]
        tool = _make_retrieve_tool(results=high_results)
        agent = _make_agent(retrieve_tool=tool)
        candidate = _make_candidate()

        captured_tasks = []

        async def mock_run_structured(task, response_model):
            captured_tasks.append(task)
            return self._make_signal_assessment()

        agent.run_structured = mock_run_structured

        await agent._analyze_candidate(candidate)
        task_text = captured_tasks[0]
        prior_end = task_text.index("Prior assessments for this package/CVE:")
        # The separator \n\n must appear between prior context and original task
        assert "\n\n" in task_text[prior_end:]
