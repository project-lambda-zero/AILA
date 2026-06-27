"""Tests for knowledge tool wiring in RiskScoringAgent and SynthesisAgent.

Covers:
- Task 1: knowledge_store_tool / knowledge_retrieve_tool params on both agents
- Task 2: VulnerabilityModule.build_runtime wires per-agent tool instances with correct namespaces
"""
from __future__ import annotations

from unittest.mock import MagicMock, create_autospec, patch

from aila.platform.tools.knowledge import KnowledgeRetrieveTool, KnowledgeStoreTool

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scoring_evidence(source: str = "model"):
    from aila.modules.vulnerability.agents.scoring.policy import ScoringEvidence
    return ScoringEvidence(
        exposure="unknown",
        severity_level="medium",
        patch_available=False,
        mitigating_control_present=False,
        detection_present=False,
        poc_available=False,
        epss_component=0,
        kev_component=0,
        exposure_component=0,
        exploitability_component=0,
        severity_component=0,
        control_gap_component=0,
        weighted_score=50,
        base_category="Moderate",
        final_category="High",
        hard_minimum_category="Moderate",
        policy_category="Moderate",
        agent_review_enabled=True,
        signal_analysis_source=source,
        scoring_mode=source,
        advisory_provenance="advisory",
        intel_provenance="intel",
    )


def _make_mock_model():
    model = MagicMock()
    model.model_id = "test-model"
    return model


def _make_mock_store_tool():
    tool = create_autospec(KnowledgeStoreTool, instance=True)
    tool.name = "knowledge_store"
    tool.forward.return_value = {
        "status": "stored",
        "operation": "inserted",
        "entry_id": 1,
    }
    return tool


def _make_mock_retrieve_tool():
    tool = create_autospec(KnowledgeRetrieveTool, instance=True)
    tool.name = "knowledge_retrieve"
    tool.forward.return_value = {"results": []}
    return tool


# ---------------------------------------------------------------------------
# Task 1 tests: RiskScoringAgent knowledge params
# ---------------------------------------------------------------------------


class TestRiskScoringAgentKnowledgeParams:
    def test_constructed_with_no_knowledge_tools(self):
        """RiskScoringAgent constructed without knowledge tools must not raise."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_store_tool=None,
            knowledge_retrieve_tool=None,
        )
        assert agent.knowledge_store_tool is None
        assert agent.knowledge_retrieve_tool is None

    def test_knowledge_store_tool_stored_on_self(self):
        """knowledge_store_tool kwarg is stored as self.knowledge_store_tool."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        mock_store = _make_mock_store_tool()
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_store_tool=mock_store,
        )
        assert agent.knowledge_store_tool is mock_store

    def test_knowledge_retrieve_tool_stored_on_self(self):
        """knowledge_retrieve_tool kwarg is stored as self.knowledge_retrieve_tool."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        mock_retrieve = _make_mock_retrieve_tool()
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_retrieve_tool=mock_retrieve,
        )
        assert agent.knowledge_retrieve_tool is mock_retrieve

    def test_store_signal_called_on_model_path(self):
        """_store_signal_to_knowledge is called when signal_source == 'model'."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        from aila.modules.vulnerability.contracts import SignalAssessment

        mock_store = _make_mock_store_tool()
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_store_tool=mock_store,
        )

        # Build a minimal candidate using ScoringCandidate
        from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
        candidate = ScoringCandidate(
            system_id=1,
            system_name="web-01",
            host="web-01.example.com",
            distribution="debian",
            package_name="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2024-0001",
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            fixed_version=None,
        )
        assessment = SignalAssessment(
            cve_detail_commentary="Critical RCE.",
            environment_commentary="Exposed to internet.",
            operator_guidance="Patch immediately.",
            exposure="internet_facing",
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
        )

        agent._store_signal_to_knowledge(candidate, assessment)

        mock_store.forward.assert_called_once()
        call_kwargs = mock_store.forward.call_args[1] if mock_store.forward.call_args[1] else mock_store.forward.call_args[0]
        # Accept both positional and keyword calling
        if isinstance(call_kwargs, tuple):
            content = call_kwargs[0]
            metadata = call_kwargs[1]
        else:
            content = call_kwargs.get("content", mock_store.forward.call_args[0][0] if mock_store.forward.call_args[0] else None)
            metadata = call_kwargs.get("metadata", mock_store.forward.call_args[0][1] if len(mock_store.forward.call_args[0]) > 1 else None)

        assert "openssl" in content
        assert "CVE-2024-0001" in content

    def test_dedup_key_present_in_metadata(self):
        """knowledge_store_tool.forward receives _dedup_key in metadata dict."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
        from aila.modules.vulnerability.contracts import SignalAssessment

        mock_store = _make_mock_store_tool()
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_store_tool=mock_store,
        )
        candidate = ScoringCandidate(
            system_id=1,
            system_name="web-01",
            host="web-01.example.com",
            distribution="debian",
            package_name="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2024-0001",
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            fixed_version=None,
        )
        assessment = SignalAssessment(
            cve_detail_commentary="Critical RCE.",
            environment_commentary="Exposed to internet.",
            operator_guidance="Patch immediately.",
            exposure="internet_facing",
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
        )
        agent._store_signal_to_knowledge(candidate, assessment)

        _, kwargs = mock_store.forward.call_args
        metadata = kwargs.get("metadata") or (mock_store.forward.call_args[0][1] if len(mock_store.forward.call_args[0]) > 1 else None)
        assert metadata is not None
        assert "_dedup_key" in metadata
        assert metadata["_dedup_key"] == "openssl:CVE-2024-0001:web-01.example.com"

    def test_store_signal_skips_when_tool_is_none(self):
        """_store_signal_to_knowledge does not raise when knowledge_store_tool is None."""
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent
        from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
        from aila.modules.vulnerability.contracts import SignalAssessment

        agent = RiskScoringAgent(model=_make_mock_model())
        candidate = ScoringCandidate(
            system_id=1,
            system_name="web-01",
            host="web-01.example.com",
            distribution="debian",
            package_name="openssl",
            installed_version="1.1.1",
            cve_id="CVE-2024-0001",
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            fixed_version=None,
        )
        assessment = SignalAssessment(
            cve_detail_commentary="Critical RCE.",
            environment_commentary="Exposed.",
            operator_guidance="Patch.",
            exposure="internet_facing",
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
        )
        # Must not raise
        agent._store_signal_to_knowledge(candidate, assessment)

    def test_store_not_called_on_cache_path(self):
        """_store_signal_to_knowledge is NOT called when signal comes from cache.

        Verifies the conditional in _score_one_candidate:
        _store_signal_to_knowledge is only invoked after _analyze_candidate (model path),
        never on the cache path where load_cached_signal_assessment returns a non-None value.
        """
        from aila.modules.vulnerability.agents.scoring.agent import RiskScoringAgent

        mock_store = _make_mock_store_tool()
        agent = RiskScoringAgent(
            model=_make_mock_model(),
            knowledge_store_tool=mock_store,
        )

        # Patch _store_signal_to_knowledge itself so we can assert call count
        with patch.object(agent, "_store_signal_to_knowledge") as mock_store_signal, \
             patch.object(agent, "_store_cached_signal_assessment"), \
             patch(
                 "aila.modules.vulnerability.agents.scoring.agent.load_cached_signal_assessment",
                 return_value=MagicMock(),  # cache hit -- signal_source = "cache"
             ), \
             patch.object(agent, "_analyze_candidate", side_effect=AssertionError("must not call model")), \
             patch(
                 "aila.modules.vulnerability.agents.scoring.agent.calculate_score_breakdown",
                 return_value=MagicMock(final_category="High", weighted_score=75),
             ), \
             patch(
                 "aila.modules.vulnerability.agents.scoring.agent.build_scoring_evidence",
                 return_value=_make_scoring_evidence("cache"),
             ), \
             patch(
                 "aila.modules.vulnerability.agents.scoring.agent.build_report_sections",
                 return_value=("facts", "inference", "action", "uncertainty"),
             ), \
             patch(
                 "aila.modules.vulnerability.agents.scoring.agent.build_rationale",
                 return_value="rationale",
             ):
            from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
            candidate = ScoringCandidate(
                system_id=1,
                system_name="web-01",
                host="web-01.example.com",
                distribution="debian",
                package_name="openssl",
                installed_version="1.1.1",
                cve_id="CVE-2024-0001",
                nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                fixed_version=None,
            )
            mock_policy = MagicMock()
            mock_policy.category_rank = {}
            agent._score_one_candidate(candidate, mock_policy)

        # _store_signal_to_knowledge must NOT have been called on the cache path
        mock_store_signal.assert_not_called()


# ---------------------------------------------------------------------------
# Task 1 tests: SynthesisAgent knowledge params
# ---------------------------------------------------------------------------


class TestSynthesisAgentKnowledgeParams:
    def test_constructed_with_no_knowledge_tools(self):
        """SynthesisAgent constructed without knowledge tools must not raise."""
        from aila.modules.vulnerability.agents.synthesis.agent import SynthesisAgent

        report_builder = MagicMock()
        agent = SynthesisAgent(
            report_builder=report_builder,
            model=_make_mock_model(),
            knowledge_store_tool=None,
            knowledge_retrieve_tool=None,
        )
        assert agent.knowledge_store_tool is None
        assert agent.knowledge_retrieve_tool is None

    def test_knowledge_store_tool_stored_on_self(self):
        """SynthesisAgent stores knowledge_store_tool on self."""
        from aila.modules.vulnerability.agents.synthesis.agent import SynthesisAgent

        mock_store = _make_mock_store_tool()
        agent = SynthesisAgent(
            report_builder=MagicMock(),
            model=_make_mock_model(),
            knowledge_store_tool=mock_store,
        )
        assert agent.knowledge_store_tool is mock_store

    def test_knowledge_retrieve_tool_stored_on_self(self):
        """SynthesisAgent stores knowledge_retrieve_tool on self."""
        from aila.modules.vulnerability.agents.synthesis.agent import SynthesisAgent

        mock_retrieve = _make_mock_retrieve_tool()
        agent = SynthesisAgent(
            report_builder=MagicMock(),
            model=_make_mock_model(),
            knowledge_retrieve_tool=mock_retrieve,
        )
        assert agent.knowledge_retrieve_tool is mock_retrieve


# ---------------------------------------------------------------------------
# Task 2 tests: VulnerabilityModule.build_runtime namespace wiring
# ---------------------------------------------------------------------------


class TestVulnerabilityModuleKnowledgeWiring:
    def test_build_runtime_constructs_scoring_knowledge_store_with_correct_namespace(self):
        """build_runtime creates KnowledgeStoreTool with namespace='RiskScoringAgent'."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        module = VulnerabilityModule()
        mock_context = _make_mock_context()

        with patch("aila.modules.vulnerability.module.KnowledgeStoreTool") as MockStore, \
             patch("aila.modules.vulnerability.module.KnowledgeRetrieveTool") as MockRetrieve, \
             patch("aila.modules.vulnerability.module.build_platform_settings") as mock_bps:
            mock_bps.return_value = MagicMock()
            MockStore.return_value = _make_mock_store_tool()
            MockRetrieve.return_value = _make_mock_retrieve_tool()
            module.build_runtime(mock_context)

        # Collect all calls and their namespace kwargs/args
        store_calls = MockStore.call_args_list
        namespaces = [_extract_namespace(c) for c in store_calls]
        assert "RiskScoringAgent" in namespaces

    def test_build_runtime_constructs_synthesis_knowledge_store_with_correct_namespace(self):
        """build_runtime creates KnowledgeStoreTool with namespace='SynthesisAgent'."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        module = VulnerabilityModule()
        mock_context = _make_mock_context()

        with patch("aila.modules.vulnerability.module.KnowledgeStoreTool") as MockStore, \
             patch("aila.modules.vulnerability.module.KnowledgeRetrieveTool") as MockRetrieve, \
             patch("aila.modules.vulnerability.module.build_platform_settings") as mock_bps:
            mock_bps.return_value = MagicMock()
            MockStore.return_value = _make_mock_store_tool()
            MockRetrieve.return_value = _make_mock_retrieve_tool()
            module.build_runtime(mock_context)

        store_calls = MockStore.call_args_list
        namespaces = [_extract_namespace(c) for c in store_calls]
        assert "SynthesisAgent" in namespaces


# ---------------------------------------------------------------------------
# Test utilities
# ---------------------------------------------------------------------------


def _extract_namespace(call):
    """Extract namespace from a MagicMock call_args (positional or keyword)."""
    args, kwargs = call
    if "namespace" in kwargs:
        return kwargs["namespace"]
    if args:
        return args[0]
    return None


def _make_mock_context():
    """Build a minimal ModuleContext mock for build_runtime testing."""
    context = MagicMock()
    context.settings = MagicMock()
    context.runtime_model = _make_mock_model()
    context.config_registry = None

    # tool_registry.require(...) returns a MagicMock for any key
    context.tool_registry.require.return_value = MagicMock()

    return context
