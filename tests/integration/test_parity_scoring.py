"""Parity test: RiskScoringAgent produces valid SignalAssessment via AilaLLMClient.

Verifies that the StructuredAgent -> AilaLLMClient pipeline produces
structurally valid SignalAssessment output, matching the pre-migration baseline.

Uses real API calls (gpt-4o-mini via OpenRouter) -- marked @pytest.mark.integration.
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.contracts.scoring import SignalAssessment
from aila.platform.routing.agent import StructuredAgent


@pytest.mark.integration
class TestScoringParity:
    """Verify scoring agent produces valid structured output via AilaLLMClient."""

    @pytest.mark.asyncio
    async def test_signal_assessment_structure(self, llm_client) -> None:
        """StructuredAgent.run_structured() returns a valid SignalAssessment
        with all required fields populated."""
        agent = StructuredAgent(
            model=llm_client,
            name="parity_scoring",
            instructions=(
                "You are the criticality scoring specialist. "
                "Use the supplied policy signals and host evidence to produce concrete operator commentary. "
                "Do not invent environment details or exploit claims."
            ),
            response_model=SignalAssessment,
        )

        task = (
            "Assess this vulnerability for patching urgency.\n"
            "Package: xz-utils, CVE: CVE-2024-3094, Host: ubuntu-web-01\n"
            "CVSS: 10.0, EPSS: 0.97, KEV: true\n"
            "Distribution: Ubuntu 22.04 LTS, internet-facing web server\n"
            "Fixed version: 5.6.1+really5.4.5-1\n"
            "Vendor status: fixed, urgency: critical\n"
            "Note: xz-utils backdoor allowing SSH authentication bypass\n"
            "Return JSON fields: exposure, mitigating_control_present, detection_present, "
            "poc_available, cve_detail_commentary, environment_commentary, operator_guidance"
        )

        result = await agent.run_structured(task=task, response_model=SignalAssessment)

        # Structural validation -- must be a valid SignalAssessment
        assert isinstance(result, SignalAssessment)
        assert result.exposure in (
            "unknown",
            "internet_facing",
            "partner_exposed",
            "internal_flat_network",
            "internal_segmented",
            "isolated",
        )
        assert isinstance(result.mitigating_control_present, bool)
        assert isinstance(result.detection_present, bool)
        assert isinstance(result.poc_available, bool)

        # Commentary fields must be non-empty strings
        assert len(result.cve_detail_commentary) > 10
        assert len(result.environment_commentary) > 10
        assert len(result.operator_guidance) > 10
