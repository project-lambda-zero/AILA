"""Parity test: SynthesisAgent produces valid RunSummaryReview via AilaLLMClient.

Verifies that the StructuredAgent -> AilaLLMClient pipeline produces
structurally valid RunSummaryReview output, matching the pre-migration baseline.

Uses real API calls (gpt-4o-mini via OpenRouter) -- marked @pytest.mark.integration.
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.contracts.scoring import RunSummaryReview
from aila.platform.routing.agent import StructuredAgent


@pytest.mark.integration
class TestSynthesisParity:
    """Verify synthesis agent produces valid structured output via AilaLLMClient."""

    @pytest.mark.asyncio
    async def test_run_summary_review_structure(self, llm_client) -> None:
        """StructuredAgent.run_structured() returns a valid RunSummaryReview
        with 3-4 non-empty summary notes."""
        agent = StructuredAgent(
            model=llm_client,
            name="parity_synthesis",
            instructions=(
                "Write short run-summary notes for the Linux vulnerability report. "
                "Call out what drives the risk, where vendor fixes are missing, and what owners should do next. "
                "Use only the payload facts. No filler."
            ),
            response_model=RunSummaryReview,
        )

        task = (
            "Write 3 to 4 short report notes.\n"
            "Each note must say what drives the risk, where fixes are missing, or what the owner should do next.\n"
            "Use plain language grounded in the payload. Do not restate scoring math. Do not invent evidence.\n"
            "Each note must be one sentence under 180 characters.\n"
            "Payload:\n"
            '{"summary":{"total_integrations":3,"total_packages_observed":412,'
            '"total_findings":17,"immediate":3,"high":5,"moderate":7,"planned":2},'
            '"scoring_mode":"model","scoring_counts":{"model":17,"cache":0},'
            '"host_summaries":[{"host":"10.0.1.5","system_name":"ubuntu-web-01",'
            '"distribution":"Ubuntu 22.04","packages_observed":180,"immediate":2,"high":3,'
            '"moderate":2,"planned":0},{"host":"10.0.1.6","system_name":"arch-dev-01",'
            '"distribution":"Arch Linux","packages_observed":132,"immediate":1,"high":2,'
            '"moderate":3,"planned":1}],'
            '"top_findings":[{"host":"10.0.1.5","package_name":"xz-utils",'
            '"cve_id":"CVE-2024-3094","criticality":"Immediate","numeric_score":98.5,'
            '"fixed_version":"5.6.1+really5.4.5-1","vendor_statuses":["fixed"],'
            '"vendor_urgencies":["critical"],"vendor_fix_states":["released"],'
            '"facts":"CVSS 10.0, EPSS 0.97, KEV listed, SSH backdoor",'
            '"recommended_action":"Patch immediately"}],'
            '"no_fix_findings":[{"host":"10.0.1.6","package_name":"glibc",'
            '"cve_id":"CVE-2024-2961","criticality":"High",'
            '"vendor_fix_states":["not-affected"],'
            '"recommended_action":"Monitor vendor advisory"}]}'
        )

        result = await agent.run_structured(task=task, response_model=RunSummaryReview)

        # Structural validation
        assert isinstance(result, RunSummaryReview)
        assert isinstance(result.summary_notes, list)

        # Quality check: 2-6 notes, each non-empty
        assert len(result.summary_notes) >= 2, f"Expected at least 2 notes, got {len(result.summary_notes)}"
        assert len(result.summary_notes) <= 6, f"Expected at most 6 notes, got {len(result.summary_notes)}"

        for note in result.summary_notes:
            assert isinstance(note, str)
            assert len(note) > 10, f"Note too short: {note!r}"
