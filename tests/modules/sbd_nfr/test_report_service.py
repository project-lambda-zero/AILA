"""Tests for the pre-meeting report service.

Validates REPORT-01 (requester + architect sections) and
REPORT-02 (citation format) using golden fixture data.

These are unit tests that validate model structure and prompt construction
helpers.  They do NOT call the real LLM — LLM integration is covered by
manual verification with a real API key.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aila.modules.sbd_nfr.contracts.artifacts import (
    ArchitectSection,
    ReportNarrativeResponse,
    RequesterSection,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def golden_resolution() -> dict:
    """Load golden_resolution_response.json fixture."""
    return json.loads((_FIXTURES_DIR / "golden_resolution_response.json").read_text())


@pytest.fixture
def golden_answers() -> list[dict]:
    """Load golden_session_answers.json fixture."""
    return json.loads((_FIXTURES_DIR / "golden_session_answers.json").read_text())


# ---------------------------------------------------------------------------
# REPORT-01: RequesterSection model structure
# ---------------------------------------------------------------------------


def test_requester_section_has_required_fields():
    """RequesterSection must have prep_checklist, scope_decisions_pending,
    supplier_details_needed, and timeline_expectations (REPORT-01 / D-03)."""
    section = RequesterSection()
    assert hasattr(section, "prep_checklist")
    assert hasattr(section, "scope_decisions_pending")
    assert hasattr(section, "supplier_details_needed")
    assert hasattr(section, "timeline_expectations")


def test_requester_section_default_types():
    """RequesterSection default field types match expected types (list, list, bool, str)."""
    section = RequesterSection()
    assert isinstance(section.prep_checklist, list)
    assert isinstance(section.scope_decisions_pending, list)
    assert isinstance(section.supplier_details_needed, bool)
    assert isinstance(section.timeline_expectations, str)


def test_requester_section_with_populated_data():
    """RequesterSection validates with realistic non-empty data."""
    section = RequesterSection(
        prep_checklist=["Architecture diagram", "Vendor contracts"],
        scope_decisions_pending=["Cloud region to be confirmed"],
        supplier_details_needed=True,
        timeline_expectations="Expect 3–4 week engagement given 12 triggered components.",
    )
    assert len(section.prep_checklist) == 2
    assert section.supplier_details_needed is True
    assert "3–4 week" in section.timeline_expectations


# ---------------------------------------------------------------------------
# REPORT-01: ArchitectSection model structure
# ---------------------------------------------------------------------------


def test_architect_section_has_required_fields():
    """ArchitectSection must have scope_analysis, gray_areas, triggered_subtasks,
    and risk_flags (REPORT-01 / D-04)."""
    section = ArchitectSection()
    assert hasattr(section, "scope_analysis")
    assert hasattr(section, "gray_areas")
    assert hasattr(section, "triggered_subtasks")
    assert hasattr(section, "risk_flags")


def test_architect_section_default_types():
    """ArchitectSection default field types match expected types (str, list, list, list)."""
    section = ArchitectSection()
    assert isinstance(section.scope_analysis, str)
    assert isinstance(section.gray_areas, list)
    assert isinstance(section.triggered_subtasks, list)
    assert isinstance(section.risk_flags, list)


def test_architect_section_gray_areas_structure():
    """ArchitectSection.gray_areas items must be dicts with component, reasoning, confidence."""
    section = ArchitectSection(
        gray_areas=[
            {"component": "waf_integration", "reasoning": "May not be needed for internal APIs", "confidence": "0.55"},
        ]
    )
    assert len(section.gray_areas) == 1
    item = section.gray_areas[0]
    assert "component" in item
    assert "reasoning" in item
    assert "confidence" in item


def test_architect_section_triggered_subtasks_structure():
    """ArchitectSection.triggered_subtasks items must be dicts with label, evidence, cited_questions."""
    section = ArchitectSection(
        triggered_subtasks=[
            {
                "label": "Network Segment Placement",
                "evidence": "External-facing service [SCOPE-01: External (APN; customer facing)]",
                "cited_questions": "SCOPE-01, NET-01",
            }
        ]
    )
    assert len(section.triggered_subtasks) == 1
    item = section.triggered_subtasks[0]
    assert "label" in item
    assert "evidence" in item
    assert "cited_questions" in item


# ---------------------------------------------------------------------------
# REPORT-01: ReportNarrativeResponse top-level structure
# ---------------------------------------------------------------------------


def test_report_narrative_response_has_required_fields():
    """ReportNarrativeResponse must have executive_summary, requester_section,
    architect_section (REPORT-01)."""
    response = ReportNarrativeResponse()
    assert hasattr(response, "executive_summary")
    assert hasattr(response, "requester_section")
    assert hasattr(response, "architect_section")


def test_report_narrative_response_default_types():
    """ReportNarrativeResponse fields have expected types (str, RequesterSection, ArchitectSection)."""
    response = ReportNarrativeResponse()
    assert isinstance(response.executive_summary, str)
    assert isinstance(response.requester_section, RequesterSection)
    assert isinstance(response.architect_section, ArchitectSection)


def test_report_narrative_response_validates_with_empty_defaults():
    """ReportNarrativeResponse with default values passes Pydantic validation without error."""
    response = ReportNarrativeResponse()
    dumped = response.model_dump()
    assert "executive_summary" in dumped
    assert "requester_section" in dumped
    assert "architect_section" in dumped


def test_report_narrative_response_validates_from_json():
    """ReportNarrativeResponse.model_validate_json() parses a realistic JSON payload."""
    payload = json.dumps({
        "executive_summary": "The project covers an external-facing SaaS platform [SCOPE-01: External (APN; customer facing)].",
        "requester_section": {
            "prep_checklist": ["Architecture diagram", "Vendor contracts"],
            "scope_decisions_pending": ["Container network policy finalisation"],
            "supplier_details_needed": True,
            "timeline_expectations": "Expect 3-4 weeks given 15 triggered components.",
        },
        "architect_section": {
            "scope_analysis": "The engagement covers 15 triggered SbD components [SCOPE-01: External].",
            "gray_areas": [
                {"component": "scs", "reasoning": "Vendor scope unclear", "confidence": "0.55"}
            ],
            "triggered_subtasks": [
                {
                    "label": "Network Segment Placement",
                    "evidence": "External service [SCOPE-01: External]",
                    "cited_questions": "SCOPE-01",
                }
            ],
            "risk_flags": ["External PII exposure requires DAST before go-live."],
        },
    })
    response = ReportNarrativeResponse.model_validate_json(payload)
    assert "external-facing SaaS" in response.executive_summary
    assert response.requester_section.supplier_details_needed is True
    assert len(response.architect_section.gray_areas) == 1
    assert len(response.architect_section.triggered_subtasks) == 1
    assert len(response.architect_section.risk_flags) == 1


# ---------------------------------------------------------------------------
# REPORT-02: Citation format validation
# ---------------------------------------------------------------------------

_CITATION_PATTERN = re.compile(r"\[[\w-]+:\s*.+?\]")


def test_citation_regex_matches_valid_patterns():
    """Citation regex must match well-formed [QUESTION-ID: answer_value] patterns."""
    valid_examples = [
        "The system is externally accessible [SCOPE-01: External (APN; customer facing)].",
        "Data is classified as PII [DATA-01: Yes].",
        "[NET-01: No] indicates DMZ placement has not been reviewed.",
        "Vendor integration confirmed [VENDOR-01: Yes] with third-party payment provider.",
    ]
    for text in valid_examples:
        matches = _CITATION_PATTERN.findall(text)
        assert matches, f"Expected citation match in: {text!r}"


def test_citation_regex_rejects_invalid_patterns():
    """Citation regex must NOT match malformed citation patterns."""
    invalid_examples = [
        "Plain text with no citations.",
        "[missing colon value]",
        "[: empty key]",
        "SCOPE-01: value without brackets",
    ]
    for text in invalid_examples:
        matches = _CITATION_PATTERN.findall(text)
        assert not matches, f"Unexpected citation match in: {text!r}"


def test_report_narrative_with_citations_validates():
    """A ReportNarrativeResponse built with citation strings passes validation and
    the citations are extractable by the citation regex."""
    summary_with_citations = (
        "The system is an external-facing service [SCOPE-01: External (APN; customer facing)] "
        "that stores PII [DATA-01: Yes] and integrates with third-party vendors [VENDOR-01: Yes]."
    )
    response = ReportNarrativeResponse(executive_summary=summary_with_citations)
    citations = _CITATION_PATTERN.findall(response.executive_summary)
    assert len(citations) == 3
    assert any("SCOPE-01" in c for c in citations)
    assert any("DATA-01" in c for c in citations)
    assert any("VENDOR-01" in c for c in citations)


# ---------------------------------------------------------------------------
# Prompt building helpers (non-LLM)
# ---------------------------------------------------------------------------


def test_build_report_system_prompt_contains_citation_instruction():
    """_build_report_system_prompt must include the citation format instruction."""
    from aila.modules.sbd_nfr.reporting.report_service import _build_report_system_prompt

    # Build a minimal mock session and classifications using simple objects
    class _MockSession:
        id = "test-session-001"
        project_name = "Test Project"
        description = None
        business_unit = "Engineering"
        requestor_name = "Jane Doe"
        requestor_email = "jane@example.com"
        status = "resolved"

    class _MockClassification:
        subtask_key = "network_segment_placement"
        classification = "triggered"
        confidence = 0.92
        reasoning = "External service requires DMZ placement."
        cited_question_ids_json = '["SCOPE-01", "NET-01"]'

    from aila.modules.sbd_nfr.services.config import SbdNfrConfig

    prompt = _build_report_system_prompt(
        session=_MockSession(),
        classifications=[_MockClassification()],
        answer_map={"SCOPE-01": "External (APN; customer facing)", "NET-01": "No"},
        config=SbdNfrConfig(),
    )
    assert "[QUESTION-ID: answer_value]" in prompt
    assert "CITATION REQUIREMENT" in prompt
    assert "Test Project" in prompt
    assert "network_segment_placement" in prompt


def test_build_report_user_message_contains_project_name():
    """_build_report_user_message must include the project name in the task description."""
    from aila.modules.sbd_nfr.reporting.report_service import _build_report_user_message

    class _MockSession:
        id = "test-session-001"
        project_name = "My Security Project"

    class _MockClassification:
        classification = "triggered"

    msg = _build_report_user_message(
        session=_MockSession(),
        classifications=[_MockClassification(), _MockClassification()],
        answer_map={"SCOPE-01": "External"},
    )
    assert "My Security Project" in msg
    assert "2" in msg  # triggered count
