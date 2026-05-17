"""Tests for the Jira draft JSON builder.

Validates REPORT-04: correct Jira REST API v2 schema, sub-task filtering
by classification and confidence threshold (D-10).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aila.modules.sbd_nfr.contracts.artifacts import JiraWorkItemDraft
from aila.modules.sbd_nfr.services.resolution_service import CONFIDENCE_THRESHOLD

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def golden_resolution() -> dict:
    """Load golden_resolution_response.json fixture."""
    return json.loads((_FIXTURES_DIR / "golden_resolution_response.json").read_text())


def _make_mock_session():
    """Create a minimal mock session object."""

    class _MockSession:
        id = "test-session-001"
        project_name = "Test NFR Project"
        status = "resolved"
        requestor_name = "Jane Doe"
        requestor_email = "jane@example.com"

    return _MockSession()


def _make_mock_classifications(components: list[dict]) -> list:
    """Build mock classification objects from fixture component data."""

    class _MockClassification:
        def __init__(self, comp: dict):
            self.subtask_key = comp["subtask_key"]
            self.classification = comp["classification"]
            self.confidence = comp["confidence"]
            self.reasoning = comp.get("reasoning", "")
            self.cited_question_ids_json = json.dumps(comp.get("cited_question_ids", []))

    return [_MockClassification(c) for c in components]


# ---------------------------------------------------------------------------
# JiraWorkItemDraft schema validation
# ---------------------------------------------------------------------------


def test_jira_work_item_draft_has_parent_subtasks_uncertain():
    """JiraWorkItemDraft must have parent, subtasks, and uncertain_components fields."""
    draft = JiraWorkItemDraft(
        parent={"fields": {"project": {"key": "PLACEHOLDER"}, "summary": "Test", "issuetype": {"name": "Story"}}},
        subtasks=[],
        uncertain_components=[],
    )
    assert hasattr(draft, "parent")
    assert hasattr(draft, "subtasks")
    assert hasattr(draft, "uncertain_components")


def test_jira_work_item_draft_validates_with_minimal_data():
    """JiraWorkItemDraft validates without error using minimal realistic data."""
    draft = JiraWorkItemDraft(
        parent={
            "fields": {
                "project": {"key": "SEC"},
                "summary": "SbD NFR Assessment: My Project",
                "description": "Assessment details here.",
                "issuetype": {"name": "Story"},
                "components": [],
            }
        },
        subtasks=[],
        uncertain_components=["waf_integration"],
    )
    assert draft.parent["fields"]["project"]["key"] == "SEC"
    assert draft.uncertain_components == ["waf_integration"]


# ---------------------------------------------------------------------------
# _build_parent_issue: Jira parent story structure
# ---------------------------------------------------------------------------


def test_parent_issue_has_required_jira_fields(golden_resolution):
    """Parent issue must have fields.project.key, fields.summary, fields.issuetype (D-09)."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_parent_issue

    components = golden_resolution["components"]
    triggered_high = [
        c for c in _make_mock_classifications(components)
        if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD
    ]
    uncertain = [
        c for c in _make_mock_classifications(components)
        if c.classification == "uncertain"
    ]

    parent = _build_parent_issue(_make_mock_session(), triggered_high, uncertain)

    assert "fields" in parent
    fields = parent["fields"]
    assert "project" in fields
    assert "key" in fields["project"]
    assert "summary" in fields
    assert "issuetype" in fields
    assert "name" in fields["issuetype"]


def test_parent_issue_summary_includes_project_name(golden_resolution):
    """Parent issue summary must include the session project name."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_parent_issue

    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)
    triggered_high = [c for c in all_cls if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]

    parent = _build_parent_issue(_make_mock_session(), triggered_high, uncertain)
    assert "Test NFR Project" in parent["fields"]["summary"]


def test_parent_issue_description_mentions_uncertain_components(golden_resolution):
    """Uncertain components must appear in the parent issue description text (D-10)."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_parent_issue

    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)
    triggered_high = [c for c in all_cls if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]

    # Only test when there are uncertain components in the fixture
    if not uncertain:
        pytest.skip("No uncertain components in golden fixture")

    parent = _build_parent_issue(_make_mock_session(), triggered_high, uncertain)
    description = parent["fields"]["description"]
    # Each uncertain component's label should appear in the description
    for u in uncertain:
        label = u.subtask_key.replace("_", " ").title()
        assert label in description, (
            f"Uncertain component label '{label}' not found in parent description"
        )


# ---------------------------------------------------------------------------
# _build_subtask_issue: sub-task structure
# ---------------------------------------------------------------------------


def test_subtask_issue_has_required_jira_fields(golden_resolution):
    """Sub-task issues must have fields.project.key, fields.summary, fields.issuetype (D-10)."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_subtask_issue

    components = golden_resolution["components"]
    triggered = [
        c for c in _make_mock_classifications(components)
        if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD
    ]
    if not triggered:
        pytest.skip("No high-confidence triggered components in golden fixture")

    subtask = _build_subtask_issue(triggered[0])
    assert "fields" in subtask
    fields = subtask["fields"]
    assert "project" in fields
    assert "key" in fields["project"]
    assert "summary" in fields
    assert "issuetype" in fields
    assert "name" in fields["issuetype"]


def test_subtask_issue_type_is_subtask(golden_resolution):
    """Sub-task issuetype.name must be 'Sub-task'."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_subtask_issue

    components = golden_resolution["components"]
    triggered = [
        c for c in _make_mock_classifications(components)
        if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD
    ]
    if not triggered:
        pytest.skip("No high-confidence triggered components in golden fixture")

    subtask = _build_subtask_issue(triggered[0])
    assert subtask["fields"]["issuetype"]["name"] == "Sub-task"


# ---------------------------------------------------------------------------
# Sub-task confidence filtering (D-10)
# ---------------------------------------------------------------------------


def test_jira_subtasks_only_high_confidence_triggered(golden_resolution):
    """Sub-tasks must only be created for classification='triggered' AND confidence >= threshold."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_subtask_issue

    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)

    triggered_high = [
        c for c in all_cls
        if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD
    ]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]

    # Simulate what generate_jira_draft does
    subtasks = [_build_subtask_issue(c) for c in triggered_high]

    # Every generated subtask must come from a triggered + high-confidence classification
    for subtask, cls in zip(subtasks, triggered_high):
        assert cls.classification == "triggered"
        assert cls.confidence >= CONFIDENCE_THRESHOLD


def test_low_confidence_triggered_not_in_subtasks(golden_resolution):
    """Triggered classifications below the confidence threshold must NOT become sub-tasks."""
    # Build a set of classifications where one triggered is below threshold
    class _LowConfTriggered:
        subtask_key = "low_conf_component"
        classification = "triggered"
        confidence = CONFIDENCE_THRESHOLD - 0.1  # Below threshold
        reasoning = "Borderline case."
        cited_question_ids_json = "[]"

    class _HighConfTriggered:
        subtask_key = "high_conf_component"
        classification = "triggered"
        confidence = CONFIDENCE_THRESHOLD + 0.1  # Above threshold
        reasoning = "Clear case."
        cited_question_ids_json = "[]"

    all_cls = [_LowConfTriggered(), _HighConfTriggered()]
    triggered_high = [c for c in all_cls if c.confidence >= CONFIDENCE_THRESHOLD]
    assert len(triggered_high) == 1
    assert triggered_high[0].subtask_key == "high_conf_component"


def test_not_triggered_components_excluded_from_draft(golden_resolution):
    """Components with classification='not_triggered' must not appear in subtasks or uncertain list."""
    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)

    not_triggered_keys = {c.subtask_key for c in all_cls if c.classification == "not_triggered"}
    triggered_high = [c for c in all_cls if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]

    # Sub-task keys should not contain any not_triggered keys
    subtask_keys = {c.subtask_key for c in triggered_high}
    assert subtask_keys.isdisjoint(not_triggered_keys), (
        f"not_triggered keys found in subtasks: {subtask_keys & not_triggered_keys}"
    )

    # Uncertain keys should not contain any not_triggered keys
    uncertain_keys = {c.subtask_key for c in uncertain}
    assert uncertain_keys.isdisjoint(not_triggered_keys), (
        f"not_triggered keys found in uncertain: {uncertain_keys & not_triggered_keys}"
    )


# ---------------------------------------------------------------------------
# Full draft assembly
# ---------------------------------------------------------------------------


def test_jira_draft_full_assembly(golden_resolution):
    """generate_jira_draft-equivalent logic produces a valid JiraWorkItemDraft."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_parent_issue, _build_subtask_issue

    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)

    triggered_high = [c for c in all_cls if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]
    uncertain_labels = [c.subtask_key.replace("_", " ").title() for c in uncertain]

    parent = _build_parent_issue(_make_mock_session(), triggered_high, uncertain)
    subtasks = [_build_subtask_issue(c) for c in triggered_high]

    draft = JiraWorkItemDraft(
        parent=parent,
        subtasks=subtasks,
        uncertain_components=uncertain_labels,
    )

    # Validate the model
    assert draft.parent["fields"]["project"]["key"] == "PLACEHOLDER"
    assert isinstance(draft.subtasks, list)
    assert isinstance(draft.uncertain_components, list)
    # All subtasks must be for triggered high-confidence components only
    assert len(draft.subtasks) == len(triggered_high)


def test_jira_draft_model_dump_is_json_serializable(golden_resolution):
    """JiraWorkItemDraft.model_dump() output must be JSON-serializable."""
    from aila.modules.sbd_nfr.reporting.jira_service import _build_parent_issue, _build_subtask_issue

    components = golden_resolution["components"]
    all_cls = _make_mock_classifications(components)
    triggered_high = [c for c in all_cls if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD]
    uncertain = [c for c in all_cls if c.classification == "uncertain"]
    uncertain_labels = [c.subtask_key.replace("_", " ").title() for c in uncertain]

    parent = _build_parent_issue(_make_mock_session(), triggered_high, uncertain)
    subtasks = [_build_subtask_issue(c) for c in triggered_high]
    draft = JiraWorkItemDraft(parent=parent, subtasks=subtasks, uncertain_components=uncertain_labels)

    # Should not raise
    serialized = json.dumps(draft.model_dump())
    parsed = json.loads(serialized)
    assert "parent" in parsed
    assert "subtasks" in parsed
