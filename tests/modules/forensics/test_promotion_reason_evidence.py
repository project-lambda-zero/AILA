"""Lead reason evidence cites what was found, not what was asked.

``_build_reason`` is what the leads endpoint renders for every lead. A
keyword that appears only in the operator's question or requested answer
format must not be reported as matching evidence.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from aila.modules.forensics.workflow.states.promotion import _build_reason


def _summary(data: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_family="execution",
        artifact_type="investigation_summary",
        data_json=json.dumps(data),
    )


def test_keyword_only_in_question_or_answer_format_is_not_evidence() -> None:
    artifact = _summary({
        "question": "Is there a backdoor or persistence on this host?",
        "answer_format": "state whether malicious persistence exists",
        "answer": "No unexpected autoruns or services were found.",
    })

    reason, evidence = _build_reason(artifact, 50.0)

    assert evidence == []
    assert "matched at" not in reason


def test_keyword_in_answer_is_still_reported_as_evidence() -> None:
    artifact = _summary({
        "question": "Is there persistence on this host?",
        "answer": "A backdoor service was installed under an unsigned binary.",
    })

    _reason, evidence = _build_reason(artifact, 50.0)

    assert [(e["keyword"], e["path"]) for e in evidence] == [("backdoor", "answer")]
