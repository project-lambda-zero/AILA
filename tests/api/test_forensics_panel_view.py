"""Panel read route returns deliberation state, not only aggregate status."""
from __future__ import annotations

from uuid import uuid4

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as forensics_limiter
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationMessageRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsInvestigationOutcomeReviewRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


def _endpoint():
    for route in create_forensics_router().routes:
        if (
            getattr(route, "path", None)
            == "/projects/{project_id}/investigations/{investigation_id}/panel"
            and "GET" in (getattr(route, "methods", set()) or set())
        ):
            return route.endpoint
    raise AssertionError("panel read route not registered")


async def test_panel_view_includes_branches_votes_and_recent_tool_results(test_db) -> None:
    previous = forensics_limiter.enabled
    forensics_limiter.enabled = False
    suffix = uuid4().hex[:8]
    try:
        async with async_session_scope() as session:
            system = ManagedSystemRecord(
                name=f"analyzer-{suffix}", host=f"analyzer-{suffix}.test", username="examiner",
            )
            session.add(system)
            await session.flush()
            project = ForensicsProjectRecord(
                name=f"project-{suffix}", system_id=system.id, evidence_directory="/evidence",
            )
            session.add(project)
            await session.flush()
            inv = InvestigationRunRecord(project_id=project.id, question="How did it persist?")
            session.add(inv)
            await session.flush()
            halvar = ForensicsInvestigationBranchRecord(
                investigation_id=inv.id, persona_voice="halvar", status="completed", turn_count=4,
            )
            maddie = ForensicsInvestigationBranchRecord(
                investigation_id=inv.id, persona_voice="maddie", status="completed", turn_count=3,
            )
            session.add(halvar)
            session.add(maddie)
            await session.flush()
            outcome = ForensicsInvestigationOutcomeRecord(
                investigation_id=inv.id, branch_id=halvar.id,
                outcome_kind="forensic_answer", confidence="strong", state="dispatched",
                payload_json=(
                    '{"answer":"RunOnce launches updater.exe",'
                    '"provenance":{"primary_artifact":"/evidence/registry.txt"},'
                    '"panel_contributions":[{"persona":"halvar","confidence":"strong"}]}'
                ),
            )
            session.add(outcome)
            await session.flush()
            session.add(ForensicsInvestigationOutcomeReviewRecord(
                outcome_id=outcome.id, reviewer_branch_id=maddie.id,
                reviewer_persona="maddie", vote="approve", comment="registry value verified",
            ))
            session.add(ForensicsInvestigationMessageRecord(
                investigation_id=inv.id, branch_id=halvar.id,
                sender_kind="engine", payload_kind="tool_call", at_turn=2,
                payload_json=(
                    '{"text":"tool_run exit=0","action":"tool_run",'
                    '"command":"grep RunOnce /evidence/registry.txt",'
                    '"stdout":"updater.exe","exit_code":0}'
                ),
            ))
            await session.commit()
            project_id = project.id
            inv_id = inv.id

        envelope = await _endpoint()(
            request=object(), project_id=project_id, investigation_id=inv_id,
            auth=AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None),
        )

        assert [(b.persona_voice, b.turn_count) for b in envelope.data.branches] == [
            ("halvar", 4), ("maddie", 3),
        ]
        [outcome_view] = envelope.data.outcomes
        assert outcome_view.answer == "RunOnce launches updater.exe"
        assert outcome_view.provenance == {"primary_artifact": "/evidence/registry.txt"}
        assert outcome_view.contributions == [{"persona": "halvar", "confidence": "strong"}]
        assert [(r.reviewer_persona, r.vote, r.comment) for r in outcome_view.reviews] == [
            ("maddie", "approve", "registry value verified"),
        ]
        [message] = envelope.data.messages
        assert (message.persona_voice, message.stdout, message.exit_code) == (
            "halvar", "updater.exe", 0,
        )
    finally:
        forensics_limiter.enabled = previous
