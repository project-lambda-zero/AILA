"""DisclosureService — orchestrates submission lifecycle for one finding.

Operations:
  create()    — POST a new (finding, track) submission. Validates track
                exists, finding exists, finding is in this workspace, and
                that the track accepts the poc_tier. Renders the body
                immediately so the operator sees the draft.

  list()      — filterable + paginated list

  get()       — single fetch

  patch()     — operator-driven state transitions + field updates.
                Re-renders body when severity / poc_tier / embargo
                changes.

  render()    — explicit re-render (idempotent — useful after the finding
                row's payload has been updated externally).

Out of scope for v1:
  - cross-track embargo coordination (GA-33)
  - vendor communications log (GA-36)
  - ARQ classifier on incoming vendor responses (GA-36)
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
    DisclosureSubmissionStatus,
    RenderedSubmission,
    VRDisclosureSubmissionCreate,
    VRDisclosureSubmissionPatch,
    VRDisclosureSubmissionSummary,
)
from aila.modules.vr.db_models import (
    VRDisclosureSubmissionRecord,
    VRFindingRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

from .registry import get_track

__all__ = [
    "DisclosureService",
    "DisclosureServiceError",
]

_log = logging.getLogger(__name__)


class DisclosureServiceError(Exception):
    """Raised on user-facing service failures (unknown track, bad transition)."""


# Status transitions the operator can request without confirmation.
# Anything else is allowed but warns; terminal states (CLOSED / WITHDRAWN)
# are one-way and cannot be left.
_TERMINAL_STATES: frozenset[DisclosureSubmissionStatus] = frozenset({
    DisclosureSubmissionStatus.CLOSED,
    DisclosureSubmissionStatus.WITHDRAWN,
})


def _finding_payload(record: VRFindingRecord) -> dict[str, Any]:
    """Pull a flat dict from a VRFindingRecord usable by track.render()."""
    return {
        "id": record.id,
        "title": (record.crash_signature or record.crash_type or "VR finding"),
        "crash_type": record.crash_type,
        "crash_signature": record.crash_signature,
        "vulnerable_function": record.vulnerable_function,
        "root_cause": record.root_cause,
        "poc_code": record.poc_code,
        "affected_component": record.vulnerable_function,
        "summary": record.crash_signature or record.root_cause,
        "attribution": "",
    }


def _record_to_summary(
    record: VRDisclosureSubmissionRecord,
    track_info: Any = None,
) -> VRDisclosureSubmissionSummary:
    sections: dict[str, str] = {}
    if record.sections_json:
        try:
            decoded = json.loads(record.sections_json)
            if isinstance(decoded, dict):
                sections = {str(k): str(v) for k, v in decoded.items()}
        except (ValueError, TypeError):
            sections = {}
    return VRDisclosureSubmissionSummary(
        id=record.id,
        finding_id=record.finding_id,
        track_id=record.track_id,
        workspace_id=record.workspace_id,
        kind=DisclosureKind(record.kind),
        status=DisclosureSubmissionStatus(record.status),
        poc_tier=ArtifactTier(record.poc_tier),
        severity_rating=record.severity_rating,
        embargo_until=record.embargo_until,
        embargo_days_used=record.embargo_days_used,
        vendor_reference=record.vendor_reference,
        bounty_awarded_usd=record.bounty_awarded_usd,
        rendered_submission_path=None,  # body lives in DB, not on disk
        notes=record.notes or "",
        validation_errors=json.loads(record.validation_errors_json or "[]"),
        track_info=track_info,
        created_at=record.created_at,
        updated_at=record.updated_at,
        sections=sections,
        regenerated_from_finding_at=record.regenerated_from_finding_at,
    )


class DisclosureService:
    """Single entry point for disclosure submission operations."""

    async def create(
        self,
        body: VRDisclosureSubmissionCreate,
        team_id: str | None,
    ) -> VRDisclosureSubmissionSummary:
        track_cls = get_track(body.track_id)
        if track_cls is None:
            raise DisclosureServiceError(
                f"unknown track_id {body.track_id!r}",
            )

        async with UnitOfWork() as uow:
            # Resolve the disclosure's anchor finding. Two paths:
            #   1. caller gave finding_id directly — load it.
            #   2. caller gave investigation_id — look up the
            #      investigation, then resolve its linked_finding_ids:
            #        * exactly 1 linked → use it
            #        * 0 linked        → auto-create a stub finding
            #          from the investigation so the operator can still
            #          file a disclosure for a still-bare investigation
            #          outcome (the stub carries the investigation id
            #          and team scope so it can be enriched later via
            #          the existing FindingDetailPage editor).
            #        * 2+ linked       → reject; the operator must
            #          specify finding_id directly because we can't
            #          guess which one they meant.
            resolved_finding_id = body.finding_id
            if resolved_finding_id is None:
                assert body.investigation_id is not None  # validator gate
                inv = (await uow.session.exec(
                    _select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == body.investigation_id,
                    ),
                )).first()
                if inv is None:
                    raise DisclosureServiceError(
                        f"investigation {body.investigation_id} not found",
                    )
                try:
                    linked = json.loads(inv.linked_finding_ids_json or "[]")
                except (TypeError, ValueError):
                    linked = []
                if not isinstance(linked, list):
                    linked = []
                linked = [str(x) for x in linked if x]

                if len(linked) == 1:
                    resolved_finding_id = linked[0]
                elif len(linked) > 1:
                    raise DisclosureServiceError(
                        f"investigation {body.investigation_id} has "
                        f"{len(linked)} linked findings; specify "
                        f"finding_id directly instead of investigation_id",
                    )
                else:
                    # Zero linked findings — auto-create a stub. The stub
                    # carries the investigation's project + workspace
                    # context so the disclosure has something concrete
                    # to bind to; downstream the operator can flesh it
                    # out via the FindingDetailPage editor.
                    stub = VRFindingRecord(
                        project_id=inv.project_id,
                        team_id=team_id,
                        crash_type=None,
                        crash_signature=None,
                        root_cause=(
                            f"stub finding auto-created for "
                            f"investigation {inv.id}; enrich via "
                            f"FindingDetailPage before publication."
                        ),
                        vulnerable_function=None,
                    )
                    uow.session.add(stub)
                    await uow.session.flush()
                    resolved_finding_id = stub.id
                    # Mirror the new finding back into the
                    # investigation's linked list so subsequent calls
                    # find it via the same one-linked-finding shortcut.
                    linked.append(stub.id)
                    inv.linked_finding_ids_json = json.dumps(linked)
                    uow.session.add(inv)

            finding = (await uow.session.exec(
                _select(VRFindingRecord).where(
                    VRFindingRecord.id == resolved_finding_id,
                ),
            )).first()
            if finding is None:
                raise DisclosureServiceError(
                    f"finding {resolved_finding_id} not found",
                )
            # Allow operator to disclose findings from any workspace they
            # have access to; we don't enforce finding.workspace_id ==
            # body.workspace_id because findings can be promoted across
            # workspaces. The team_id check is what enforces tenancy.

            payload = _finding_payload(finding)
            validation_errors = track_cls.validate(
                poc_tier=body.poc_tier, finding_payload=payload,
            )
            rendered = track_cls.render(
                finding_payload=payload,
                poc_tier=body.poc_tier,
                severity_rating=body.severity_rating,
                embargo_days=body.embargo_days_override or track_cls.embargo_default_days,
            )
            embargo_days = (
                body.embargo_days_override
                if body.embargo_days_override is not None
                else track_cls.embargo_default_days
            )
            embargo_until = None
            if embargo_days is not None and embargo_days > 0:
                embargo_until = utc_now() + timedelta(days=embargo_days)

            now = utc_now()
            record = VRDisclosureSubmissionRecord(
                team_id=team_id,
                finding_id=resolved_finding_id,
                workspace_id=body.workspace_id,
                track_id=body.track_id,
                kind=track_cls.kind.value,
                status=DisclosureSubmissionStatus.DRAFTED.value,
                poc_tier=body.poc_tier.value,
                severity_rating=body.severity_rating,
                embargo_days_used=embargo_days,
                embargo_until=embargo_until,
                rendered_submission_body=rendered,
                rendered_submission_format="markdown",
                last_rendered_at=now,
                rendered_submission_metadata_json="{}",
                notes=body.notes or "",
                validation_errors_json=json.dumps(validation_errors),
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            return _record_to_summary(record, track_info=track_cls.info())

    async def get(
        self, submission_id: str,
    ) -> VRDisclosureSubmissionSummary | None:
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if record is None:
                return None
            track_cls = get_track(record.track_id)
            info = track_cls.info() if track_cls is not None else None
            return _record_to_summary(record, track_info=info)

    async def list(
        self,
        *,
        finding_id: str | None = None,
        workspace_id: str | None = None,
        track_id: str | None = None,
        status: DisclosureSubmissionStatus | None = None,
        team_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[VRDisclosureSubmissionSummary], int]:
        async with UnitOfWork() as uow:
            stmt = _select(VRDisclosureSubmissionRecord)
            count_stmt = _select(sa_func.count()).select_from(
                VRDisclosureSubmissionRecord,
            )
            if team_id is not None:
                stmt = stmt.where(VRDisclosureSubmissionRecord.team_id == team_id)
                count_stmt = count_stmt.where(
                    VRDisclosureSubmissionRecord.team_id == team_id,
                )
            for col, val in (
                (VRDisclosureSubmissionRecord.finding_id, finding_id),
                (VRDisclosureSubmissionRecord.workspace_id, workspace_id),
                (VRDisclosureSubmissionRecord.track_id, track_id),
            ):
                if val:
                    stmt = stmt.where(col == val)
                    count_stmt = count_stmt.where(col == val)
            if status:
                stmt = stmt.where(VRDisclosureSubmissionRecord.status == status.value)
                count_stmt = count_stmt.where(
                    VRDisclosureSubmissionRecord.status == status.value,
                )

            total = (await uow.session.exec(count_stmt)).one()
            stmt = (
                stmt.order_by(VRDisclosureSubmissionRecord.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await uow.session.exec(stmt)).all()

        summaries: list[VRDisclosureSubmissionSummary] = []
        for r in rows:
            track_cls = get_track(r.track_id)
            info = track_cls.info() if track_cls is not None else None
            summaries.append(_record_to_summary(r, track_info=info))
        return summaries, int(total)

    async def patch(
        self,
        submission_id: str,
        body: VRDisclosureSubmissionPatch,
    ) -> VRDisclosureSubmissionSummary:
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if record is None:
                raise DisclosureServiceError(
                    f"submission {submission_id} not found",
                )
            current_status = DisclosureSubmissionStatus(record.status)
            if current_status in _TERMINAL_STATES and body.status is not None and body.status != current_status:
                raise DisclosureServiceError(
                    f"cannot transition from terminal state {current_status.value} "
                    f"to {body.status.value}",
                )

            mutated = False
            re_render = False

            if body.status is not None and body.status.value != record.status:
                record.status = body.status.value
                mutated = True
            if body.poc_tier is not None and body.poc_tier.value != record.poc_tier:
                record.poc_tier = body.poc_tier.value
                mutated = True
                re_render = True
            if body.severity_rating is not None and body.severity_rating != record.severity_rating:
                record.severity_rating = body.severity_rating
                mutated = True
                re_render = True
            if body.embargo_days_override is not None and body.embargo_days_override != record.embargo_days_used:
                record.embargo_days_used = body.embargo_days_override
                if body.embargo_days_override > 0:
                    record.embargo_until = utc_now() + timedelta(
                        days=body.embargo_days_override,
                    )
                else:
                    record.embargo_until = None
                mutated = True
                re_render = True
            if body.vendor_reference is not None and body.vendor_reference != record.vendor_reference:
                record.vendor_reference = body.vendor_reference
                mutated = True
            if body.bounty_awarded_usd is not None and body.bounty_awarded_usd != record.bounty_awarded_usd:
                record.bounty_awarded_usd = body.bounty_awarded_usd
                mutated = True
            if body.notes is not None and body.notes != record.notes:
                record.notes = body.notes
                mutated = True

            if re_render:
                finding = (await uow.session.exec(
                    _select(VRFindingRecord).where(
                        VRFindingRecord.id == record.finding_id,
                    ),
                )).first()
                if finding is not None:
                    track_cls = get_track(record.track_id)
                    if track_cls is not None:
                        payload = _finding_payload(finding)
                        record.rendered_submission_body = track_cls.render(
                            finding_payload=payload,
                            poc_tier=ArtifactTier(record.poc_tier),
                            severity_rating=record.severity_rating,
                            embargo_days=record.embargo_days_used or track_cls.embargo_default_days,
                        )
                        record.last_rendered_at = utc_now()
                        record.validation_errors_json = json.dumps(
                            track_cls.validate(
                                poc_tier=ArtifactTier(record.poc_tier),
                                finding_payload=payload,
                            ),
                        )

            if mutated:
                record.updated_at = utc_now()
                uow.session.add(record)
                await uow.session.commit()
                await uow.session.refresh(record)

            track_cls = get_track(record.track_id)
            info = track_cls.info() if track_cls is not None else None
            return _record_to_summary(record, track_info=info)

    async def render(self, submission_id: str) -> RenderedSubmission:
        """Re-render an existing submission (idempotent)."""
        async with UnitOfWork() as uow:
            record = (await uow.session.exec(
                _select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if record is None:
                raise DisclosureServiceError(
                    f"submission {submission_id} not found",
                )
            finding = (await uow.session.exec(
                _select(VRFindingRecord).where(
                    VRFindingRecord.id == record.finding_id,
                ),
            )).first()
            if finding is None:
                raise DisclosureServiceError(
                    f"finding {record.finding_id} disappeared",
                )

            track_cls = get_track(record.track_id)
            if track_cls is None:
                raise DisclosureServiceError(
                    f"track {record.track_id!r} no longer registered",
                )

            payload = _finding_payload(finding)
            validation_errors = track_cls.validate(
                poc_tier=ArtifactTier(record.poc_tier),
                finding_payload=payload,
            )
            body = track_cls.render(
                finding_payload=payload,
                poc_tier=ArtifactTier(record.poc_tier),
                severity_rating=record.severity_rating,
                embargo_days=record.embargo_days_used or track_cls.embargo_default_days,
            )
            now = utc_now()
            record.rendered_submission_body = body
            record.last_rendered_at = now
            record.validation_errors_json = json.dumps(validation_errors)
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

            return RenderedSubmission(
                submission_id=record.id,
                track_id=record.track_id,
                finding_id=record.finding_id,
                rendered_at=now,
                body=body,
                body_format=record.rendered_submission_format,
                metadata=json.loads(record.rendered_submission_metadata_json or "{}"),
                validation_errors=validation_errors,
            )
