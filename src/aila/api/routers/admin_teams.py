"""Admin teams router (Phase 177) — multi-team management.

All endpoints require admin role (team_id=None in the caller's JWT).

    GET     /admin/teams                       -- list all teams
    POST    /admin/teams                       -- create team
    GET     /admin/teams/cross-view            -- cross-team stats (admin only)
    GET     /admin/teams/{team_id}             -- team detail + member list
    PUT     /admin/teams/{team_id}             -- rename / update description
    DELETE  /admin/teams/{team_id}             -- soft delete (reject if data exists)
    POST    /admin/teams/{team_id}/members     -- add member
    DELETE  /admin/teams/{team_id}/members/{user_id}
                                               -- remove member

All responses use DataEnvelope. All admin writes are rate-limited.
"""
from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlmodel import select

from aila.api.limiter import limiter
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    ManagedSystemRecord,
    TeamMemberRecord,
    TeamRecord,
    UserRecord,
    WorkflowRunRecord,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)
_slog = structlog.get_logger(__name__)


async def _require_admin(ctx: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    """Reject non-admin callers from team administration."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This endpoint requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    return ctx


router = APIRouter(
    prefix="/admin/teams",
    tags=["admin-teams"],
    dependencies=[Depends(_require_admin)],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TeamCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)


class TeamUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class MemberAddRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    role: str = Field(default="operator", pattern=r"^(admin|operator|reader)$")


class TeamResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime
    member_count: int = 0


class TeamMemberResponse(BaseModel):
    id: str
    user_id: str
    username: str
    email: str | None
    role: str
    created_at: datetime


class TeamDetailResponse(BaseModel):
    team: TeamResponse
    members: list[TeamMemberResponse]


class CrossTeamStatsRow(BaseModel):
    team_id: str
    team_name: str
    systems_count: int
    runs_count: int
    members_count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_valid_uuid(value: str) -> bool:
    try:
        UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _team_to_response(team: TeamRecord, member_count: int = 0) -> TeamResponse:
    return TeamResponse(
        id=team.id,
        name=team.name,
        description=team.description,
        created_at=team.created_at,
        updated_at=team.updated_at,
        member_count=member_count,
    )


async def _load_team(team_id: str) -> TeamRecord:
    if not _is_valid_uuid(team_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="team_id must be a UUID",
        )
    async with async_session_scope() as session:
        team = await session.get(TeamRecord, team_id)
    if team is None or team.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
    return team


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=DataEnvelope[list[TeamResponse]], summary="List teams")
async def list_teams() -> DataEnvelope[list[TeamResponse]]:
    async with async_session_scope() as session:
        stmt = select(TeamRecord).where(TeamRecord.deleted_at.is_(None))  # type: ignore[attr-defined]
        teams = list((await session.exec(stmt)).all())

        # Count members per team in a single query
        count_stmt = (
            select(TeamMemberRecord.team_id, func.count(TeamMemberRecord.id))  # type: ignore[arg-type]
            .group_by(TeamMemberRecord.team_id)
        )
        count_rows = list((await session.exec(count_stmt)).all())
        counts: dict[str, int] = {row[0]: int(row[1]) for row in count_rows}

    return DataEnvelope(
        data=[_team_to_response(t, counts.get(t.id, 0)) for t in teams]
    )


@router.post(
    "",
    response_model=DataEnvelope[TeamResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a team",
)
@limiter.limit("60/minute")
async def create_team(
    request: Request,
    body: TeamCreateRequest,
) -> DataEnvelope[TeamResponse]:
    now = utc_now()
    team = TeamRecord(
        id=str(uuid4()),
        name=body.name,
        description=body.description,
        created_at=now,
        updated_at=now,
    )
    async with async_session_scope() as session:
        # Uniqueness check on active (non-deleted) teams
        stmt = select(TeamRecord).where(
            TeamRecord.name == body.name,
            TeamRecord.deleted_at.is_(None),  # type: ignore[attr-defined]
        )
        existing = (await session.exec(stmt)).first()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Team with name '{body.name}' already exists",
            )
        session.add(team)
        await session.commit()
        await session.refresh(team)

    _slog.info("team_created", team_id=team.id, team_name=team.name)
    return DataEnvelope(data=_team_to_response(team, 0))


@router.get(
    "/cross-view",
    response_model=DataEnvelope[list[CrossTeamStatsRow]],
    summary="Cross-team stats (admin only)",
)
async def cross_team_view() -> DataEnvelope[list[CrossTeamStatsRow]]:
    """Aggregate systems / runs / members across all teams."""
    async with async_session_scope() as session:
        teams = list(
            (
                await session.exec(
                    select(TeamRecord).where(TeamRecord.deleted_at.is_(None))  # type: ignore[attr-defined]
                )
            ).all()
        )

        rows: list[CrossTeamStatsRow] = []
        for team in teams:
            sys_count = (
                await session.exec(
                    select(func.count(ManagedSystemRecord.id)).where(  # type: ignore[arg-type]
                        ManagedSystemRecord.team_id == team.id
                    )
                )
            ).first() or 0
            run_count = (
                await session.exec(
                    select(func.count(WorkflowRunRecord.id)).where(  # type: ignore[arg-type]
                        WorkflowRunRecord.team_id == team.id
                    )
                )
            ).first() or 0
            mem_count = (
                await session.exec(
                    select(func.count(TeamMemberRecord.id)).where(  # type: ignore[arg-type]
                        TeamMemberRecord.team_id == team.id
                    )
                )
            ).first() or 0

            rows.append(
                CrossTeamStatsRow(
                    team_id=team.id,
                    team_name=team.name,
                    systems_count=int(sys_count),
                    runs_count=int(run_count),
                    members_count=int(mem_count),
                )
            )

    return DataEnvelope(data=rows)


@router.get(
    "/{team_id}",
    response_model=DataEnvelope[TeamDetailResponse],
    summary="Team detail + members",
)
async def get_team(team_id: str) -> DataEnvelope[TeamDetailResponse]:
    team = await _load_team(team_id)

    async with async_session_scope() as session:
        member_rows = list(
            (
                await session.exec(
                    select(TeamMemberRecord).where(TeamMemberRecord.team_id == team_id)
                )
            ).all()
        )

        user_ids = [m.user_id for m in member_rows]
        if user_ids:
            user_rows = list(
                (
                    await session.exec(
                        select(UserRecord).where(UserRecord.id.in_(user_ids))  # type: ignore[attr-defined]
                    )
                ).all()
            )
        else:
            user_rows = []
        users_by_id: dict[str, UserRecord] = {u.id: u for u in user_rows}

    members = [
        TeamMemberResponse(
            id=m.id,
            user_id=m.user_id,
            username=users_by_id[m.user_id].username if m.user_id in users_by_id else "(removed)",
            email=users_by_id[m.user_id].email if m.user_id in users_by_id else None,
            role=m.role,
            created_at=m.created_at,
        )
        for m in member_rows
    ]

    return DataEnvelope(
        data=TeamDetailResponse(
            team=_team_to_response(team, len(members)),
            members=members,
        )
    )


@router.put(
    "/{team_id}",
    response_model=DataEnvelope[TeamResponse],
    summary="Update a team",
)
@limiter.limit("60/minute")
async def update_team(
    request: Request,
    team_id: str,
    body: TeamUpdateRequest,
) -> DataEnvelope[TeamResponse]:
    if not _is_valid_uuid(team_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="team_id must be a UUID",
        )
    async with async_session_scope() as session:
        team = await session.get(TeamRecord, team_id)
        if team is None or team.deleted_at is not None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        if body.name is not None and body.name != team.name:
            # Uniqueness check
            stmt = select(TeamRecord).where(
                TeamRecord.name == body.name,
                TeamRecord.deleted_at.is_(None),  # type: ignore[attr-defined]
                TeamRecord.id != team_id,
            )
            other = (await session.exec(stmt)).first()
            if other is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Team with name '{body.name}' already exists",
                )
            team.name = body.name
        if body.description is not None:
            team.description = body.description

        team.updated_at = utc_now()
        session.add(team)
        await session.commit()
        await session.refresh(team)

        count = (
            await session.exec(
                select(func.count(TeamMemberRecord.id)).where(  # type: ignore[arg-type]
                    TeamMemberRecord.team_id == team_id
                )
            )
        ).first() or 0

    return DataEnvelope(data=_team_to_response(team, int(count)))


@router.delete(
    "/{team_id}",
    response_model=DataEnvelope[dict],
    summary="Delete a team (soft delete)",
)
@limiter.limit("30/minute")
async def delete_team(request: Request, team_id: str) -> DataEnvelope[dict]:
    if not _is_valid_uuid(team_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="team_id must be a UUID",
        )
    async with async_session_scope() as session:
        team = await session.get(TeamRecord, team_id)
        if team is None or team.deleted_at is not None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        # Reject deletion when the team still owns systems — operators must
        # migrate data first to avoid orphaning team-scoped rows.
        sys_count = (
            await session.exec(
                select(func.count(ManagedSystemRecord.id)).where(  # type: ignore[arg-type]
                    ManagedSystemRecord.team_id == team_id
                )
            )
        ).first() or 0
        if int(sys_count) > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Team has {int(sys_count)} system(s). Reassign them before deleting."
                ),
            )

        team.deleted_at = utc_now()
        session.add(team)
        # Also drop memberships so the user can be re-added elsewhere
        members = list(
            (
                await session.exec(
                    select(TeamMemberRecord).where(TeamMemberRecord.team_id == team_id)
                )
            ).all()
        )
        for m in members:
            await session.delete(m)
        await session.commit()

    _slog.info("team_deleted", team_id=team_id)
    return DataEnvelope(data={"deleted": team_id})


@router.post(
    "/{team_id}/members",
    response_model=DataEnvelope[TeamMemberResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Add a team member",
)
@limiter.limit("60/minute")
async def add_member(
    request: Request,
    team_id: str,
    body: MemberAddRequest,
) -> DataEnvelope[TeamMemberResponse]:
    await _load_team(team_id)  # 404 if team missing

    async with async_session_scope() as session:
        user = await session.get(UserRecord, body.user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Duplicate check
        stmt = select(TeamMemberRecord).where(
            TeamMemberRecord.team_id == team_id,
            TeamMemberRecord.user_id == body.user_id,
        )
        dup = (await session.exec(stmt)).first()
        if dup is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already a member of this team",
            )

        member = TeamMemberRecord(
            id=str(uuid4()),
            team_id=team_id,
            user_id=body.user_id,
            role=body.role,
            created_at=utc_now(),
        )
        session.add(member)
        await session.commit()
        await session.refresh(member)

    return DataEnvelope(
        data=TeamMemberResponse(
            id=member.id,
            user_id=member.user_id,
            username=user.username,
            email=user.email,
            role=member.role,
            created_at=member.created_at,
        )
    )


@router.delete(
    "/{team_id}/members/{user_id}",
    response_model=DataEnvelope[dict],
    summary="Remove a team member",
)
@limiter.limit("60/minute")
async def remove_member(
    request: Request, team_id: str, user_id: str
) -> DataEnvelope[dict]:
    await _load_team(team_id)

    async with async_session_scope() as session:
        stmt = select(TeamMemberRecord).where(
            TeamMemberRecord.team_id == team_id,
            TeamMemberRecord.user_id == user_id,
        )
        member = (await session.exec(stmt)).first()
        if member is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Membership not found",
            )
        await session.delete(member)
        await session.commit()

    return DataEnvelope(data={"removed": user_id, "team_id": team_id})
