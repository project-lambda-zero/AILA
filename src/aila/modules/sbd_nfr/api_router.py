"""FastAPI router for the SbD NFR module.

Wires all HTTP endpoints to service functions.  Two sub-routers are used to
separate auth strategies (Pitfall 3 in 134-RESEARCH):

  _protected   JWT required for every route (via router-level dependency).
               All schema, session management, admin CRUD, dashboard, and
               search routes live here.

  _shared      Dual-auth: accepts either a Bearer JWT or ?share_token= query
               param.  Used for session detail read and answer submission so
               share-token contributors can fill out questionnaires without a
               platform account.

Design references:
  QSCHEMA-01: GET /schema
  QSCHEMA-05: POST /sessions, GET /sessions, GET /sessions/{id}
  D-02:       Schema admin CRUD (POST/PATCH/DELETE /schema/sections and /questions)
  D-23a/b/c:  SessionAccessContext permission checks on shared routes
  D-25:       contributor_name + contributor_email required for share_token path
  D-26:       GET /sessions with typed filter params
  D-27:       GET /sessions/{id}/export
  D-31:       PATCH /sessions/{id}/sections/{key}/answers (bulk upsert)
  D-32:       GET /sessions/{id} full state snapshot
  D-33:       POST /sessions/{id}/clone
  D-35a:      DELETE /sessions/{id} (owner soft-delete; admin hard-delete)
  D-44/D-45:  POST /sessions/smart-search
  D-48:       GET /dashboard/stats (operator+)
  D-53:       POST /sessions/{id}/assign
  D-60:       POST /sessions/{id}/save-as-template
  D-61:       POST /sessions/bulk-assign, POST /sessions/bulk-export
  D-66:       GET /sessions/{id}/activity

Security references:
  T-134-17:   require_role("admin") on schema CRUD routes
  T-134-18:   share_token validated inside require_session_access
"""

from __future__ import annotations

import io
import json
import logging
import time
from collections import defaultdict
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from aila.api.schemas.common import PaginatedResponse
from aila.platform.contracts.auth import AuthContext, require_auth, require_role
from aila.platform.uow import UnitOfWork

from .contracts import (
    ActivityResponse,
    ApproveSessionRequest,
    ArchitectNotesRequest,
    BulkAnswerRequest,
    DashboardStatsResponse,
    MappingCreateRequest,
    MappingResponse,
    OptionCreateRequest,
    OptionResponse,
    OptionUpdateRequest,
    QuestionCreateRequest,
    QuestionListResponse,
    QuestionResponse,
    QuestionUpdateRequest,
    SchemaTreeResponse,
    SchemaVersionResponse,
    SectionCreateRequest,
    SectionListResponse,
    SectionProgressResponse,
    SectionResponse,
    SectionUpdateRequest,
    SessionCreateRequest,
    SessionDetailResponse,
    SessionSummaryResponse,
    SmartSearchRequest,
    SmartSearchResponse,
    SubgroupCreateRequest,
    SubgroupListResponse,
    SubgroupUpdateRequest,
    SubmitForReviewRequest,
    SubtaskComponentResponse,
)
from .contracts.resolution import (
    AssistRequest,
    AssistResponse,
    ComponentClassificationResponse,
    ResolutionResultResponse,
)
from .contracts.responses import (
    BulkAssignResponse,
    BulkExportResponse,
    ResolutionTriggerResponse,
    TriageContextResponse,
)
from .services import (
    activity_service,
    answer_service,
    assist_service,
    resolution_service,
    schema_service,
    search_service,
    session_service,
    stats_service,
)
from .services.auth import SessionAccessContext
from .services.auth import require_session_access as _require_session_access
from .services.session_service import SessionListFilters

# ---------------------------------------------------------------------------
# In-memory rate limit stores (D-18, T-135-07, T-135-08)
# Simple sliding-window counters — acceptable for low per-session limits.
# ---------------------------------------------------------------------------

_resolve_rate_limits: dict[str, list[float]] = defaultdict(list)
_assist_rate_limits: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(
    store: dict[str, list[float]],
    key: str,
    max_calls: int,
    window_seconds: int,
) -> bool:
    """Return True if the rate limit is exceeded, False otherwise.

    Removes timestamps older than ``window_seconds`` before checking.
    Appends the current timestamp when the limit is not exceeded.
    """
    now = time.time()
    cutoff = now - window_seconds
    store[key] = [t for t in store[key] if t > cutoff]
    if len(store[key]) >= max_calls:
        return True
    store[key].append(now)
    return False

_log = logging.getLogger(__name__)

__all__ = ["create_sbd_nfr_router", "create_sbd_nfr_shared_router"]

# Bearer scheme used by the dual-auth wrapper (auto_error=False so share-token
# requests are not rejected before our code can inspect the share_token param).
_OPTIONAL_BEARER: HTTPBearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Dependency wrappers
# ---------------------------------------------------------------------------


async def _session_access_dep(
    session_id: str,
    share_token: str | None = Query(default=None),
    contributor_name: str | None = Query(default=None),
    contributor_email: str | None = Query(default=None),
    credentials: HTTPAuthorizationCredentials | None = Depends(_OPTIONAL_BEARER),
) -> SessionAccessContext:
    """Router-level wrapper for require_session_access.

    Opens its own DB session so FastAPI never sees AsyncSession | None in
    the dependency signature (which causes a FastAPIError on startup).

    The underlying _require_session_access() accepts db=None and loads the
    session itself when db is provided.  Here we pass a real session so the
    auth check can validate the session exists and the token/share_token matches.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        return await _require_session_access(
            session_id=session_id,
            share_token=share_token,
            contributor_name=contributor_name,
            contributor_email=contributor_email,
            credentials=credentials,
            db=db,
        )


# Alias for use in Depends() calls below.
require_session_access = _session_access_dep


async def _load_session_or_404(session_id: str) -> Any:
    """Load a non-deleted session record or raise 404.

    Opens its own UnitOfWork — returns the detached ORM row.
    Raises HTTPException(404) when the session is missing or soft-deleted.
    """
    from sqlmodel import select as sa_select

    from .db_models import SbdNfrSessionRecord

    async with UnitOfWork() as _uow:
        db = _uow.session
        record = (await db.exec(
            sa_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()

    if record is None or record.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )
    return record


async def _verify_session_read_access(
    session_id: str,
    auth: AuthContext,
) -> None:
    """Check the caller has read access to a session (owner, architect, operator, or admin).

    Readers can only access their own sessions. Operators and admins can access any.
    Raises HTTPException(404) for not found, HTTPException(403) for unauthorized.
    """
    session_record = await _load_session_or_404(session_id)

    if auth.role in ("operator", "admin"):
        return
    if auth.user_id == session_record.owner_id:
        return
    if (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Session '{session_id}' not found",
    )


# ---------------------------------------------------------------------------
# Sub-routers
# ---------------------------------------------------------------------------

# All routes on _protected require a valid JWT Bearer token.
_protected = APIRouter(dependencies=[Depends(require_auth)])

# Routes on _shared accept EITHER a JWT Bearer OR ?share_token= query param.
# Each handler receives SessionAccessContext from require_session_access.
_shared = APIRouter()


# ===========================================================================
# Schema endpoints — QSCHEMA-01
# ===========================================================================


@_protected.get(
    "/schema",
    response_model=SchemaTreeResponse,
    summary="Get full question schema tree",
    tags=["schema"],
)
async def get_schema_tree(
    version: int | None = Query(default=None, description="Schema version; defaults to latest"),
    _auth: AuthContext = Depends(require_auth),
) -> SchemaTreeResponse:
    """Return the complete nested section -> subgroup -> question tree.

    Any authenticated user can call this endpoint.  The tree reflects the
    current (or specified) schema version.
    """
    return await schema_service.get_schema_tree(version=version)


@_protected.get(
    "/schema/subtasks",
    response_model=list[SubtaskComponentResponse],
    summary="List all subtask components",
    tags=["schema"],
)
async def list_subtask_components(
    _auth: AuthContext = Depends(require_auth),
) -> list[SubtaskComponentResponse]:
    """Return all active subtask components ordered by display_order."""
    return await schema_service.get_subtask_components()


# ---------------------------------------------------------------------------
# Schema admin CRUD — D-02, T-134-17
# ---------------------------------------------------------------------------


@_protected.post(
    "/schema/sections",
    response_model=SectionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new schema section (admin only)",
    tags=["schema-admin"],
)
async def create_section(
    body: SectionCreateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> SectionResponse:
    """Create a new questionnaire section and bump the schema version.

    Requires admin role (T-134-17).
    """
    return await schema_service.create_section(body, changed_by=admin.user_id)


@_protected.patch(
    "/schema/sections/{section_id}",
    response_model=SectionResponse,
    summary="Update a schema section (admin only)",
    tags=["schema-admin"],
)
async def update_section(
    section_id: str,
    body: SectionUpdateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> SectionResponse:
    """Update section fields and bump the schema version.

    Requires admin role (T-134-17).
    """
    try:
        return await schema_service.update_section(section_id, body, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.delete(
    "/schema/sections/{section_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a schema section (admin only)",
    tags=["schema-admin"],
)
async def deactivate_section(
    section_id: str,
    admin: AuthContext = Depends(require_role("admin")),
) -> None:
    """Soft-delete a section and cascade to subgroups and questions.

    Requires admin role (T-134-17).
    """
    try:
        await schema_service.deactivate_section(section_id, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.post(
    "/schema/questions",
    response_model=QuestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new schema question (admin only)",
    tags=["schema-admin"],
)
async def create_question(
    body: QuestionCreateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> QuestionResponse:
    """Create a new questionnaire question in a subgroup.

    Requires admin role (T-134-17).
    """
    try:
        return await schema_service.create_question(body, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@_protected.patch(
    "/schema/questions/{question_id}",
    response_model=QuestionResponse,
    summary="Update a schema question (admin only)",
    tags=["schema-admin"],
)
async def update_question(
    question_id: str,
    body: QuestionUpdateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> QuestionResponse:
    """Update question fields and bump the schema version.

    Requires admin role (T-134-17).
    """
    try:
        return await schema_service.update_question(question_id, body, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.delete(
    "/schema/questions/{question_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a schema question (admin only)",
    tags=["schema-admin"],
)
async def deactivate_question(
    question_id: str,
    admin: AuthContext = Depends(require_role("admin")),
) -> None:
    """Soft-delete a question by setting is_active=False.

    Requires admin role (T-134-17).
    """
    try:
        await schema_service.deactivate_question(question_id, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ===========================================================================
# Phase 155 — EDIT-07: flat list read endpoints (all authenticated)
# ===========================================================================


@_protected.get(
    "/schema/sections",
    response_model=list[SectionListResponse],
    summary="List schema sections (flat)",
    tags=["schema"],
)
async def list_sections(
    schema_version: int | None = Query(default=None, description="Schema version; defaults to latest"),
    include_inactive: bool = Query(default=False, description="Include inactive sections"),
    _auth: AuthContext = Depends(require_auth),
) -> list[SectionListResponse]:
    """Return a flat ordered list of sections for the given (or latest) schema version.

    Any authenticated user can call this endpoint.
    """
    return await schema_service.list_sections(schema_version=schema_version, include_inactive=include_inactive)


@_protected.get(
    "/schema/questions",
    response_model=list[QuestionListResponse],
    summary="List schema questions (flat)",
    tags=["schema"],
)
async def list_questions(
    subgroup_id: str | None = Query(default=None, description="Filter by subgroup ID"),
    schema_version: int | None = Query(default=None, description="Schema version; defaults to latest"),
    include_inactive: bool = Query(default=False, description="Include inactive questions"),
    _auth: AuthContext = Depends(require_auth),
) -> list[QuestionListResponse]:
    """Return a flat ordered list of questions, optionally filtered by subgroup.

    Any authenticated user can call this endpoint.
    """
    return await schema_service.list_questions(
        subgroup_id=subgroup_id, schema_version=schema_version, include_inactive=include_inactive
    )


@_protected.get(
    "/schema/version",
    response_model=SchemaVersionResponse,
    summary="Get the current schema version",
    tags=["schema"],
)
async def get_schema_version(
    _auth: AuthContext = Depends(require_auth),
) -> SchemaVersionResponse:
    """Return the current (highest) schema version record.

    Any authenticated user can call this endpoint.
    Returns version=0 with empty fields if no version records exist.
    """
    from sqlmodel import select as _sa_select

    from .db_models import SbdNfrSchemaVersionRecord

    async with UnitOfWork() as _uow:
        db = _uow.session
        row = (await db.exec(
            _sa_select(
                SbdNfrSchemaVersionRecord.version,
                SbdNfrSchemaVersionRecord.change_summary,
                SbdNfrSchemaVersionRecord.changed_by,
                SbdNfrSchemaVersionRecord.created_at,
            )
            .order_by(SbdNfrSchemaVersionRecord.version.desc())
            .limit(1)
        )).first()
        if row is None:
            from datetime import datetime, timezone
            return SchemaVersionResponse(
                version=0,
                change_summary="",
                changed_by="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        version, change_summary, changed_by, created_at = row
        return SchemaVersionResponse(
            version=int(version),
            change_summary=str(change_summary),
            changed_by=str(changed_by),
            created_at=created_at.isoformat(),
        )


@_protected.get(
    "/schema/options",
    response_model=list[OptionResponse],
    summary="List answer options for a question",
    tags=["schema"],
)
async def list_options(
    question_id: str = Query(..., description="Question ID to list options for"),
    _auth: AuthContext = Depends(require_auth),
) -> list[OptionResponse]:
    """Return all answer options for the given question, ordered by display_order.

    Any authenticated user can call this endpoint.
    """
    return await schema_service.list_options(question_id=question_id)


@_protected.get(
    "/schema/mappings",
    response_model=list[MappingResponse],
    summary="List question-to-subtask mappings",
    tags=["schema"],
)
async def list_subtask_mappings(
    question_id: str | None = Query(default=None, description="Filter by question ID"),
    subtask_key: str | None = Query(default=None, description="Filter by subtask component key"),
    _auth: AuthContext = Depends(require_auth),
) -> list[MappingResponse]:
    """Return subtask mappings with optional filters.

    Any authenticated user can call this endpoint.
    """
    return await schema_service.list_subtask_mappings(question_id=question_id, subtask_key=subtask_key)


# ===========================================================================
# Phase 155 — EDIT-07: subgroup CRUD (admin only, T-155-05)
# ===========================================================================


@_protected.post(
    "/schema/subgroups",
    response_model=SubgroupListResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new schema subgroup (admin only)",
    tags=["schema-admin"],
)
async def create_subgroup(
    body: SubgroupCreateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> SubgroupListResponse:
    """Create a new subgroup within a section and bump the schema version.

    Requires admin role (T-155-05).
    """
    return await schema_service.create_subgroup(body, changed_by=admin.user_id)


@_protected.patch(
    "/schema/subgroups/{subgroup_id}",
    response_model=SubgroupListResponse,
    summary="Update a schema subgroup (admin only)",
    tags=["schema-admin"],
)
async def update_subgroup(
    subgroup_id: str,
    body: SubgroupUpdateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> SubgroupListResponse:
    """Update subgroup fields and bump the schema version.

    Requires admin role (T-155-05).
    """
    try:
        return await schema_service.update_subgroup(subgroup_id, body, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.delete(
    "/schema/subgroups/{subgroup_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a schema subgroup (admin only)",
    tags=["schema-admin"],
)
async def deactivate_subgroup(
    subgroup_id: str,
    admin: AuthContext = Depends(require_role("admin")),
) -> None:
    """Soft-delete a subgroup and cascade to all its questions.

    Requires admin role (T-155-05).
    """
    try:
        await schema_service.deactivate_subgroup(subgroup_id, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ===========================================================================
# Phase 155 — EDIT-07: option CRUD (admin only, T-155-05)
# ===========================================================================


@_protected.post(
    "/schema/options",
    response_model=OptionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new answer option (admin only)",
    tags=["schema-admin"],
)
async def create_option(
    body: OptionCreateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> OptionResponse:
    """Create a new answer option for a question.

    Requires admin role (T-155-05).
    """
    return await schema_service.create_option(body, changed_by=admin.user_id)


@_protected.patch(
    "/schema/options/{option_id}",
    response_model=OptionResponse,
    summary="Update an answer option (admin only)",
    tags=["schema-admin"],
)
async def update_option(
    option_id: str,
    body: OptionUpdateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> OptionResponse:
    """Update answer option fields.

    Requires admin role (T-155-05).
    """
    try:
        return await schema_service.update_option(option_id, body, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.delete(
    "/schema/options/{option_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an answer option (admin only)",
    tags=["schema-admin"],
)
async def delete_option(
    option_id: str,
    admin: AuthContext = Depends(require_role("admin")),
) -> None:
    """Hard-delete an answer option.

    Requires admin role (T-155-05).
    """
    try:
        await schema_service.delete_option(option_id, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ===========================================================================
# Phase 155 — EDIT-07: subtask mapping CRUD (admin only, T-155-05)
# ===========================================================================


@_protected.post(
    "/schema/mappings",
    response_model=MappingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a question-to-subtask mapping (admin only)",
    tags=["schema-admin"],
)
async def create_subtask_mapping(
    body: MappingCreateRequest,
    admin: AuthContext = Depends(require_role("admin")),
) -> MappingResponse:
    """Create a new question-to-subtask mapping.

    Returns 409 if the (question_id, subtask_key) pair already exists.
    Requires admin role (T-155-05).
    """
    try:
        return await schema_service.create_subtask_mapping(body, changed_by=admin.user_id)
    except ValueError as exc:
        if "already exists" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@_protected.delete(
    "/schema/mappings/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a question-to-subtask mapping (admin only)",
    tags=["schema-admin"],
)
async def delete_subtask_mapping(
    mapping_id: str,
    admin: AuthContext = Depends(require_role("admin")),
) -> None:
    """Hard-delete a question-to-subtask mapping.

    Requires admin role (T-155-05).
    """
    try:
        await schema_service.delete_subtask_mapping(mapping_id, changed_by=admin.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ===========================================================================
# Phase 155 — EDIT-07: schema version publish (admin only, T-155-05)
# ===========================================================================


class _PublishRequest(BaseModel):
    """Inline request body for schema version publish."""

    change_summary: str = "Manual publish"


@_protected.post(
    "/schema/version/publish",
    response_model=SchemaVersionResponse,
    summary="Publish a new schema version (admin only)",
    tags=["schema-admin"],
)
async def publish_schema_version(
    body: _PublishRequest = Body(default_factory=_PublishRequest),
    admin: AuthContext = Depends(require_role("admin")),
) -> SchemaVersionResponse:
    """Publish a new schema version by incrementing the version counter.

    Existing sessions remain pinned to their creation-time version.
    Requires admin role (T-155-05, T-155-06).
    """
    return await schema_service.publish_schema_version(
        change_summary=body.change_summary, changed_by=admin.user_id
    )


# ===========================================================================
# Session endpoints — QSCHEMA-05
# ===========================================================================


@_protected.post(
    "/sessions",
    response_model=SessionDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new NFR assessment session",
    tags=["sessions"],
)
async def create_session(
    body: SessionCreateRequest,
    auth: AuthContext = Depends(require_auth),
) -> SessionDetailResponse:
    """Create a new session in 'draft' status pinned to the current schema version."""
    return await session_service.create_session(body, owner_id=auth.user_id)


@_protected.get(
    "/sessions",
    response_model=PaginatedResponse[SessionSummaryResponse],
    summary="List sessions with optional filters",
    tags=["sessions"],
)
async def list_sessions(
    status_filter: str | None = Query(default=None, alias="status"),
    business_unit: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    search: str | None = Query(default=None),
    is_template: bool | None = Query(default=None, description="Filter by template flag (Phase 145 D-12)"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=250),
    auth: AuthContext = Depends(require_auth),
) -> PaginatedResponse[SessionSummaryResponse]:
    """List sessions with typed filters and pagination (D-26).

    Readers see only their own sessions; operators and admins see all.
    """
    filters = SessionListFilters(
        status=status_filter,
        business_unit=business_unit,
        tag=tag,
        search=search,
        is_template=is_template,
        # Restrict reader role to own sessions only.
        owner_id=auth.user_id if auth.role == "reader" else None,
    )
    paginated = await session_service.list_sessions(filters, page=page, page_size=page_size)
    pages = (
        (paginated.total + paginated.page_size - 1) // paginated.page_size
        if paginated.page_size > 0
        else 0
    )
    return PaginatedResponse(
        total=paginated.total,
        page=paginated.page,
        page_size=paginated.page_size,
        pages=pages,
        items=paginated.items,
    )


@_protected.post(
    "/sessions/smart-search",
    response_model=SmartSearchResponse,
    summary="LLM-powered smart search over sessions",
    tags=["sessions"],
)
async def smart_search(
    body: SmartSearchRequest,
    auth: AuthContext = Depends(require_auth),
) -> SmartSearchResponse:
    """Semantic search using an LLM to rank sessions by relevance (D-44/D-45).

    Role-based filtering (T-134-16):
    - reader role: only own sessions are candidates.
    - operator/admin: all non-deleted sessions are candidates.

    The LLM receives only filtered session data to prevent cross-user leaking.
    """
    # Obtain the LLM client from the platform runtime.
    # Imported lazily to avoid circular import at module load time.
    from aila.config import get_settings
    from aila.platform.config import PlatformSettings
    from aila.platform.llm import AilaLLMClient
    from aila.storage.registry import ConfigRegistry
    from aila.storage.secrets import SecretStore

    settings = get_settings()
    platform_settings = PlatformSettings(settings=settings)
    config_registry = ConfigRegistry()
    secret_store = SecretStore(platform_settings)
    llm_client = AilaLLMClient(registry=config_registry, secret_store=secret_store)

    return await search_service.smart_search(
        request=body,
        user_id=auth.user_id,
        user_role=auth.role,
        llm_client=llm_client,
    )


@_protected.post(
    "/sessions/{session_id}/clone",
    response_model=SessionDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Clone a session",
    tags=["sessions"],
)
async def clone_session(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> SessionDetailResponse:
    """Create a copy of an existing session with all answers cloned (D-33)."""
    await _verify_session_read_access(session_id, auth)
    return await session_service.clone_session(session_id, owner_id=auth.user_id)


@_protected.post(
    "/sessions/{session_id}/complete",
    response_model=SessionDetailResponse,
    status_code=status.HTTP_202_ACCEPTED,  # Resolution runs async (D-01, RESOLVE-04)
    summary="Complete a session and auto-trigger resolution",
    tags=["sessions"],
)
async def complete_session(
    request: Request,
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> SessionDetailResponse:
    """Validate all required answers and transition session to 'completed' (D-23c).

    Returns 202 Accepted — resolution is auto-triggered as a background task
    (RESOLVE-04 / D-01).  Only the session owner, assigned architect, or admin
    may complete a session.
    """
    # Verify access: only owner, architect, or admin may complete (D-23c).
    session_record = await _load_session_or_404(session_id)

    is_owner = auth.user_id == session_record.owner_id
    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    is_admin = auth.role == "admin"

    if not (is_owner or is_architect or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the session owner, assigned architect, or admin may complete a session",
        )

    # Obtain TaskQueue via platform DI — modules never construct TaskQueue directly.
    from aila.api.deps import get_task_queue

    task_queue = get_task_queue("sbd_nfr", request)

    return await session_service.complete_session(
        session_id,
        actor_name=auth.user_id,
        actor_email=auth.user_id,
        task_queue=task_queue,
    )


# ===========================================================================
# Resolution endpoints — D-02, D-11, D-13, D-14, D-18, RESOLVE-04, PLAT-03
# ===========================================================================


@_protected.post(
    "/sessions/{session_id}/resolve",
    response_model=ResolutionTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Manually trigger or retry resolution",
    tags=["resolution"],
)
async def trigger_resolution(
    request: Request,
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> ResolutionTriggerResponse:
    """Re-trigger resolution for a session in resolution_failed state (D-02).

    Only the session owner, assigned architect, or admin may trigger resolution.
    Rate limited to max 3 calls per session per hour (D-18 / T-135-07).
    Only allowed when session status is ``resolution_failed``.
    """
    from aila.api.deps import get_task_queue

    session_record = await _load_session_or_404(session_id)

    is_owner = auth.user_id == session_record.owner_id
    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    is_admin = auth.role == "admin"

    if not (is_owner or is_architect or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the session owner, assigned architect, or admin may trigger resolution",
        )

    # Only allow retry from resolution_failed (T-135-12)
    if session_record.status != "resolution_failed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Session is in '{session_record.status}' state. "
                "Manual retry is only allowed from 'resolution_failed' state."
            ),
        )

    # Rate limit: max 3 resolve calls per session per hour (D-18 / T-135-07)
    if _check_rate_limit(_resolve_rate_limits, session_id, 3, 3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: max 3 resolution attempts per session per hour",
        )

    # Obtain TaskQueue via platform DI before mutating session state.
    task_queue = get_task_queue("sbd_nfr", request)

    await session_service.update_session_status(session_id, "resolving")
    await task_queue.submit(
        track="sbd_nfr",
        fn=resolution_service.run_resolution,
        kwargs={"session_id": session_id},
        user_id=session_record.owner_id,
    )

    return ResolutionTriggerResponse(status="resolving", session_id=session_id)


@_protected.get(
    "/sessions/{session_id}/resolution",
    response_model=ResolutionResultResponse,
    summary="Get resolution classification results",
    tags=["resolution"],
)
async def get_resolution(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> ResolutionResultResponse:
    """Return the 25 SbD sub-task classification results for a session (D-11).

    Only the session owner, assigned architect, or admin may access results.
    Returns an empty components list when resolution has not yet completed.
    """
    from sqlmodel import select as sa_select

    from .db_models import SbdNfrSubtaskComponentRecord

    # Load session + RBAC check
    session_record = await _load_session_or_404(session_id)

    is_owner = auth.user_id == session_record.owner_id
    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    is_admin = auth.role == "admin"

    if not (is_owner or is_architect or is_admin):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    # Load resolution results (sessionless — manages own UoW)
    result_records = await resolution_service.get_resolution_results(session_id)

    # Load subtask label map
    async with UnitOfWork() as _uow:
        db = _uow.session
        subtask_label_map: dict[str, str] = {
            r.key: r.label for r in (await db.exec(sa_select(SbdNfrSubtaskComponentRecord))).all()
        }

    # Extract executive_summary from resolution_json on the session record
    executive_summary: str | None = None
    if session_record.resolution_json:
        try:
            resolution_data = json.loads(session_record.resolution_json)
            executive_summary = resolution_data.get("executive_summary")
        except (json.JSONDecodeError, AttributeError):
            executive_summary = None

    # resolved_at from first result record (all share the same timestamp)
    resolved_at = result_records[0].resolved_at if result_records else None

    components = [
        ComponentClassificationResponse(
            subtask_key=r.subtask_key,
            subtask_label=subtask_label_map.get(r.subtask_key, r.subtask_key),
            classification=r.classification,
            confidence=r.confidence,
            reasoning=r.reasoning,
            cited_question_ids=json.loads(r.cited_question_ids_json)
            if r.cited_question_ids_json
            else [],
        )
        for r in result_records
    ]

    return ResolutionResultResponse(
        session_id=session_id,
        status=session_record.status,
        resolved_at=resolved_at,
        components=components,
        executive_summary=executive_summary,
    )


@_protected.get(
    "/sessions/{session_id}/events",
    summary="Stream resolution SSE events (D-13, PLAT-03)",
    tags=["resolution"],
)
async def stream_session_events(
    session_id: str,
    last_id: str = Query(default="0", description="Redis Stream ID to start from"),
    auth: AuthContext = Depends(require_auth),
) -> StreamingResponse:
    """Stream resolution progress events for a session via SSE (D-13 / PLAT-03).

    Replays all events since ``last_id`` (late-connect replay), then streams
    live events.  Auto-terminates after ``resolution_completed`` or
    ``resolution_failed`` event (T-135-09).

    Yields ``text/event-stream`` response for use with the EventSource API.
    """
    # Verify session exists and caller has access before opening the stream
    session_record = await _load_session_or_404(session_id)

    is_owner = auth.user_id == session_record.owner_id
    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    is_admin = auth.role in ("operator", "admin")

    if not (is_owner or is_architect or is_admin):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    from aila.platform.services.redis_pool import get_redis

    try:
        async with get_redis() as client:
            await client.ping()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSE unavailable -- Redis not configured",
        ) from exc

    async def _generator() -> AsyncGenerator[str, None]:
        from aila.modules.sbd_nfr.services.event_stream import SessionEventStream

        stream = SessionEventStream()

        catchup_events = await stream.catchup_async(session_id, last_id)
        for event in catchup_events:
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("event") in ("resolution_completed", "resolution_failed"):
                return

        async for event in stream.astream_events(session_id, last_id):
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("event") in ("resolution_completed", "resolution_failed"):
                break

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@_protected.post(
    "/questions/{question_id}/assist",
    response_model=AssistResponse,
    summary="Get LLM assistance for a question",
    tags=["assist"],
)
async def assist_question(
    question_id: str,
    body: AssistRequest,
    auth: AuthContext = Depends(require_auth),
) -> AssistResponse:
    """Return a conversational LLM reply for a per-question assist request (D-14).

    Rate limited to max 20 messages per user per question per hour
    (D-18 / T-135-08).

    Security (T-135-13): user message placed in user role only.  History
    validated by Pydantic (max_length=40).  No system prompt injection possible.
    """
    rate_key = f"{auth.user_id}:{question_id}"
    if _check_rate_limit(_assist_rate_limits, rate_key, 20, 3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: max 20 assist messages per user per question per hour",
        )

    return await assist_service.handle_assist(
        question_id=question_id,
        request=body,
        actor_id=auth.user_id,
    )


@_protected.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a session",
    tags=["sessions"],
)
async def delete_session(
    session_id: str,
    hard: bool = Query(default=False, description="Admin-only: permanently delete all data"),
    auth: AuthContext = Depends(require_auth),
) -> None:
    """Delete a session (D-35a).

    - Standard (hard=False): soft-delete by setting is_deleted=True. Owner only.
    - Hard (hard=True): permanent deletion of session + all answers + activity. Admin only.
    """
    if hard and auth.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hard delete requires admin role",
        )

    if hard:
        await session_service.hard_delete_session(session_id)
    else:
        # Verify ownership before soft-delete.
        session_record = await _load_session_or_404(session_id)
        if auth.user_id != session_record.owner_id and auth.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the session owner or admin may delete this session",
            )
        await session_service.soft_delete_session(
            session_id, actor_name=auth.user_id, actor_email=auth.user_id
        )


@_protected.get(
    "/sessions/{session_id}/export",
    response_model=SessionDetailResponse,
    summary="Export a session as JSON",
    tags=["sessions"],
)
async def export_session(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> SessionDetailResponse:
    """Export the full session state as a typed Pydantic model (D-27)."""
    await _verify_session_read_access(session_id, auth)
    return await session_service.get_session_detail(session_id)


@_protected.post(
    "/sessions/{session_id}/assign",
    response_model=SessionSummaryResponse,
    summary="Assign an architect to a session",
    tags=["sessions"],
)
async def assign_architect(
    session_id: str,
    architect_id: str = Body(..., embed=True),
    auth: AuthContext = Depends(require_role("operator")),
) -> SessionSummaryResponse:
    """Assign an architect to a session (D-53).

    Requires operator or admin role.
    """
    return await session_service.assign_architect(
        session_id,
        architect_id=architect_id,
        actor_name=auth.user_id,
        actor_email=auth.user_id,
    )


@_protected.post(
    "/sessions/{session_id}/submit-for-review",
    response_model=SessionSummaryResponse,
    summary="Submit a resolved session for architect review",
    tags=["sessions"],
)
async def submit_for_review(
    session_id: str,
    body: SubmitForReviewRequest = Body(default_factory=SubmitForReviewRequest),
    auth: AuthContext = Depends(require_auth),
) -> SessionSummaryResponse:
    """Transition a session from resolved to in_review (Phase 145 D-01, D-02).

    Requires operator or admin role.  Transitions: resolved -> in_review.
    """
    if auth.role not in ("operator", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only operators and admins may submit sessions for review",
        )
    return await session_service.submit_for_review(
        session_id,
        notes=body.notes,
        actor_name=auth.user_id,
        actor_email=auth.user_id,
    )


@_protected.post(
    "/sessions/{session_id}/approve",
    response_model=SessionSummaryResponse,
    summary="Approve a session under architect review",
    tags=["sessions"],
)
async def approve_session(
    session_id: str,
    body: ApproveSessionRequest = Body(default_factory=ApproveSessionRequest),
    auth: AuthContext = Depends(require_auth),
) -> SessionSummaryResponse:
    """Transition a session from in_review to approved (Phase 145 D-01, D-02).

    Caller must be the assigned architect or an admin.
    Transitions: in_review -> approved.
    """
    session_record = await _load_session_or_404(session_id)

    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    if not (is_architect or auth.role == "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the assigned architect or admin may approve this session",
        )

    return await session_service.approve_session(
        session_id,
        notes=body.notes,
        actor_name=auth.user_id,
        actor_email=auth.user_id,
    )


@_protected.patch(
    "/sessions/{session_id}/architect-notes",
    response_model=SessionSummaryResponse,
    summary="Save architect notes on a session",
    tags=["sessions"],
)
async def save_architect_notes(
    session_id: str,
    body: ArchitectNotesRequest,
    auth: AuthContext = Depends(require_auth),
) -> SessionSummaryResponse:
    """Persist architect notes without changing session status (Phase 145 D-13).

    Caller must be the assigned architect or an admin.
    """
    session_record = await _load_session_or_404(session_id)

    is_architect = (
        session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )
    if not (is_architect or auth.role == "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the assigned architect or admin may save notes",
        )

    return await session_service.save_architect_notes(
        session_id,
        notes=body.notes,
        actor_name=auth.user_id,
        actor_email=auth.user_id,
    )


@_protected.get(
    "/sessions/{session_id}/activity",
    response_model=list[ActivityResponse],
    summary="Get session activity log",
    tags=["sessions"],
)
async def get_session_activity(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> list[ActivityResponse]:
    """Return the chronological activity log for a session (D-66)."""
    await _verify_session_read_access(session_id, auth)
    # activity_service.get_session_activity retains its db param for callers
    # that need atomicity with their own UoW.  Here we open a dedicated session.
    async with UnitOfWork() as _uow:
        db = _uow.session
        return await activity_service.get_session_activity(db, session_id)


# ---------------------------------------------------------------------------
# Bulk operations — D-61
# ---------------------------------------------------------------------------


@_protected.post(
    "/sessions/bulk-assign",
    response_model=BulkAssignResponse,
    summary="Bulk assign architect to multiple sessions",
    tags=["sessions"],
)
async def bulk_assign_architect(
    session_ids: list[str] = Body(..., embed=True, max_length=100),
    architect_id: str = Body(..., embed=True),
    auth: AuthContext = Depends(require_role("operator")),
) -> BulkAssignResponse:
    """Assign the same architect to multiple sessions in a single call (D-61). Capped at 100."""
    results: dict[str, str] = {}
    for session_id in session_ids:
        try:
            await session_service.assign_architect(
                session_id,
                architect_id=architect_id,
                actor_name=auth.user_id,
                actor_email=auth.user_id,
            )
            results[session_id] = "assigned"
        except HTTPException as exc:
            results[session_id] = f"error: {exc.detail}"
    return BulkAssignResponse(results=results)


@_protected.post(
    "/sessions/bulk-export",
    response_model=BulkExportResponse,
    summary="Export multiple sessions as JSON",
    tags=["sessions"],
)
async def bulk_export_sessions(
    session_ids: list[str] = Body(..., embed=True, max_length=50),
    auth: AuthContext = Depends(require_auth),
) -> BulkExportResponse:
    """Export multiple sessions in a single call (D-61).

    Returns a dict keyed by session_id.  Missing or inaccessible sessions
    are omitted with an error note.  Capped at 50 sessions per request.
    """
    exports: dict[str, Any] = {}
    for session_id in session_ids:
        try:
            await _verify_session_read_access(session_id, auth)
            exports[session_id] = await session_service.export_session(session_id)
        except HTTPException as exc:
            exports[session_id] = {"error": str(exc.detail)}
    return BulkExportResponse(exports=exports)


# ---------------------------------------------------------------------------
# Template operations — D-60
# ---------------------------------------------------------------------------


@_protected.post(
    "/sessions/{session_id}/save-as-template",
    response_model=SessionSummaryResponse,
    summary="Mark a session as a reusable template",
    tags=["sessions"],
)
async def save_as_template(
    session_id: str,
    template_name: str = Body(..., embed=True),
    auth: AuthContext = Depends(require_auth),
) -> SessionSummaryResponse:
    """Set is_template=True and assign a template_name (D-60).

    Only the session owner or admin may save a session as a template.
    """
    from sqlmodel import select as sa_select
    from sqlalchemy import update as sa_update

    from aila.platform.contracts._common import utc_now

    from .db_models import SbdNfrSessionRecord
    from .services.session_service import _session_to_summary

    async with UnitOfWork() as _uow:
        db = _uow.session
        session_record = (await db.exec(
            sa_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session_record is None or session_record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found",
            )

        if auth.user_id != session_record.owner_id and auth.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the session owner or admin may save a template",
            )

        await db.exec(
            sa_update(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.id == session_id)
            .values(
                is_template=True,
                template_name=template_name,
                updated_at=utc_now(),
            )
        )
        await db.commit()

        updated = (await db.exec(
            sa_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Unexpected error after update")
        return _session_to_summary(updated)


# ===========================================================================
# Dashboard — D-48
# ===========================================================================


@_protected.get(
    "/dashboard/stats",
    response_model=DashboardStatsResponse,
    summary="Get dashboard statistics",
    tags=["dashboard"],
)
async def get_dashboard_stats(
    _auth: AuthContext = Depends(require_role("operator")),
) -> DashboardStatsResponse:
    """Return aggregate session and answer statistics for the dashboard (D-48).

    Requires operator or admin role.
    """
    return await stats_service.get_dashboard_stats()


# ===========================================================================
# Artifact endpoints — D-11, D-12, D-13, REPORT-05
# ===========================================================================


@_protected.get(
    "/sessions/{session_id}/artifacts/report/preview",
    summary="Get report HTML preview",
    tags=["artifacts"],
)
async def get_report_preview(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> HTMLResponse:
    """Return the pre-meeting report as an HTML page for in-browser preview.

    Generates on-demand from current resolution results (D-11).
    Access restricted to session owner, assigned architect, or admin (D-13).
    """
    await _verify_session_read_access(session_id, auth)
    from .reporting import generate_report_html
    html = await generate_report_html(session_id)
    return HTMLResponse(content=html)


@_protected.get(
    "/sessions/{session_id}/artifacts/report/pdf",
    summary="Download report as PDF",
    tags=["artifacts"],
)
async def download_report_pdf(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> StreamingResponse:
    """Return the pre-meeting report as a PDF file download.

    Generates on-demand (D-11). Stores SHA-256 hash on first generation (EXEC-04).
    Hash is stored only once — subsequent downloads use the existing hash value.
    """
    import hashlib

    from sqlmodel import select as sa_select

    from aila.platform.contracts._common import utc_now

    from .db_models import SbdNfrSessionRecord

    await _verify_session_read_access(session_id, auth)

    from .reporting import generate_report_pdf
    pdf_bytes = await generate_report_pdf(session_id)

    # EXEC-04: compute and store SHA-256 hash on first generation.
    # If the column already has a value, do not overwrite — the stored hash
    # certifies that specific artifact generation event.
    async with UnitOfWork() as _uow:
        db = _uow.session
        session_record = (await db.exec(
            sa_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session_record is not None and session_record.report_hash_sha256 is None:
            hex_digest = hashlib.sha256(pdf_bytes).hexdigest()
            session_record.report_hash_sha256 = hex_digest
            session_record.report_hash_generated_at = utc_now()
            await db.commit()
        else:
            hex_digest = session_record.report_hash_sha256 if session_record else None

    response_headers: dict[str, str] = {
        "Content-Disposition": f'attachment; filename="nfr_report_{session_id[:8]}.pdf"',
    }
    if hex_digest:
        response_headers["X-Report-Hash"] = hex_digest

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers=response_headers,
    )


@_protected.get(
    "/sessions/{session_id}/artifacts/workbook",
    summary="Download NFR workbook as XLSX",
    tags=["artifacts"],
)
async def download_workbook(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> StreamingResponse:
    """Return the NFR Excel workbook as an .xlsx file download.

    Generates on-demand from current resolution results and captured answers (D-11).
    """
    await _verify_session_read_access(session_id, auth)
    from .reporting import generate_workbook
    xlsx_bytes = await generate_workbook(session_id)
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="nfr_workbook_{session_id[:8]}.xlsx"'},
    )


@_protected.get(
    "/sessions/{session_id}/artifacts/jira-draft",
    summary="Get Jira work-item draft as JSON",
    tags=["artifacts"],
)
async def get_jira_draft(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> Any:
    """Return the Jira work-item draft as JSON.

    Generates on-demand (D-11). Returns JiraWorkItemDraft with parent issue
    and sub-task dicts matching Jira REST API v2 create-issue schema (D-09).
    """
    await _verify_session_read_access(session_id, auth)
    from .reporting import generate_jira_draft
    return await generate_jira_draft(session_id)


@_protected.get(
    "/sessions/{session_id}/artifacts/report/hash",
    summary="Get SbD report integrity hash (EXEC-04)",
    tags=["artifacts"],
)
async def get_report_hash(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
) -> Any:
    """Return the SHA-256 integrity hash for the SbD report PDF (EXEC-04).

    The hash is computed and stored on the FIRST call to the PDF download endpoint.
    Subsequent calls return the same stored hash -- it certifies that specific artifact.

    Response shape:
      {"data": {"session_id": str, "sha256": str|None, "computed_at": str|None,
                 "status": "available"|"not_generated"}}

    Returns 404 if session does not exist or caller lacks read access.
    """
    from aila.api.schemas.envelope import DataEnvelope

    await _verify_session_read_access(session_id, auth)
    session_record = await _load_session_or_404(session_id)

    computed_at_str: str | None = None
    if session_record.report_hash_generated_at is not None:
        computed_at_str = session_record.report_hash_generated_at.isoformat()

    hash_status = "available" if session_record.report_hash_sha256 else "not_generated"

    return DataEnvelope(
        data={
            "session_id": session_id,
            "sha256": session_record.report_hash_sha256,
            "computed_at": computed_at_str,
            "status": hash_status,
        }
    )

# ===========================================================================
# Shared (dual-auth) routes
# ===========================================================================


@_shared.get(
    "/sessions/{session_id}",
    response_model=SessionDetailResponse,
    summary="Get full session state snapshot",
    tags=["sessions"],
)
async def get_session_detail(
    session_id: str,
    access: SessionAccessContext = Depends(require_session_access),
) -> SessionDetailResponse:
    """Return the full session state snapshot (D-32).

    Accepts either a Bearer JWT or ?share_token= query param (dual-auth).
    Share-token contributors can view the session to fill out their answers.
    """
    return await session_service.get_session_detail(session_id)


@_shared.patch(
    "/sessions/{session_id}/sections/{section_key}/answers",
    response_model=SectionProgressResponse,
    summary="Bulk save answers for a section",
    tags=["sessions"],
)
async def bulk_save_answers(
    session_id: str,
    section_key: str,
    body: BulkAnswerRequest,
    access: SessionAccessContext = Depends(require_session_access),
) -> SectionProgressResponse:
    """Bulk-upsert answers for one section in a single transaction (D-31).

    Accepts either a Bearer JWT or ?share_token= query param (dual-auth).
    Share-token contributors may submit answers but cannot complete the session.

    Returns updated section progress after saving.
    """
    if not access.can_edit_answers:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to edit answers for this session",
        )

    async with UnitOfWork() as _uow:
        db = _uow.session
        # Resolve schema_version from the session record.
        from sqlmodel import select as sa_select

        from .db_models import SbdNfrSessionRecord

        session_record = (await db.exec(
            sa_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session_record is None or session_record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found",
            )

        return await answer_service.bulk_upsert_answers(
            db,
            session_id=session_id,
            section_key=section_key,
            answers=body.answers,
            contributor_name=access.contributor_name or (access.user_id or ""),
            contributor_email=access.contributor_email or (access.user_id or ""),
            schema_version=session_record.schema_version_at_start,
        )


# ===========================================================================
# Triage context endpoint — TRIAGE-01, TRIAGE-02
# ===========================================================================


@_protected.get(
    "/systems/{system_id}/triage-context",
    summary="Get pre-triage context for a system from its most recently completed NFR session",
    response_model=TriageContextResponse | None,
)
async def get_system_triage_context(
    system_id: int,
    auth: AuthContext = Depends(require_auth),
) -> TriageContextResponse | None:
    """Return the most recent pre-triage risk context for a registered system.

    Queries SbdNfrSessionSystemRecord for the most recently completed session
    linked to this system and returns the stored pre_triage_context_json.

    Returns null (HTTP 200 with null body) if the system has no completed
    NFR session -- this is not an error condition (TRIAGE-01).

    The context object contains:
      - data_sensitivity: raw scope answer (e.g. "pii", "confidential")
      - internet_exposure: raw scope answer (e.g. "internet_facing", "internal")
      - business_impact_tier: "critical"|"high"|"medium"|"low"|"unknown"
      - risk_tier: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
      - severity_multiplier: float used to adjust finding CVSS scores (TRIAGE-03, TRIAGE-04)

    Security: requires JWT Bearer token (T-154-09).
    system_id is an ORM-parameterised path param — SQL injection mitigated (T-154-08).
    """
    from sqlmodel import select as sa_select

    from .db_models import SbdNfrSessionRecord, SbdNfrSessionSystemRecord

    # Completed-or-later statuses that indicate a session has been scored.
    _completed_statuses = (
        "completed",
        "resolving",
        "resolved",
        "in_review",
        "approved",
        "report_generated",
        "resolution_failed",
    )

    async with UnitOfWork() as _uow:
        db = _uow.session
        stmt = (
            sa_select(SbdNfrSessionSystemRecord)
            .join(
                SbdNfrSessionRecord,
                SbdNfrSessionSystemRecord.session_id == SbdNfrSessionRecord.id,
            )
            .where(SbdNfrSessionSystemRecord.system_id == system_id)
            .where(SbdNfrSessionRecord.status.in_(_completed_statuses))
            .where(SbdNfrSessionSystemRecord.pre_triage_context_json.isnot(None))
            .order_by(SbdNfrSessionSystemRecord.updated_at.desc())
            .limit(1)
        )
        link = (await db.exec(stmt)).first()

    if link is None or link.pre_triage_context_json is None:
        return None
    return TriageContextResponse.model_validate(json.loads(link.pre_triage_context_json))


# ===========================================================================
# Router factory
# ===========================================================================


def create_sbd_nfr_router() -> APIRouter:
    """Factory called by ModuleRouteSpec for protected (JWT-required) routes.

    Returns only the _protected sub-router.  The _shared sub-router is
    returned by create_sbd_nfr_shared_router() so the platform can mount
    it WITHOUT the global require_user_or_api_key dependency — share-token
    contributors must be able to access those endpoints without a JWT.
    """
    router = APIRouter(tags=["sbd_nfr"])
    router.include_router(_protected)
    return router


def create_sbd_nfr_shared_router() -> APIRouter:
    """Factory for dual-auth (JWT or share-token) routes.

    Mounted under the same /sbd_nfr prefix but WITHOUT the global
    require_user_or_api_key dependency.  Each handler uses
    require_session_access to validate either a Bearer JWT or a
    ?share_token= query parameter.
    """
    router = APIRouter(tags=["sbd_nfr"])
    router.include_router(_shared)
    return router
