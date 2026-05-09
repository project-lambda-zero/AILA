"""Services package for the SbD NFR module.

Re-exports skip logic engine, schema service, session service, auth
dependency functions, activity logging, dashboard stats, smart search,
resolution service, and assist service so callers can import from the
package surface:

    from aila.modules.sbd_nfr.services import compute_visible_question_ids
    from aila.modules.sbd_nfr.services import get_schema_tree
    from aila.modules.sbd_nfr.services import SessionAccessContext
    from aila.modules.sbd_nfr.services import create_session
    from aila.modules.sbd_nfr.services import bulk_upsert_answers
    from aila.modules.sbd_nfr.services import log_activity, get_session_activity
    from aila.modules.sbd_nfr.services import get_dashboard_stats
    from aila.modules.sbd_nfr.services import smart_search
    from aila.modules.sbd_nfr.services import run_resolution, get_resolution_results
    from aila.modules.sbd_nfr.services import handle_assist
"""

from __future__ import annotations

from .activity_service import (
    EVENT_ANSWERS_SAVED,
    EVENT_LINK_ACCESSED,
    EVENT_RESOLUTION_COMPLETED,
    EVENT_RESOLUTION_FAILED,
    EVENT_RESOLUTION_STARTED,
    EVENT_SESSION_ASSIGNED,
    EVENT_SESSION_CLONED,
    EVENT_SESSION_COMPLETED,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_DELETED,
    get_session_activity,
    log_activity,
)
from .answer_service import (
    bulk_upsert_answers,
    compute_all_section_progress,
    validate_answer,
    validate_completion,
)
from .assist_service import handle_assist
from .auth import (
    SessionAccessContext,
    require_jwt_session_owner,
    require_session_access,
)
from .resolution_service import (
    CONFIDENCE_THRESHOLD,
    get_resolution_results,
    run_resolution,
)
from .schema_service import (
    create_question,
    create_section,
    deactivate_question,
    deactivate_section,
    get_current_schema_version,
    get_schema_tree,
    get_subtask_components,
    update_question,
    update_section,
)
from .search_service import smart_search
from .session_service import (
    PaginatedResponse,
    SessionListFilters,
    assign_architect,
    clone_session,
    complete_session,
    create_session,
    export_session,
    get_session_detail,
    hard_delete_session,
    list_sessions,
    soft_delete_session,
    update_session_status,
)
from .skip_logic import (
    QuestionSkipInfo,
    SectionProgressResult,
    SectionSkipInfo,
    compute_section_progress,
    compute_visible_question_ids,
    compute_visible_section_ids,
)
from .stats_service import get_dashboard_stats

__all__ = [
    # activity_service.py
    "EVENT_SESSION_CREATED",
    "EVENT_SESSION_CLONED",
    "EVENT_LINK_ACCESSED",
    "EVENT_ANSWERS_SAVED",
    "EVENT_SESSION_COMPLETED",
    "EVENT_SESSION_ASSIGNED",
    "EVENT_SESSION_DELETED",
    "EVENT_RESOLUTION_STARTED",
    "EVENT_RESOLUTION_COMPLETED",
    "EVENT_RESOLUTION_FAILED",
    "log_activity",
    "get_session_activity",
    # skip_logic.py
    "QuestionSkipInfo",
    "SectionSkipInfo",
    "SectionProgressResult",
    "compute_visible_question_ids",
    "compute_visible_section_ids",
    "compute_section_progress",
    # schema_service.py
    "get_current_schema_version",
    "get_schema_tree",
    "get_subtask_components",
    "create_section",
    "update_section",
    "deactivate_section",
    "create_question",
    "update_question",
    "deactivate_question",
    # answer_service.py
    "bulk_upsert_answers",
    "validate_answer",
    "validate_completion",
    "compute_all_section_progress",
    # auth.py
    "SessionAccessContext",
    "require_session_access",
    "require_jwt_session_owner",
    # session_service.py
    "SessionListFilters",
    "PaginatedResponse",
    "create_session",
    "get_session_detail",
    "list_sessions",
    "clone_session",
    "complete_session",
    "soft_delete_session",
    "hard_delete_session",
    "export_session",
    "assign_architect",
    "update_session_status",
    # stats_service.py
    "get_dashboard_stats",
    # search_service.py
    "smart_search",
    # resolution_service.py
    "CONFIDENCE_THRESHOLD",
    "run_resolution",
    "get_resolution_results",
    # assist_service.py
    "handle_assist",
]
