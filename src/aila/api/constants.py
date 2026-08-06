"""Named constants for the AILA API layer.

Replaces hardcoded string literals scattered across routers and auth code.
Grouped by domain: roles, JWT/auth, content types, audit events, tracks.
"""
from __future__ import annotations

__all__ = [
    # Roles
    "ROLE_ADMIN",
    "ROLE_OPERATOR",
    "ROLE_READER",
    "VALID_ROLES",
    # JWT / auth
    "JWT_ALGORITHM",
    "JWT_TYP_ACCESS",
    "JWT_TYP_REFRESH",
    "JWT_TYP_USER_ACCESS",
    "JWT_TYP_USER_REFRESH",
    "TOKEN_TYPE_BEARER",
    # Media types
    "MEDIA_TYPE_SSE",
    # Audit events
    "AUDIT_STAGE_AUTH",
    "AUDIT_STAGE_CONFIG",
    "AUDIT_STAGE_SCAN",
    "AUDIT_STAGE_SESSION",
    "AUDIT_STAGE_SYSTEM",
    "AUDIT_STAGE_TASK",
    "AUDIT_STAGE_TOOL",
    "AUDIT_STAGE_FINDING",
    "AUDIT_ACTION_CREATE_API_KEY",
    "AUDIT_ACTION_REVOKE_API_KEY",
    "AUDIT_ACTION_TOKEN_ISSUE",
    "AUDIT_ACTION_TOKEN_REFRESH",
    "AUDIT_ACTION_CONFIG_UPDATE",
    "AUDIT_ACTION_SCAN_SUBMIT",
    "AUDIT_ACTION_SESSION_CREATE",
    "AUDIT_ACTION_SESSION_MESSAGE",
    "AUDIT_ACTION_SYSTEM_CREATE",
    "AUDIT_ACTION_SYSTEM_UPDATE",
    "AUDIT_ACTION_SYSTEM_DELETE",
    "AUDIT_ACTION_TASK_CANCEL",
    "AUDIT_ACTION_TASK_RESUME",
    "AUDIT_ACTION_TASK_SUBMIT",
    "AUDIT_ACTION_TOOL_INVOKE",
    "AUDIT_ACTION_FINDING_BULK_UPDATE",
    "AUDIT_STATUS_COMPLETED",
    # Track names
    "TRACK_PLATFORM",
    # Module IDs
    "MODULE_ID_PLATFORM",
]

# --- Roles ----------------------------------------------------------------
ROLE_ADMIN: str = "admin"
ROLE_OPERATOR: str = "operator"
ROLE_READER: str = "reader"
VALID_ROLES: frozenset[str] = frozenset({ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER})

# --- JWT / auth ------------------------------------------------------------
JWT_ALGORITHM: str = "HS256"
JWT_TYP_ACCESS: str = "access"
JWT_TYP_REFRESH: str = "refresh"
JWT_TYP_USER_ACCESS: str = "user_access"
JWT_TYP_USER_REFRESH: str = "user_refresh"
TOKEN_TYPE_BEARER: str = "bearer"

# --- Media types -----------------------------------------------------------
MEDIA_TYPE_SSE: str = "text/event-stream"

# --- Audit events ----------------------------------------------------------
AUDIT_STAGE_AUTH: str = "auth"
AUDIT_STAGE_CONFIG: str = "config"
AUDIT_STAGE_SCAN: str = "scan"
AUDIT_STAGE_SESSION: str = "session"
AUDIT_STAGE_SYSTEM: str = "system"
AUDIT_STAGE_TASK: str = "task"
AUDIT_STAGE_TOOL: str = "tool"
AUDIT_STAGE_FINDING: str = "finding"
AUDIT_ACTION_CREATE_API_KEY: str = "create_api_key"
AUDIT_ACTION_REVOKE_API_KEY: str = "revoke_api_key"
AUDIT_ACTION_TOKEN_ISSUE: str = "token_issue"
AUDIT_ACTION_TOKEN_REFRESH: str = "token_refresh"
AUDIT_ACTION_CONFIG_UPDATE: str = "config_update"
AUDIT_ACTION_SCAN_SUBMIT: str = "scan_submit"
AUDIT_ACTION_SESSION_CREATE: str = "session_create"
AUDIT_ACTION_SESSION_MESSAGE: str = "session_message"
AUDIT_ACTION_SYSTEM_CREATE: str = "system_create"
AUDIT_ACTION_SYSTEM_UPDATE: str = "system_update"
AUDIT_ACTION_SYSTEM_DELETE: str = "system_delete"
AUDIT_ACTION_TASK_CANCEL: str = "task_cancel"
AUDIT_ACTION_TASK_RESUME: str = "task_resume"
AUDIT_ACTION_TASK_SUBMIT: str = "task_submit"
AUDIT_ACTION_TOOL_INVOKE: str = "tool_invoke"
AUDIT_ACTION_FINDING_BULK_UPDATE: str = "finding_bulk_update"
AUDIT_STATUS_COMPLETED: str = "completed"

# --- Track names -----------------------------------------------------------
TRACK_PLATFORM: str = "platform"

# --- Module IDs ------------------------------------------------------------
MODULE_ID_PLATFORM: str = "__platform__"
