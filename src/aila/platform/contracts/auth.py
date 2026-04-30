"""Platform auth contract — types and dependencies modules may import.

Modules MUST import auth primitives from here, NOT from aila.api.auth.
The API layer is a platform implementation detail; this contract is the
stable surface modules depend on.
"""
from __future__ import annotations

__all__ = [
    "AuthContext",
    "TeamContext",
    "decode_and_verify_token",
    "get_team_context",
    "require_auth",
    "require_role",
]

# Re-export from the implementation — modules see only the contract surface.
from aila.api.auth import AuthContext, TeamContext, get_team_context, require_role
from aila.api.auth import decode_and_blacklist_check as decode_and_verify_token
from aila.api.auth import require_user_or_api_key as require_auth
