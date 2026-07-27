"""#36 -- OIDC auto-provision resolves the IdP-issued role.

The previous implementation hardcoded ``role=\"operator\"`` for every OIDC
sign-in, so an identity provider whose users are intended to be admins or
read-only saw every account collapse to the same fixed role. The helper
:func:`aila.api.routers.oidc._resolve_oidc_role` now honours a scalar
``role`` claim or the first valid entry of a ``roles`` array, validates
against :data:`VALID_ROLES` (so a hostile IdP cannot inject an unknown
value), and falls back to :data:`ROLE_OPERATOR` when no usable claim is
present.
"""

from __future__ import annotations

from aila.api.constants import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER
from aila.api.routers.oidc import _resolve_oidc_role


def test_scalar_role_claim_resolves_to_admin() -> None:
    assert _resolve_oidc_role({"role": ROLE_ADMIN}) == ROLE_ADMIN


def test_scalar_role_claim_resolves_to_reader() -> None:
    assert _resolve_oidc_role({"role": ROLE_READER}) == ROLE_READER


def test_scalar_role_claim_resolves_to_operator() -> None:
    assert _resolve_oidc_role({"role": ROLE_OPERATOR}) == ROLE_OPERATOR


def test_roles_array_claim_picks_first_valid() -> None:
    """A ``roles`` array claim uses the first entry that is a known role."""
    assert (
        _resolve_oidc_role({"roles": ["superuser", ROLE_ADMIN, ROLE_OPERATOR]})
        == ROLE_ADMIN
    )


def test_unknown_scalar_role_falls_back_to_operator() -> None:
    """A ``role`` claim outside VALID_ROLES MUST NOT be honoured."""
    assert _resolve_oidc_role({"role": "superuser"}) == ROLE_OPERATOR


def test_unknown_roles_array_falls_back_to_operator() -> None:
    """A ``roles`` array with no valid entries falls back to operator."""
    assert (
        _resolve_oidc_role({"roles": ["superuser", "root", "wheel"]})
        == ROLE_OPERATOR
    )


def test_missing_claims_falls_back_to_operator() -> None:
    """No ``role``/``roles`` claim -> safe default operator (backward compat)."""
    assert _resolve_oidc_role({"sub": "user-1", "email": "u@example.com"}) == ROLE_OPERATOR


def test_non_string_role_claim_falls_back_to_operator() -> None:
    """A non-string ``role`` claim (int, dict, list) MUST fall back safely."""
    assert _resolve_oidc_role({"role": 1}) == ROLE_OPERATOR
    assert _resolve_oidc_role({"role": {"kind": "admin"}}) == ROLE_OPERATOR
    assert _resolve_oidc_role({"role": [ROLE_ADMIN]}) == ROLE_OPERATOR


def test_roles_list_with_non_strings_is_skipped() -> None:
    """Non-string entries in ``roles`` are skipped; the first valid string wins."""
    assert _resolve_oidc_role({"roles": [None, 42, ROLE_READER]}) == ROLE_READER
