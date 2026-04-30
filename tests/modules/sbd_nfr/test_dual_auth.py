"""Unit tests for SessionAccessContext and _VALID_TRANSITIONS (Phase 134, Plan 03).

These tests are pure — no DB, no HTTP, no async fixtures required.
They verify the D-20 state machine and the D-23a/b/c permission model.
"""

from __future__ import annotations

import pytest

from aila.modules.sbd_nfr.services.auth import SessionAccessContext
from aila.modules.sbd_nfr.services.session_service import _VALID_TRANSITIONS


# ---------------------------------------------------------------------------
# SessionAccessContext property tests
# ---------------------------------------------------------------------------


class TestOwnerPermissions:
    def _ctx(self) -> SessionAccessContext:
        return SessionAccessContext(session_id="s1", is_owner=True, user_id="u1", user_role="operator")

    def test_can_complete(self) -> None:
        assert self._ctx().can_complete is True

    def test_can_edit_answers(self) -> None:
        assert self._ctx().can_edit_answers is True

    def test_can_delete(self) -> None:
        assert self._ctx().can_delete is True


class TestArchitectPermissions:
    def _ctx(self) -> SessionAccessContext:
        return SessionAccessContext(session_id="s1", is_architect=True, user_id="u2", user_role="operator")

    def test_can_complete(self) -> None:
        assert self._ctx().can_complete is True

    def test_can_edit_answers(self) -> None:
        assert self._ctx().can_edit_answers is True

    def test_cannot_delete(self) -> None:
        # D-35a: only owner or admin can delete; architect cannot.
        assert self._ctx().can_delete is False


class TestShareTokenContributorPermissions:
    def _ctx(self) -> SessionAccessContext:
        return SessionAccessContext(
            session_id="s1",
            is_share_token_contributor=True,
            contributor_name="Alice",
            contributor_email="alice@example.com",
            user_role="contributor",
        )

    def test_cannot_complete(self) -> None:
        # T-134-09: contributor cannot complete session.
        assert self._ctx().can_complete is False

    def test_can_edit_answers(self) -> None:
        assert self._ctx().can_edit_answers is True

    def test_cannot_delete(self) -> None:
        assert self._ctx().can_delete is False


class TestAdminPermissions:
    def _ctx(self) -> SessionAccessContext:
        return SessionAccessContext(session_id="s1", is_admin=True, user_id="u3", user_role="admin")

    def test_can_complete(self) -> None:
        assert self._ctx().can_complete is True

    def test_cannot_edit_answers_via_contributor_path(self) -> None:
        # Admin can edit via their own JWT session, not via the contributor path.
        assert self._ctx().can_edit_answers is False

    def test_can_delete(self) -> None:
        assert self._ctx().can_delete is True


class TestDefaultPermissions:
    """A bare SessionAccessContext with all booleans at their defaults."""

    def _ctx(self) -> SessionAccessContext:
        return SessionAccessContext(session_id="s1")

    def test_cannot_complete(self) -> None:
        assert self._ctx().can_complete is False

    def test_cannot_edit_answers(self) -> None:
        assert self._ctx().can_edit_answers is False

    def test_cannot_delete(self) -> None:
        assert self._ctx().can_delete is False


# ---------------------------------------------------------------------------
# _VALID_TRANSITIONS state machine tests (D-20)
# ---------------------------------------------------------------------------


class TestValidTransitions:
    def test_has_exactly_ten_states(self) -> None:
        # v3.0 workflow: draft, in_progress, completed, resolving, resolved,
        # in_review, approved, report_generated, resolution_failed, expired
        assert len(_VALID_TRANSITIONS) == 10

    def test_draft_leads_to_in_progress(self) -> None:
        assert "in_progress" in _VALID_TRANSITIONS["draft"]

    def test_in_progress_leads_to_completed(self) -> None:
        assert "completed" in _VALID_TRANSITIONS["in_progress"]

    def test_completed_leads_to_resolving(self) -> None:
        assert "resolving" in _VALID_TRANSITIONS["completed"]

    def test_resolving_leads_to_resolved_and_resolution_failed(self) -> None:
        targets = _VALID_TRANSITIONS["resolving"]
        assert "resolved" in targets
        assert "resolution_failed" in targets

    def test_resolved_leads_to_in_review(self) -> None:
        # v3.0 workflow: resolved -> in_review (approval workflow)
        assert "in_review" in _VALID_TRANSITIONS["resolved"]

    def test_resolution_failed_is_retryable(self) -> None:
        # D-24: resolution_failed -> resolving (retry).
        assert "resolving" in _VALID_TRANSITIONS["resolution_failed"]

    def test_expired_is_revivable(self) -> None:
        # D-62: expired -> draft (revive).
        assert "draft" in _VALID_TRANSITIONS["expired"]
