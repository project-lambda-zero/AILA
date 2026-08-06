"""Multi-target investigation service.

Operator attaches / lists / detaches secondary targets on an existing
investigation. The primary target stays on the investigation row; secondary
targets live exclusively in the module's investigation-target attachment table.

Generic over the module: a concrete subclass binds the record models, the role
enum, and the summary contract as class variables. The platform base owns the
attach / list / detach logic and never names a module.
"""
from __future__ import annotations

import logging
from typing import Any, ClassVar

from sqlmodel import select as _select

from aila.platform.uow import UnitOfWork

__all__ = [
    "MultiTargetServiceBase",
    "MultiTargetServiceError",
]

_log = logging.getLogger(__name__)


class MultiTargetServiceError(Exception):
    """User-facing errors (missing FK, duplicate attachment, primary detach)."""


class MultiTargetServiceBase:
    """Attach + list + detach secondary targets on an investigation.

    A concrete subclass MUST set ``_investigation_model``, ``_target_model``,
    ``_attachment_model``, ``_role_enum``, and ``_summary_cls``.
    """

    _investigation_model: ClassVar[type]
    _target_model: ClassVar[type]
    _attachment_model: ClassVar[type]
    _role_enum: ClassVar[Any]
    _summary_cls: ClassVar[type]

    def _to_summary(self, record: Any) -> Any:
        return self._summary_cls(
            id=record.id,
            investigation_id=record.investigation_id,
            target_id=record.target_id,
            role=self._role_enum(record.role),
            rationale=record.rationale or "",
            attached_at=record.attached_at,
        )

    async def attach(
        self,
        investigation_id: str,
        target_id: str,
        role: Any,
        rationale: str,
        team_id: str | None,
    ) -> Any:
        if role == self._role_enum.PRIMARY:
            raise MultiTargetServiceError(
                "PRIMARY role is reserved for the investigation's own primary "
                "target column. Use a different role (comparison / "
                "parallel_codebase / parent_library / derived_fork) for "
                "secondary attachments.",
            )

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(self._investigation_model).where(
                    self._investigation_model.id == investigation_id,
                ),
            )).first()
            if inv is None:
                raise MultiTargetServiceError(
                    f"investigation {investigation_id} not found",
                )

            target = (await uow.session.exec(
                _select(self._target_model).where(
                    self._target_model.id == target_id,
                ),
            )).first()
            if target is None:
                raise MultiTargetServiceError(
                    f"target {target_id} not found",
                )

            # Disallow attaching the primary target a second time as a
            # secondary -- it's already the primary.
            if inv.target_id == target_id:
                raise MultiTargetServiceError(
                    f"target {target_id} is already this investigation's primary "
                    "target; secondary attachments must be different targets",
                )

            existing = (await uow.session.exec(
                _select(self._attachment_model).where(
                    self._attachment_model.investigation_id == investigation_id,
                    self._attachment_model.target_id == target_id,
                ),
            )).first()
            if existing is not None:
                # Idempotent -- update role + rationale if changed.
                mutated = False
                if existing.role != role.value:
                    existing.role = role.value
                    mutated = True
                if rationale and existing.rationale != rationale:
                    existing.rationale = rationale
                    mutated = True
                if mutated:
                    uow.session.add(existing)
                    await uow.session.commit()
                    await uow.session.refresh(existing)
                return self._to_summary(existing)

            record = self._attachment_model(
                team_id=team_id,
                investigation_id=investigation_id,
                target_id=target_id,
                role=role.value,
                rationale=rationale or "",
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            return self._to_summary(record)

    async def list_for_investigation(
        self, investigation_id: str,
    ) -> list[Any]:
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(self._attachment_model)
                .where(self._attachment_model.investigation_id == investigation_id)
                .order_by(self._attachment_model.attached_at.asc()),
            )).all()
            return [self._to_summary(r) for r in rows]

    async def detach(
        self, investigation_id: str, target_id: str,
    ) -> bool:
        """Detach a secondary target. Returns True if a row was removed."""
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(self._investigation_model).where(
                    self._investigation_model.id == investigation_id,
                ),
            )).first()
            if inv is None:
                raise MultiTargetServiceError(
                    f"investigation {investigation_id} not found",
                )
            if inv.target_id == target_id:
                raise MultiTargetServiceError(
                    f"cannot detach the investigation's primary target "
                    f"({target_id}). Detaching the primary would orphan the "
                    "investigation; archive the investigation instead.",
                )

            existing = (await uow.session.exec(
                _select(self._attachment_model).where(
                    self._attachment_model.investigation_id == investigation_id,
                    self._attachment_model.target_id == target_id,
                ),
            )).first()
            if existing is None:
                return False
            await uow.session.delete(existing)
            await uow.session.commit()
            return True
