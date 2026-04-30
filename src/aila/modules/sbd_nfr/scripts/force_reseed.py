"""Force-reseed dev command for rapid content iteration.

Wipes ALL SbD NFR data — session records AND questionnaire schema seed data —
then re-runs seed_data() atomically within a single transaction.

WARNING: This is a DESTRUCTIVE operation intended for development use only.
It wipes session/answer/activity/resolution data AND all seed tables.
A confirmation prompt is shown unless --force is supplied.

Tables wiped (in FK-safe order):
    Session tables (wiped first — they reference seed tables):
    1. SbdNfrResolutionResultRecord  (references sessions)
    2. SbdNfrActivityRecord          (references sessions)
    3. SbdNfrAnswerRecord            (references sessions + questions)
    4. SbdNfrSessionSystemRecord     (references sessions)
    5. SbdNfrSessionRecord           (base session record)

    Seed tables (wiped after session tables):
    6. SbdNfrQuestionSubtaskMapRecord  (references questions + subtasks)
    7. SbdNfrQuestionOptionRecord      (references questions)
    8. SbdNfrQuestionRecord            (references subgroups)
    9. SbdNfrSubgroupRecord            (references sections)
    10. SbdNfrSectionRecord            (references schema versions)
    11. SbdNfrSchemaVersionRecord
    12. SbdNfrSubtaskComponentRecord   (wipe-then-re-insert acceptable for dev)
    13. SeedVersionRecord              (where module_id = "sbd_nfr")

Usage:
    python -m aila.modules.sbd_nfr.scripts.force_reseed
    python -m aila.modules.sbd_nfr.scripts.force_reseed --force
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Any

_log = logging.getLogger(__name__)

# Ordered list of model classes to wipe — FK-safe deletion order.
# Session tables MUST precede seed tables because AnswerRecord references
# QuestionRecord.  This constant is also used by tests to verify the wipe order.
WIPE_ORDER = [
    # Session tables (FK-safe order) — wiped first per D-01
    "SbdNfrResolutionResultRecord",
    "SbdNfrActivityRecord",
    "SbdNfrAnswerRecord",
    "SbdNfrSessionSystemRecord",
    "SbdNfrSessionRecord",
    # Seed tables (existing FK-safe order)
    "SbdNfrQuestionSubtaskMapRecord",
    "SbdNfrQuestionOptionRecord",
    "SbdNfrQuestionRecord",
    "SbdNfrSubgroupRecord",
    "SbdNfrSectionRecord",
    "SbdNfrSchemaVersionRecord",
    "SbdNfrSubtaskComponentRecord",
]

MODULE_ID = "sbd_nfr"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for force_reseed.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:] when None.

    Returns:
        Parsed namespace with ``force`` boolean attribute.
    """
    parser = argparse.ArgumentParser(
        description="Force-reseed SbD NFR questionnaire data (destructive dev operation)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt and proceed immediately",
    )
    return parser.parse_args(argv)


async def verify_reseed(session: Any) -> bool:
    """Verify all seed data counts match expected values per D-03.

    Runs SQL count queries after seed_data() completes and prints a status
    line for each check.  Returns True only when all checks pass.

    Args:
        session: An active async SQLModel session (within an open transaction).

    Returns:
        True if all verification checks pass, False if any fail.
    """
    from sqlmodel import func, select

    from aila.modules.sbd_nfr.db_models import (
        SbdNfrQuestionOptionRecord,
        SbdNfrQuestionRecord,
        SbdNfrQuestionSubtaskMapRecord,
        SbdNfrSectionRecord,
        SbdNfrSubtaskComponentRecord,
    )
    from aila.storage.db_models import SeedVersionRecord

    all_ok = True

    # 80 questions
    q_count = (await session.exec(select(func.count()).select_from(SbdNfrQuestionRecord))).one()
    status = "OK" if q_count == 80 else "FAIL"
    if q_count != 80:
        all_ok = False
    _log.info("  [%s] Questions: %s (expected 80)", status, q_count)

    # 11 sections
    s_count = (await session.exec(select(func.count()).select_from(SbdNfrSectionRecord))).one()
    status = "OK" if s_count == 11 else "FAIL"
    if s_count != 11:
        all_ok = False
    _log.info("  [%s] Sections: %s (expected 11)", status, s_count)

    # 76 seed_mappings (question-subtask maps)
    m_count = (
        await session.exec(select(func.count()).select_from(SbdNfrQuestionSubtaskMapRecord))
    ).one()
    status = "OK" if m_count == 76 else "FAIL"
    if m_count != 76:
        all_ok = False
    _log.info("  [%s] Seed mappings: %s (expected 76)", status, m_count)

    # 25 subtask components (D-03 authoritative count)
    st_count = (
        await session.exec(select(func.count()).select_from(SbdNfrSubtaskComponentRecord))
    ).one()
    status = "OK" if st_count == 25 else "FAIL"
    if st_count != 25:
        all_ok = False
    _log.info("  [%s] Subtask components: %s (expected 25)", status, st_count)

    # Option templates: __BINARY__ and __MATURITY_TIER__ must both exist
    # These templates are stored with question_id = "__BINARY__" / "__MATURITY_TIER__"
    binary_count = (
        await session.exec(
            select(func.count())
            .select_from(SbdNfrQuestionOptionRecord)
            .where(SbdNfrQuestionOptionRecord.question_id == "__BINARY__")
        )
    ).one()
    maturity_count = (
        await session.exec(
            select(func.count())
            .select_from(SbdNfrQuestionOptionRecord)
            .where(SbdNfrQuestionOptionRecord.question_id == "__MATURITY_TIER__")
        )
    ).one()
    status = "OK" if binary_count > 0 and maturity_count > 0 else "FAIL"
    if binary_count == 0 or maturity_count == 0:
        all_ok = False
    _log.info(
        "  [%s] Option templates: __BINARY__=%s, __MATURITY_TIER__=%s",
        status, binary_count, maturity_count,
    )

    # All sections must have non-null section_key
    null_keys = (
        await session.exec(
            select(func.count())
            .select_from(SbdNfrSectionRecord)
            .where(SbdNfrSectionRecord.section_key == None)
        )
    ).one()
    status = "OK" if null_keys == 0 else "FAIL"
    if null_keys != 0:
        all_ok = False
    _log.info("  [%s] Sections with NULL section_key: %s (expected 0)", status, null_keys)

    # SeedVersionRecord updated to "3.0"
    ver_row = (
        await session.exec(
            select(SeedVersionRecord.seed_version).where(
                SeedVersionRecord.module_id == MODULE_ID
            )
        )
    ).first()
    status = "OK" if ver_row == "3.0" else "FAIL"
    if ver_row != "3.0":
        all_ok = False
    _log.info("  [%s] SeedVersionRecord: %r (expected '3.0')", status, ver_row)

    return all_ok


async def main(args: argparse.Namespace) -> None:
    """Wipe all SbD NFR data atomically and re-run seed_data().

    The entire wipe + re-seed runs in a single transaction.  If seed_data()
    raises, the wipe is rolled back — the database is left in its previous
    state.

    Args:
        args: Parsed CLI arguments from parse_args().
    """
    # Imports inside async main so the module can be imported without
    # triggering DB connection at import time.
    from sqlmodel import delete, func, select

    from aila.modules.sbd_nfr.db_models import (
        SbdNfrActivityRecord,
        SbdNfrAnswerRecord,
        SbdNfrQuestionOptionRecord,
        SbdNfrQuestionRecord,
        SbdNfrQuestionSubtaskMapRecord,
        SbdNfrResolutionResultRecord,
        SbdNfrSchemaVersionRecord,
        SbdNfrSectionRecord,
        SbdNfrSessionRecord,
        SbdNfrSessionSystemRecord,
        SbdNfrSubgroupRecord,
        SbdNfrSubtaskComponentRecord,
    )
    from aila.modules.sbd_nfr.module import SEED_VERSION, SbdNfrModule
    from aila.platform.uow import UnitOfWork
    from aila.storage.db_models import SeedVersionRecord

    # Model classes in the same FK-safe order as WIPE_ORDER
    model_classes = [
        SbdNfrResolutionResultRecord,
        SbdNfrActivityRecord,
        SbdNfrAnswerRecord,
        SbdNfrSessionSystemRecord,
        SbdNfrSessionRecord,
        SbdNfrQuestionSubtaskMapRecord,
        SbdNfrQuestionOptionRecord,
        SbdNfrQuestionRecord,
        SbdNfrSubgroupRecord,
        SbdNfrSectionRecord,
        SbdNfrSchemaVersionRecord,
        SbdNfrSubtaskComponentRecord,
    ]

    # --- Confirmation prompt (D-02) ---
    if not args.force:
        async with UnitOfWork() as _uow:
            session = _uow.session
            current_version_row = (
                await session.exec(
                    select(SeedVersionRecord.seed_version).where(
                        SeedVersionRecord.module_id == MODULE_ID
                    )
                )
            ).first()
            current_version = current_version_row or "unknown"

            session_count = (
                await session.exec(
                    select(func.count()).select_from(SbdNfrSessionRecord)
                )
            ).one()

        _log.warning("force_reseed is a DESTRUCTIVE dev-only operation.")
        _log.info("")
        _log.info("  Current seed version : %s", current_version)
        _log.info("  Sessions to wipe     : %s", session_count)
        _log.info("  Target seed version  : %s", SEED_VERSION)
        _log.info("")
        _log.warning("This will wipe ALL session, answer, activity, resolution, and seed data.")
        confirm = input("Type 'yes' to proceed: ")
        if confirm.strip().lower() != "yes":
            _log.info("Aborted.")
            return
        _log.info("")

    # --- Wipe + reseed in a single transaction ---
    _log.info(
        "Wiping %d tables + SeedVersionRecord for module '%s'...",
        len(model_classes), MODULE_ID,
    )

    async with UnitOfWork() as _uow:
        session = _uow.session
        # Wipe all model tables in FK-safe order
        for model_cls in model_classes:
            result = await session.exec(delete(model_cls))  # type: ignore[call-overload]
            deleted = result.rowcount if hasattr(result, "rowcount") else "?"
            _log.info("  Wiped %s: %s rows", model_cls.__tablename__, deleted)  # type: ignore[attr-defined]

        # Wipe SeedVersionRecord for this module
        result = await session.exec(  # type: ignore[call-overload]
            delete(SeedVersionRecord).where(SeedVersionRecord.module_id == MODULE_ID)
        )
        seed_deleted = result.rowcount if hasattr(result, "rowcount") else "?"
        _log.info("  Wiped seed_version_record (module_id=%r): %s rows", MODULE_ID, seed_deleted)

        await session.flush()

        # --- Re-seed atomically in the same transaction ---
        _log.info("")
        _log.info("Re-seeding from JSON files...")
        module = SbdNfrModule()
        await module.seed_data(session)
        # seed_data() commits internally — no additional commit needed here

        # --- Post-reseed verification (D-03) ---
        _log.info("")
        _log.info("Verifying reseed results...")
        ok = await verify_reseed(session)
        if not ok:
            _log.warning("")
            _log.warning("Some verification checks failed!")

    _log.info("")
    _log.info(
        "Force-reseed complete: wiped %d tables, re-seeded from JSON",
        len(model_classes),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    _args = parse_args()
    asyncio.run(main(_args))
