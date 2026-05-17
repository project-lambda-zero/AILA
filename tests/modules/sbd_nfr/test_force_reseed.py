"""Structural tests for the force_reseed dev script.

These tests verify the script's module-level constants and import surface
without connecting to a database.  The actual DB wipe is verified by running
the command against a dev database (manual step).

Per plan 151-03 Task 2: structural tests are sufficient — the full wipe
semantics are covered by WIPE_ORDER and the integration test is the dev
run itself.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Test 1: Module imports cleanly without triggering a DB connection
# ---------------------------------------------------------------------------


def test_force_reseed_imports_cleanly() -> None:
    """force_reseed can be imported without side effects or DB connection."""
    from aila.modules.sbd_nfr.scripts import force_reseed  # noqa: F401

    assert hasattr(force_reseed, "main"), "main() coroutine must be importable"
    assert hasattr(force_reseed, "WIPE_ORDER"), "WIPE_ORDER constant must be exported"
    assert hasattr(force_reseed, "MODULE_ID"), "MODULE_ID constant must be exported"
    assert hasattr(force_reseed, "parse_args"), "parse_args() must be importable"
    assert hasattr(force_reseed, "verify_reseed"), "verify_reseed() coroutine must be importable"


# ---------------------------------------------------------------------------
# Test 2: WIPE_ORDER contains the expected table class names in a safe order
# ---------------------------------------------------------------------------


def test_wipe_order_contains_expected_tables() -> None:
    """WIPE_ORDER must list all session and seed tables that need wiping."""
    from aila.modules.sbd_nfr.scripts.force_reseed import WIPE_ORDER

    expected_tables = {
        # Session tables (D-01: wiped before seed tables)
        "SbdNfrResolutionResultRecord",
        "SbdNfrActivityRecord",
        "SbdNfrAnswerRecord",
        "SbdNfrSessionSystemRecord",
        "SbdNfrSessionRecord",
        # Seed tables
        "SbdNfrQuestionSubtaskMapRecord",
        "SbdNfrQuestionOptionRecord",
        "SbdNfrQuestionRecord",
        "SbdNfrSubgroupRecord",
        "SbdNfrSectionRecord",
        "SbdNfrSchemaVersionRecord",
        "SbdNfrSubtaskComponentRecord",
    }
    assert set(WIPE_ORDER) == expected_tables, (
        f"WIPE_ORDER is missing or has extra tables.\n"
        f"Expected: {sorted(expected_tables)}\n"
        f"Got:      {sorted(WIPE_ORDER)}"
    )


# ---------------------------------------------------------------------------
# Test 3: FK-safe deletion order — child tables before parent tables
# ---------------------------------------------------------------------------


def test_wipe_order_is_fk_safe() -> None:
    """Verify FK-safe ordering: child tables precede parent tables.

    Key FK relationships (session tables):
    - ResolutionResultRecord → SessionRecord (must come first)
    - ActivityRecord → SessionRecord (must come first)
    - AnswerRecord → SessionRecord + QuestionRecord (must come first)
    - SessionSystemRecord → SessionRecord (must come first)

    Key FK relationships (seed tables):
    - QuestionSubtaskMapRecord → QuestionRecord (must come first)
    - QuestionOptionRecord → QuestionRecord (must come first)
    - QuestionRecord → SubgroupRecord (must come first)
    - SubgroupRecord → SectionRecord (must come first)
    - SectionRecord → SchemaVersionRecord (must come first)

    Session tables must all precede seed tables (AnswerRecord references QuestionRecord).
    """
    from aila.modules.sbd_nfr.scripts.force_reseed import WIPE_ORDER

    def idx(name: str) -> int:
        return WIPE_ORDER.index(name)

    # All session tables must be deleted before seed tables
    session_tables = [
        "SbdNfrResolutionResultRecord",
        "SbdNfrActivityRecord",
        "SbdNfrAnswerRecord",
        "SbdNfrSessionSystemRecord",
        "SbdNfrSessionRecord",
    ]
    for session_table in session_tables:
        assert idx(session_table) < idx("SbdNfrQuestionSubtaskMapRecord"), (
            f"{session_table} must be wiped before seed tables"
        )

    # SessionRecord must be deleted AFTER the tables that reference it
    assert idx("SbdNfrResolutionResultRecord") < idx("SbdNfrSessionRecord"), (
        "SbdNfrResolutionResultRecord must be wiped before SbdNfrSessionRecord"
    )
    assert idx("SbdNfrActivityRecord") < idx("SbdNfrSessionRecord"), (
        "SbdNfrActivityRecord must be wiped before SbdNfrSessionRecord"
    )
    assert idx("SbdNfrAnswerRecord") < idx("SbdNfrSessionRecord"), (
        "SbdNfrAnswerRecord must be wiped before SbdNfrSessionRecord"
    )
    assert idx("SbdNfrSessionSystemRecord") < idx("SbdNfrSessionRecord"), (
        "SbdNfrSessionSystemRecord must be wiped before SbdNfrSessionRecord"
    )

    # QuestionSubtaskMapRecord must be deleted before QuestionRecord
    assert idx("SbdNfrQuestionSubtaskMapRecord") < idx("SbdNfrQuestionRecord"), (
        "SbdNfrQuestionSubtaskMapRecord must be wiped before SbdNfrQuestionRecord"
    )

    # QuestionOptionRecord must be deleted before QuestionRecord
    assert idx("SbdNfrQuestionOptionRecord") < idx("SbdNfrQuestionRecord"), (
        "SbdNfrQuestionOptionRecord must be wiped before SbdNfrQuestionRecord"
    )

    # QuestionRecord must be deleted before SubgroupRecord
    assert idx("SbdNfrQuestionRecord") < idx("SbdNfrSubgroupRecord"), (
        "SbdNfrQuestionRecord must be wiped before SbdNfrSubgroupRecord"
    )

    # SubgroupRecord must be deleted before SectionRecord
    assert idx("SbdNfrSubgroupRecord") < idx("SbdNfrSectionRecord"), (
        "SbdNfrSubgroupRecord must be wiped before SbdNfrSectionRecord"
    )

    # SectionRecord must be deleted before SchemaVersionRecord
    assert idx("SbdNfrSectionRecord") < idx("SbdNfrSchemaVersionRecord"), (
        "SbdNfrSectionRecord must be wiped before SbdNfrSchemaVersionRecord"
    )


# ---------------------------------------------------------------------------
# Test 4: MODULE_ID matches the sbd_nfr module identifier
# ---------------------------------------------------------------------------


def test_module_id_is_sbd_nfr() -> None:
    """MODULE_ID must be 'sbd_nfr' to correctly target the SeedVersionRecord."""
    from aila.modules.sbd_nfr.scripts.force_reseed import MODULE_ID

    assert MODULE_ID == "sbd_nfr"


# ---------------------------------------------------------------------------
# Test 5: main is an async coroutine function
# ---------------------------------------------------------------------------


def test_main_is_coroutine() -> None:
    """main() must be an async function (coroutine), not a sync function."""
    import asyncio

    from aila.modules.sbd_nfr.scripts.force_reseed import main

    assert asyncio.iscoroutinefunction(main), (
        "force_reseed.main must be an async def coroutine function"
    )


# ---------------------------------------------------------------------------
# Test 6: parse_args returns Namespace with --force flag defaulting to False
# ---------------------------------------------------------------------------


def test_parse_args_force_defaults_false() -> None:
    """parse_args() with no arguments must have force=False."""
    from aila.modules.sbd_nfr.scripts.force_reseed import parse_args

    args = parse_args([])
    assert hasattr(args, "force"), "Namespace must have 'force' attribute"
    assert args.force is False, "--force must default to False when not supplied"


def test_parse_args_force_flag() -> None:
    """parse_args(['--force']) must set force=True."""
    from aila.modules.sbd_nfr.scripts.force_reseed import parse_args

    args = parse_args(["--force"])
    assert args.force is True, "--force flag must set force=True"


# ---------------------------------------------------------------------------
# Test 7: verify_reseed is an async coroutine function
# ---------------------------------------------------------------------------


def test_verify_reseed_is_coroutine() -> None:
    """verify_reseed() must be an async function (coroutine)."""
    import asyncio

    from aila.modules.sbd_nfr.scripts.force_reseed import verify_reseed

    assert asyncio.iscoroutinefunction(verify_reseed), (
        "force_reseed.verify_reseed must be an async def coroutine function"
    )


# ---------------------------------------------------------------------------
# Test 8: WIPE_ORDER has exactly 12 entries (5 session + 7 seed tables)
# ---------------------------------------------------------------------------


def test_wipe_order_length() -> None:
    """WIPE_ORDER must have exactly 12 entries: 5 session + 7 seed tables."""
    from aila.modules.sbd_nfr.scripts.force_reseed import WIPE_ORDER

    assert len(WIPE_ORDER) == 12, (
        f"WIPE_ORDER must have 12 entries (5 session + 7 seed), got {len(WIPE_ORDER)}"
    )
