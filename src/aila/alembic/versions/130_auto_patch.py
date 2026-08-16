"""130 -- ``platform_patch_attempt`` (issue #149 auto-patch synthesis).

Adds the platform-owned table that records every synthesise + verify
attempt fired by :mod:`aila.platform.services.patching` after a
:class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`
returns a ``confirmed`` verdict AND the operator has enabled the
``platform.autopatch_enabled`` flag. Default OFF: the table stays
empty on every existing deployment until the flag flips.

Columns:

* ``id``               -- UUID primary key.
* ``investigation_id`` -- source investigation (nullable so a manual
  admin retry with no live investigation still records).
* ``outcome_id``       -- canonical outcome row the patch targets;
  nullable for the same reason.
* ``module_id``        -- module whose finding is being patched
  (``vr`` / ``malware`` / ...), so operator dashboards can slice by
  origin without joining the outcome table.
* ``team_id``          -- team scope carried through from the source
  investigation for RLS-style filtering on the admin surface.
* ``finding_ref``      -- opaque module-side identifier for the
  finding (e.g. ``VRFindingRecord.id``); free-form because different
  modules key their findings differently.
* ``synth_model``      -- resolved LLM model id the synthesiser used.
* ``synth_task_type``  -- routing task_type at synthesis time
  (``platform.autopatch.synthesize``).
* ``synth_prompt_tokens`` / ``synth_completion_tokens``
                       -- usage split for cost roll-up.
* ``synth_cost_usd``   -- USD estimate for the synthesis LLM call.
* ``patch_diff``       -- the unified diff the synthesiser produced
  (may be empty when synthesis failed / declined).
* ``patch_files_json`` -- JSON list of touched file paths extracted
  from the diff (indexable summary next to the raw diff blob).
* ``verify_status``    -- one of ``pending`` / ``accepted`` /
  ``rejected`` / ``skipped`` / ``error``.
* ``verify_backend``   -- sandbox backend that ran the reproducer
  (``nsjail`` / ``firecracker`` / ``''`` when skipped).
* ``verify_exit_code`` -- reproducer exit code, or NULL on kill.
* ``verify_stdout`` / ``verify_stderr`` -- truncated tail of the
  reproducer output, kept short so the admin list stays paginable.
* ``verify_duration_s`` -- wall-clock verify duration in seconds.
* ``verify_reason``    -- one-line human-readable reason for the
  verdict (``reproducer_failed_on_patched`` = accepted;
  ``reproducer_still_crashes`` = rejected; ``sandbox_unavailable`` =
  skipped; ``synthesis_declined`` = skipped; ...).
* ``harness_json``     -- JSON blob describing the reproducer used
  (argv / input files / expected exit shape) for reproducibility.
* ``total_cost_usd``   -- sum of synth + verify (sandbox time carries
  no LLM cost today; kept as a first-class column so a future
  sandbox-billing extension does not require a schema change).
* ``created_at`` / ``updated_at`` -- lifecycle timestamps.

One unique constraint (``investigation_id, outcome_id, finding_ref``)
so re-fires from the ``_maybe_trigger_patcher`` chokepoint after a
worker retry do not accumulate duplicate rows -- the service uses this
key to detect and update the prior attempt in place.

Two supporting indexes:

* ``ix_platform_patch_attempt_investigation_id`` -- admin list scoped
  by an investigation.
* ``ix_platform_patch_attempt_created_at`` -- default recency sort
  for the admin pager.

Every named constraint / index is module-prefixed
(``platform_patch_attempt_``) because Postgres constraint names are
schema-global (CLAUDE.md common mistake 21).

Revision ID: 130_auto_patch
Revises:     129_router_hard_negatives
Create Date: 2026-08-17
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "130_auto_patch"
down_revision: str | None = "129_router_hard_negatives"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "platform_patch_attempt"
_UQ_INV_OUTCOME_FINDING: str = "uq_platform_patch_attempt_inv_outcome_finding"
_IX_INVESTIGATION: str = "ix_platform_patch_attempt_investigation_id"
_IX_CREATED: str = "ix_platform_patch_attempt_created_at"


def _table_present() -> bool:
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if _table_present():
        # Fresh test bootstrap that created the table via metadata.create_all
        # (e.g. the test_db fixture) -- stamp-only, no-op the DDL. Mirrors
        # the pattern in 115 / 124 / 126 / 128 / 129.
        return
    op.execute(sa.text(
        f"""
CREATE TABLE {_TABLE} (
    id                       VARCHAR(36)   NOT NULL,
    investigation_id         VARCHAR(64),
    outcome_id               VARCHAR(64),
    module_id                VARCHAR(64)   NOT NULL DEFAULT '',
    team_id                  VARCHAR(64),
    finding_ref              VARCHAR(128)  NOT NULL DEFAULT '',
    synth_model              VARCHAR(128)  NOT NULL DEFAULT '',
    synth_task_type          VARCHAR(128)  NOT NULL DEFAULT '',
    synth_prompt_tokens      INTEGER       NOT NULL DEFAULT 0,
    synth_completion_tokens  INTEGER       NOT NULL DEFAULT 0,
    synth_cost_usd           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    patch_diff               TEXT          NOT NULL DEFAULT '',
    patch_files_json         TEXT          NOT NULL DEFAULT '[]',
    verify_status            VARCHAR(16)   NOT NULL DEFAULT 'pending',
    verify_backend           VARCHAR(32)   NOT NULL DEFAULT '',
    verify_exit_code         INTEGER,
    verify_stdout            TEXT          NOT NULL DEFAULT '',
    verify_stderr            TEXT          NOT NULL DEFAULT '',
    verify_duration_s        DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    verify_reason            VARCHAR(128)  NOT NULL DEFAULT '',
    harness_json             TEXT          NOT NULL DEFAULT '{{}}',
    total_cost_usd           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT pk_platform_patch_attempt PRIMARY KEY (id),
    CONSTRAINT {_UQ_INV_OUTCOME_FINDING} UNIQUE (investigation_id, outcome_id, finding_ref)
)
"""
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_IX_INVESTIGATION} "
        f"ON {_TABLE} (investigation_id)"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_IX_CREATED} "
        f"ON {_TABLE} (created_at)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_IX_CREATED}"))
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_IX_INVESTIGATION}"))
    op.execute(sa.text(f"DROP TABLE IF EXISTS {_TABLE}"))
