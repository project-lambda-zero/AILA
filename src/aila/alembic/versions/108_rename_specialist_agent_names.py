"""108 -- rename built-in specialist agents to named panelists.

The optional specialist agents a panel can request (reverse engineering,
mobile, exploit development, variant hunt, crypto) previously carried a
bare capability slug as their ``name`` (``re``, ``mobile``, ...). The
name doubles as the spawned branch's ``persona_voice``, so a specialist
rendered as a lowercase slug next to the named core spine (halvar /
maddie / renzo). This migration renames the seeded registry rows -- and
any branch already spawned under an old name -- to distinct named
panelists so every voice on the board reads the same way.

Routing is unaffected: dispatch keys off ``specialist_agent.capability``,
which is left untouched; only the display / persona_voice ``name`` moves.

Data-only migration -- no schema change. Rows a user renamed via the
CRUD API no longer match the old name and are left untouched. A fresh DB
that never seeded the defaults updates zero rows.

Revision ID: 108_rename_specialist_agent_names
Revises:     107_forensics_panel_tables
Create Date: 2026-07-31
"""
from __future__ import annotations

from alembic import op

revision: str = "108_rename_specialist_agent_names"
down_revision: str | None = "107_forensics_panel_tables"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


# (module_id, old_name, new_name). ``re`` appears in both modules with a
# different target capability, so each rename is module-scoped.
_VR_RENAMES: tuple[tuple[str, str], ...] = (
    ("re", "snake"),
    ("mobile", "jak"),
    ("exploit-dev", "kratos"),
    ("variant", "lara"),
)
_MALWARE_RENAMES: tuple[tuple[str, str], ...] = (
    ("re", "alucard"),
    ("crypto", "vincent"),
)


def _apply(
    module_id: str,
    branch_table: str,
    renames: tuple[tuple[str, str], ...],
) -> None:
    for old, new in renames:
        op.execute(
            "UPDATE specialist_agent SET name = '%s', updated_at = now() "
            "WHERE module_id = '%s' AND name = '%s'" % (new, module_id, old)
        )
        op.execute(
            "UPDATE %s SET persona_voice = '%s' "
            "WHERE persona_voice = '%s'" % (branch_table, new, old)
        )


def upgrade() -> None:
    _apply("vr", "vr_investigation_branches", _VR_RENAMES)
    _apply("malware", "malware_investigation_branches", _MALWARE_RENAMES)


def downgrade() -> None:
    _apply(
        "vr", "vr_investigation_branches",
        tuple((new, old) for old, new in _VR_RENAMES),
    )
    _apply(
        "malware", "malware_investigation_branches",
        tuple((new, old) for old, new in _MALWARE_RENAMES),
    )
