"""Template binding of the platform terminal-branch cleanup helper.

Pre-binds ``branch_table`` to the template's branches table so callers
inside the module do not repeat the string. Mirrors the vr / malware
call-site pattern (they pass the string inline today; a copier can
either keep this partial or replicate the inline form after renaming).
"""
from __future__ import annotations

from functools import partial

from aila.platform.services.branch_cleanup import (
    close_orphan_branches_on_terminal as _platform_close,
)

__all__ = ["close_orphan_branches_on_terminal"]

_TEMPLATE_BRANCH_TABLE = "template_investigation_branches"

close_orphan_branches_on_terminal = partial(
    _platform_close,
    branch_table=_TEMPLATE_BRANCH_TABLE,
)
