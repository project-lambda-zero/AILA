"""SbD NFR database models package.

Re-exports all 12 table classes so that existing imports of the form::

    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord

continue to work without modification.

Submodules:
- schema      — schema versioning and questionnaire structure (7 classes)
- sessions    — assessment sessions, answers, activity, system links (4 classes)
- resolution  — LLM resolution results (1 class)
"""

from aila.modules.sbd_nfr.db_models.resolution import SbdNfrResolutionResultRecord
from aila.modules.sbd_nfr.db_models.schema import (
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrQuestionSubtaskMapRecord,
    SbdNfrSchemaVersionRecord,
    SbdNfrSectionRecord,
    SbdNfrSubgroupRecord,
    SbdNfrSubtaskComponentRecord,
)
from aila.modules.sbd_nfr.db_models.sessions import (
    SbdNfrActivityRecord,
    SbdNfrAnswerRecord,
    SbdNfrSessionRecord,
    SbdNfrSessionSystemRecord,
)

__all__ = [
    # schema
    "SbdNfrSchemaVersionRecord",
    "SbdNfrSectionRecord",
    "SbdNfrSubgroupRecord",
    "SbdNfrQuestionRecord",
    "SbdNfrQuestionOptionRecord",
    "SbdNfrSubtaskComponentRecord",
    "SbdNfrQuestionSubtaskMapRecord",
    # sessions
    "SbdNfrSessionRecord",
    "SbdNfrAnswerRecord",
    "SbdNfrActivityRecord",
    "SbdNfrSessionSystemRecord",
    # resolution
    "SbdNfrResolutionResultRecord",
]
