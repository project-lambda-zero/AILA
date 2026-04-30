"""Public contracts for the SbD NFR module.

Re-exports all public names from schema.py, session.py, stats.py, search.py,
resolution.py, artifacts.py, and responses.py so callers can import from the
package surface:

    from aila.modules.sbd_nfr.contracts import SchemaTreeResponse, BulkAnswerRequest
    from aila.modules.sbd_nfr.contracts import ActivityResponse, DashboardStatsResponse
    from aila.modules.sbd_nfr.contracts import SmartSearchRequest, SmartSearchResponse
    from aila.modules.sbd_nfr.contracts import ComponentClassification, ResolutionResponse
    from aila.modules.sbd_nfr.contracts import AssistRequest, AssistResponse
    from aila.modules.sbd_nfr.contracts import ReportNarrativeResponse, JiraWorkItemDraft
    from aila.modules.sbd_nfr.contracts import ResolutionTriggerResponse, TriageContextResponse
"""

from __future__ import annotations

from .config import SbdNfrConfig
from .artifacts import (
    ArchitectSection,
    ArtifactMetadataResponse,
    JiraDraftSubtask,
    JiraWorkItemDraft,
    ReportNarrativeResponse,
    RequesterSection,
)
from .resolution import (
    AssistRequest,
    AssistResponse,
    ComponentClassification,
    ComponentClassificationResponse,
    ResolutionResponse,
    ResolutionResultResponse,
)
from .responses import (
    BulkAssignResponse,
    BulkExportResponse,
    ResolutionTriggerResponse,
    TriageContextResponse,
)
from .schema import (
    MappingCreateRequest,
    MappingResponse,
    OptionCreateRequest,
    OptionResponse,
    OptionUpdateRequest,
    QuestionCreateRequest,
    QuestionListResponse,
    QuestionOptionResponse,
    QuestionResponse,
    QuestionUpdateRequest,
    SchemaTreeResponse,
    SchemaVersionResponse,
    SectionCreateRequest,
    SectionListResponse,
    SectionResponse,
    SectionUpdateRequest,
    SubgroupCreateRequest,
    SubgroupListResponse,
    SubgroupResponse,
    SubgroupUpdateRequest,
    SubtaskComponentResponse,
    SubtaskMappingResponse,
)
from .search import (
    SearchMatchedAnswer,
    SearchResultItem,
    SmartSearchRequest,
    SmartSearchResponse,
)
from .session import (
    AnswerInput,
    AnswerResponse,
    ApproveSessionRequest,
    ArchitectNotesRequest,
    BulkAnswerRequest,
    SectionProgressResponse,
    SessionCreateRequest,
    SessionDetailResponse,
    SessionSummaryResponse,
    SubmitForReviewRequest,
)
from .stats import (
    ActivityResponse,
    DashboardStatsResponse,
)

__all__ = [
    # config.py
    "SbdNfrConfig",
    # schema.py
    "QuestionOptionResponse",
    "QuestionResponse",
    "SectionCreateRequest",
    "SectionListResponse",
    "SectionResponse",
    "SectionUpdateRequest",
    "QuestionCreateRequest",
    "QuestionListResponse",
    "QuestionUpdateRequest",
    "SchemaTreeResponse",
    "SchemaVersionResponse",
    "SubgroupCreateRequest",
    "SubgroupListResponse",
    "SubgroupResponse",
    "SubgroupUpdateRequest",
    "SubtaskComponentResponse",
    "SubtaskMappingResponse",
    "OptionCreateRequest",
    "OptionResponse",
    "OptionUpdateRequest",
    "MappingCreateRequest",
    "MappingResponse",
    # search.py
    "SearchMatchedAnswer",
    "SearchResultItem",
    "SmartSearchRequest",
    "SmartSearchResponse",
    # session.py
    "AnswerInput",
    "AnswerResponse",
    "ArchitectNotesRequest",
    "ApproveSessionRequest",
    "BulkAnswerRequest",
    "SectionProgressResponse",
    "SessionCreateRequest",
    "SessionDetailResponse",
    "SessionSummaryResponse",
    "SubmitForReviewRequest",
    # stats.py
    "ActivityResponse",
    "DashboardStatsResponse",
    # resolution.py
    "ComponentClassification",
    "ResolutionResponse",
    "ComponentClassificationResponse",
    "ResolutionResultResponse",
    "AssistRequest",
    "AssistResponse",
    # artifacts.py
    "RequesterSection",
    "ArchitectSection",
    "ReportNarrativeResponse",
    "ArtifactMetadataResponse",
    "JiraDraftSubtask",
    "JiraWorkItemDraft",
    # responses.py
    "BulkAssignResponse",
    "BulkExportResponse",
    "ResolutionTriggerResponse",
    "TriageContextResponse",
]
