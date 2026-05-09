"""Module entrypoint for the SbD NFR assessment module.

Implements ModuleProtocol.  This file is the only file the platform imports
directly — all wiring happens here.

Design references: D-01, D-03b, D-15, D-16, D-37, D-40, D-63, D-09.
Pitfall 4: seed_data() NEVER deletes existing subtask or session rows.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session

from aila.config import Settings
from aila.platform.contracts._common import JsonObject, utc_now
from aila.platform.modules import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRouteSpec,
    ModuleRuntime,
    action_id_for,
)
from aila.platform.runtime import ToolRegistry
from aila.storage.db_models import SeedVersionRecord

from .api_router import create_sbd_nfr_router, create_sbd_nfr_shared_router
from .capabilities import MODULE_DESCRIPTION, MODULE_EXAMPLES, MODULE_TOOLS
from .db_models import (
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
from .runtime import SbdNfrRuntime
from .services.config import SbdNfrConfig

_log = logging.getLogger(__name__)

MODULE_ID = Path(__file__).parent.name
MODULE_ACTION_ID = action_id_for(MODULE_ID, "assess_nfr")
SEED_VERSION = "3.0"

_DATA_DIR = Path(__file__).parent / "data"


def _load_seed_json(filename: str) -> Any:
    """Load a seed JSON file from the module data directory."""
    path = _DATA_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


class SbdNfrModule(ModuleProtocol):
    """Feature module implementing the SbD NFR questionnaire assessment."""

    module_id = MODULE_ID
    action_id = MODULE_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.action_id,
                description=MODULE_DESCRIPTION,
                tools=list(MODULE_TOOLS),
                examples=list(MODULE_EXAMPLES),
            )
        ]

    def route_specs(self) -> list[ModuleRouteSpec]:
        return [
            ModuleRouteSpec(
                prefix="/sbd_nfr",
                router_factory=create_sbd_nfr_router,
                tool_keys=(),
                config_namespace="sbd_nfr",
            ),
            ModuleRouteSpec(
                prefix="/sbd_nfr",
                router_factory=create_sbd_nfr_shared_router,
                tool_keys=(),
                auth_required=False,
            ),
        ]

    def required_tools(self) -> list[str]:
        return [*MODULE_TOOLS]

    def report_filter_keys(self) -> list[str]:
        return []

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: Settings,
        registry: Any = None,
        schema_registry: Any = None,
    ) -> None:
        del tool_registry, settings
        if schema_registry is not None:
            schema_registry.push(SbdNfrSchemaVersionRecord)
            schema_registry.push(SbdNfrSectionRecord)
            schema_registry.push(SbdNfrSubgroupRecord)
            schema_registry.push(SbdNfrQuestionRecord)
            schema_registry.push(SbdNfrQuestionOptionRecord)
            schema_registry.push(SbdNfrSubtaskComponentRecord)
            schema_registry.push(SbdNfrQuestionSubtaskMapRecord)
            schema_registry.push(SbdNfrSessionRecord)
            schema_registry.push(SbdNfrAnswerRecord)
            schema_registry.push(SbdNfrActivityRecord)
            schema_registry.push(SbdNfrSessionSystemRecord)
            schema_registry.push(SbdNfrResolutionResultRecord)
        if registry is not None:
            await registry.register("sbd_nfr", SbdNfrConfig)

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        del context
        return SbdNfrRuntime(
            module_id=self.module_id,
            action_id=self.action_id,
            capability_profiles=self.capability_profiles(),
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        del filters
        return list(rows)

    async def seed_data(self, session: Any) -> None:
        """Seed all questionnaire master data idempotently.

        Idempotency contract:
        - Checks SeedVersionRecord for this module_id.  If seed_version matches
          SEED_VERSION, returns immediately without touching the DB.
        - Subtask components are upserted by key (Pitfall 4: never deleted).
        - Sections and subgroups are upserted by key + schema_version.
        - Questions are upserted by id (the semantic ID is the PK).
        - Options are delete-and-reinsert by question_id (user-uneditable).
        - Mappings are delete-and-reinsert by question_id (user-uneditable).
        - __COMPLIANCE__ options are expanded to all compliance-type questions.
        """
        from sqlmodel import select

        # --- Version check ---
        existing_version = (
            await session.exec(
                select(SeedVersionRecord).where(
                    SeedVersionRecord.module_id == self.module_id
                )
            )
        ).first()
        if existing_version is not None and existing_version.seed_version == SEED_VERSION:
            return

        # --- Load all seed JSONs ---
        # The five seed JSONs are produced by `aila.modules.sbd_nfr.scripts.extract_nfr`
        # using the proprietary AILA NFR Security Workbook + document_engine.py constants.
        # In a fresh dev clone where the workbook isn't available, the data directory
        # may be empty. Skip seeding gracefully so the rest of the platform still boots;
        # sbd_nfr functionality remains unavailable until the seed files are produced.
        seed_files = (
            "seed_subtasks.json",
            "seed_sections.json",
            "seed_questions.json",
            "seed_options.json",
            "seed_mappings.json",
        )
        missing = [name for name in seed_files if not (_DATA_DIR / name).is_file()]
        if missing:
            _log.warning(
                "sbd_nfr: skipping master-data seed — missing files: %s. "
                "Run 'python -m aila.modules.sbd_nfr.scripts.extract_nfr' to produce them. "
                "The sbd_nfr module will not be functional until seed data is in place.",
                ", ".join(missing),
            )
            return

        _log.info("sbd_nfr: seeding master data (version %s)", SEED_VERSION)
        subtasks = _load_seed_json("seed_subtasks.json")
        sections = _load_seed_json("seed_sections.json")
        questions = _load_seed_json("seed_questions.json")
        options = _load_seed_json("seed_options.json")
        mappings = _load_seed_json("seed_mappings.json")

        # --- Step 1: Schema version record ---
        schema_version = 2
        existing_schema = (
            await session.exec(
                select(SbdNfrSchemaVersionRecord).where(
                    SbdNfrSchemaVersionRecord.version == schema_version
                )
            )
        ).first()
        if existing_schema is None:
            session.add(
                SbdNfrSchemaVersionRecord(
                    version=schema_version,
                    change_summary="Phase 153: Conditional sections 7-10 (API, Web, Supply Chain, Governance)",
                    changed_by="system",
                )
            )
            await session.flush()

        # --- Step 2: Upsert subtask components (Pitfall 4: never delete) ---
        for i, subtask in enumerate(subtasks):
            existing = (
                await session.exec(
                    select(SbdNfrSubtaskComponentRecord).where(
                        SbdNfrSubtaskComponentRecord.key == subtask["key"]
                    )
                )
            ).first()
            if existing is None:
                session.add(
                    SbdNfrSubtaskComponentRecord(
                        key=subtask["key"],
                        label=subtask["label"],
                        category=subtask["category"],
                        description=subtask["description"],
                        icon_hint=subtask.get("icon_hint", ""),
                        display_order=subtask.get("display_order", i + 1),
                        is_active=subtask.get("is_active", True),
                    )
                )
            else:
                # TOOL-02: Update existing subtask fields instead of silently skipping
                existing.label = subtask["label"]
                existing.category = subtask["category"]
                existing.description = subtask["description"]
                existing.is_active = subtask.get("is_active", True)
                existing.icon_hint = subtask.get("icon_hint", "")
                existing.display_order = subtask.get("display_order", i + 1)
                existing.updated_at = utc_now()
                session.add(existing)
        await session.flush()

        # --- Step 3: Upsert sections and their subgroups ---
        section_id_by_key: dict[str, str] = {}
        subgroup_id_by_key: dict[str, str] = {}

        for section_data in sections:
            section_key = section_data["section_key"]
            existing = (
                await session.exec(
                    select(SbdNfrSectionRecord).where(
                        SbdNfrSectionRecord.section_key == section_key,
                        SbdNfrSectionRecord.schema_version == schema_version,
                    )
                )
            ).first()
            if existing is None:
                record = SbdNfrSectionRecord(
                    schema_version=schema_version,
                    section_key=section_key,
                    label=section_data["label"],
                    description=section_data.get("description") or None,
                    display_order=section_data.get("display_order", 0),
                    is_active=section_data.get("is_active", True),
                    depends_on_question_id=section_data.get("depends_on_question_id"),
                    expected_when=section_data.get("expected_when"),
                    condition_expr_json=section_data.get("condition_expr_json"),
                )
                session.add(record)
                await session.flush()
                section_id_by_key[section_key] = record.id
            else:
                section_id_by_key[section_key] = existing.id

            # Upsert subgroups for this section
            for subgroup_data in section_data.get("subgroups", []):
                subgroup_key = subgroup_data["subgroup_key"]
                existing_sg = (
                    await session.exec(
                        select(SbdNfrSubgroupRecord).where(
                            SbdNfrSubgroupRecord.subgroup_key == subgroup_key,
                            SbdNfrSubgroupRecord.schema_version == schema_version,
                        )
                    )
                ).first()
                if existing_sg is None:
                    sg_record = SbdNfrSubgroupRecord(
                        schema_version=schema_version,
                        section_id=section_id_by_key[section_key],
                        subgroup_key=subgroup_key,
                        label=subgroup_data["label"],
                        display_order=subgroup_data.get("display_order", 0),
                    )
                    session.add(sg_record)
                    await session.flush()
                    subgroup_id_by_key[subgroup_key] = sg_record.id
                else:
                    subgroup_id_by_key[subgroup_key] = existing_sg.id

        # --- Step 4: Upsert questions by semantic ID ---
        for question_data in questions:
            question_id = question_data["id"]
            subgroup_key = question_data["subgroup_key"]
            subgroup_id = subgroup_id_by_key.get(subgroup_key, "")
            existing = (
                await session.exec(
                    select(SbdNfrQuestionRecord).where(
                        SbdNfrQuestionRecord.id == question_id
                    )
                )
            ).first()
            if existing is None:
                session.add(
                    SbdNfrQuestionRecord(
                        id=question_id,
                        schema_version=schema_version,
                        subgroup_id=subgroup_id,
                        question_type=question_data["question_type"],
                        depth_level=question_data["depth_level"],
                        answer_type=question_data["answer_type"],
                        label=question_data["label"],
                        instruction=question_data.get("instruction"),
                        guideline=question_data.get("guideline"),
                        help_text=question_data.get("help_text"),
                        is_required=question_data.get("is_required", True),
                        depends_on_question_id=question_data.get("depends_on_question_id"),
                        expected_when=question_data.get("expected_when"),
                        display_order=question_data.get("display_order", 0),
                    )
                )
        await session.flush()

        # --- Step 5: Delete-and-reinsert options ---
        # Collect compliance template entries and per-question entries separately
        compliance_options = [o for o in options if o["question_id"] == "__COMPLIANCE__"]
        specific_options = [o for o in options if o["question_id"] != "__COMPLIANCE__"]

        # Delete existing options for specific question IDs
        specific_question_ids = {o["question_id"] for o in specific_options}
        for qid in specific_question_ids:
            existing_opts = (
                await session.exec(
                    select(SbdNfrQuestionOptionRecord).where(
                        SbdNfrQuestionOptionRecord.question_id == qid
                    )
                )
            ).all()
            for opt in existing_opts:
                await session.delete(opt)
        await session.flush()

        for opt_data in specific_options:
            session.add(
                SbdNfrQuestionOptionRecord(
                    question_id=opt_data["question_id"],
                    value=opt_data["value"],
                    label=opt_data["label"],
                    description=opt_data.get("description"),
                    display_order=opt_data.get("display_order", 0),
                )
            )
        await session.flush()

        # --- Step 6: Expand __COMPLIANCE__ template to all compliance questions ---
        compliance_question_ids = [
            q["id"] for q in questions if q.get("answer_type") == "compliance"
        ]
        for compliance_qid in compliance_question_ids:
            existing_opts = (
                await session.exec(
                    select(SbdNfrQuestionOptionRecord).where(
                        SbdNfrQuestionOptionRecord.question_id == compliance_qid
                    )
                )
            ).all()
            for opt in existing_opts:
                await session.delete(opt)
        await session.flush()

        for compliance_qid in compliance_question_ids:
            for opt_data in compliance_options:
                session.add(
                    SbdNfrQuestionOptionRecord(
                        question_id=compliance_qid,
                        value=opt_data["value"],
                        label=opt_data["label"],
                        description=opt_data.get("description"),
                        display_order=opt_data.get("display_order", 0),
                    )
                )
        await session.flush()

        # --- Step 7: Delete-and-reinsert mappings ---
        existing_maps = (
            await session.exec(select(SbdNfrQuestionSubtaskMapRecord))
        ).all()
        for m in existing_maps:
            await session.delete(m)
        await session.flush()

        for mapping_data in mappings:
            session.add(
                SbdNfrQuestionSubtaskMapRecord(
                    question_id=mapping_data["question_id"],
                    subtask_key=mapping_data["subtask_key"],
                )
            )
        await session.flush()

        # --- Step 8: Update SeedVersionRecord ---
        if existing_version is None:
            session.add(
                SeedVersionRecord(
                    module_id=self.module_id,
                    seed_version=SEED_VERSION,
                )
            )
        else:
            existing_version.seed_version = SEED_VERSION
            existing_version.seeded_at = utc_now()
            session.add(existing_version)

        await session.commit()
        _log.info("sbd_nfr: seed_data() complete (schema_version=%d)", schema_version)

    async def system_summary(self, system_id: int, session: "Session") -> dict[str, Any]:
        del system_id, session
        return {}

    async def report_count(self, run_id: str, session: "Session") -> dict[str, Any]:
        del run_id, session
        return {}

    def health_checks(self) -> dict[str, object]:
        """Module-specific health checks per D-59.

        Returns three async callables:
        1. sbd_nfr.schema_seeded  — question count > 0 in sbd_nfr_question_record.
        2. sbd_nfr.subtask_coverage — 25 unique subtask_key values mapped.
        3. sbd_nfr.db_connectivity — successful query against sbd_nfr_session_record.

        Each callable is zero-argument and returns a dict with at least a
        'status' key ('up', 'degraded', or 'down').
        """

        async def check_schema_seeded() -> dict[str, object]:
            from aila.platform.services.factory import ServiceFactory

            svc = ServiceFactory()
            records = await svc.storage.fetch_all(SbdNfrQuestionRecord)
            count = len(records)
            if count == 0:
                return {"status": "down", "detail": "No questions seeded"}
            return {"status": "up", "detail": f"{count} questions seeded"}

        async def check_subtask_coverage() -> dict[str, object]:
            from aila.platform.services.factory import ServiceFactory

            svc = ServiceFactory()
            records = await svc.storage.fetch_all(SbdNfrQuestionSubtaskMapRecord)
            unique_keys = {r.subtask_key for r in records}
            count = len(unique_keys)
            if count < 25:
                return {
                    "status": "degraded",
                    "detail": f"Only {count}/25 subtasks mapped",
                }
            return {"status": "up", "detail": "25/25 subtasks mapped"}

        async def check_db_connectivity() -> dict[str, object]:
            from aila.platform.services.factory import ServiceFactory

            try:
                svc = ServiceFactory()
                await svc.storage.fetch_all(SbdNfrSessionRecord)
                return {"status": "up"}
            except (OSError, RuntimeError, ValueError) as exc:
                return {"status": "down", "detail": str(exc)}

        return {
            "sbd_nfr.schema_seeded": check_schema_seeded,
            "sbd_nfr.subtask_coverage": check_subtask_coverage,
            "sbd_nfr.db_connectivity": check_db_connectivity,
        }


def create_module() -> ModuleProtocol:
    """Instantiate and return the SbD NFR module."""
    return SbdNfrModule()
