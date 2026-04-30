"""Document and workbook engine for the SbD NFR module."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree as ET

from aila.platform.contracts._common import utc_now

SOURCE_WORKBOOK_NAME = "nfr_security_workbook_source.xlsx"

_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS = {"a": _MAIN_NS}
_XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
ET.register_namespace("", _MAIN_NS)

_YES = "YES"
_NO = "NO"
_COMPLIANCE_OPTIONS = ("Yes", "Partial", "No", "Not applicable")
_RECOMMENDATION_CATALOG: list[dict[str, str]] = [
    {"key": "access_point_integration", "label": "Access Point Integration", "category": "integration"},
    {"key": "application_logging", "label": "Application Logging", "category": "logging"},
    {"key": "archer_inventory_update", "label": "Archer Inventory Update", "category": "governance"},
    {"key": "arcsight_new_update_alert_request", "label": "ArcSight - New Update Alert Request", "category": "logging"},
    {"key": "container_native_firewall", "label": "Container Native Firewall", "category": "container"},
    {"key": "container_security_scan", "label": "Container Security Scan", "category": "container"},
    {"key": "cyberark_epm", "label": "Cyberark-EPM", "category": "identity"},
    {"key": "dast", "label": "DAST", "category": "assurance"},
    {"key": "database_logging", "label": "Database Logging", "category": "logging"},
    {"key": "file_integrity_monitoring_integration", "label": "File Integrity Monitoring Integration", "category": "runtime"},
    {"key": "network_segment_placement", "label": "Network Segment & Placement", "category": "architecture"},
    {"key": "onetrust_supplier_security_assesment", "label": "OneTrust Supplier Security Assesment", "category": "third_party"},
    {"key": "operating_system_logging_unix", "label": "Operating System Logging (Unix)", "category": "logging"},
    {"key": "operating_system_logging_windows", "label": "Operating System Logging (Windows)", "category": "logging"},
    {"key": "penetration_testing", "label": "Penetration Testing", "category": "validation"},
    {"key": "privileged_user_access_management_integrations_cyberark", "label": "Privileged user access management/integrations (Cyberark)", "category": "identity"},
    {"key": "proxy_definition", "label": "Proxy Definition", "category": "integration"},
    {"key": "risk_assesment", "label": "Risk Assesment", "category": "architecture"},
    {"key": "sast", "label": "SAST", "category": "assurance"},
    {"key": "scs", "label": "SCS", "category": "assurance"},
    {"key": "secure_by_design_assesment", "label": "Secure by Design Assesment", "category": "architecture"},
    {"key": "software_composition_analysis_sca", "label": "Software Composition Analysis (SCA)", "category": "assurance"},
    {"key": "vulnerability_scan_tenable", "label": "Vulnerability Scan (Tenable)", "category": "validation"},
    {"key": "waf_integration", "label": "WAF Integration", "category": "runtime"},
    {"key": "web_certificate_request", "label": "WEb certificate Request", "category": "integration"},
]
_QUESTION_GROUPS: dict[str, list[str]] = {
    "project_frame": ["0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "api_usage", "0.1.6"],
    "specialist_flags": ["0.1.7", "0.1.8", "0.1.9", "0.1.10", "non_production_test_device", "0.1.11"],
}
_QUESTION_OPTIONS: dict[str, list[str]] = {
    "0.1.1": [
        "New service for immediate commercial sale",
        "Enhancement to an existing service",
    ],
    "0.1.2": [
        "External ( APN; customer facing; private access)",
        "Internal",
    ],
    "0.1.3": ["3rd Party Storage", "Corporate Environments"],
    "0.1.4": [_YES, _NO],
    "0.1.5": [_YES, _NO],
    "api_usage": [_YES, _NO],
    "0.1.6": [_YES, _NO],
    "0.1.7": [_YES, _NO],
    "0.1.8": [_YES, _NO],
    "0.1.9": [_YES, _NO],
    "0.1.10": [_YES, _NO],
    "non_production_test_device": [_YES, _NO],
    "0.1.11": [_YES, _NO],
}
_SECTION_SHEET_PATHS: dict[str, str] = {
    "0.Base Questionnaire": "xl/worksheets/sheet2.xml",
    "Hygiene&Essentials": "xl/worksheets/sheet3.xml",
    "DataProtection": "xl/worksheets/sheet4.xml",
    "Logging&Monitoring": "xl/worksheets/sheet5.xml",
    "User&Accounts": "xl/worksheets/sheet6.xml",
    "APIs": "xl/worksheets/sheet7.xml",
    "Supplier&3rdParty": "xl/worksheets/sheet8.xml",
    "Web&Mobile": "xl/worksheets/sheet9.xml",
    "VOIP": "xl/worksheets/sheet10.xml",
    "CPE": "xl/worksheets/sheet11.xml",
}
_SECTION_LAYOUTS: dict[str, dict[str, str]] = {
    "Hygiene&Essentials": {"compliance_column": "E", "response_column": "F"},
    "DataProtection": {"compliance_column": "C", "response_column": "D"},
    "Logging&Monitoring": {"compliance_column": "C", "response_column": "D"},
    "User&Accounts": {"compliance_column": "C", "response_column": "D"},
    "APIs": {"compliance_column": "C", "response_column": "D"},
    "Supplier&3rdParty": {"compliance_column": "C", "response_column": "D"},
    "Web&Mobile": {"compliance_column": "C", "response_column": "D"},
    "VOIP": {"compliance_column": "C", "response_column": "D"},
    "CPE": {"compliance_column": "C", "response_column": "D"},
}
_SECTION_COPY: dict[str, dict[str, str]] = {
    "Hygiene&Essentials": {
        "title": "Security hygiene and platform baseline",
        "intro": "Mandatory foundational controls covering architecture, zoning, hardening, and operations hygiene.",
    },
    "DataProtection": {
        "title": "Data protection requirements",
        "intro": "Additional controls when the service handles personal, C3, or C4 data.",
    },
    "Logging&Monitoring": {
        "title": "Logging and monitoring",
        "intro": "Mandatory operational logging, event integrity, and central monitoring expectations.",
    },
    "User&Accounts": {
        "title": "User and account controls",
        "intro": "Mandatory access, authentication, and privileged access requirements.",
    },
    "APIs": {
        "title": "API design and exposure",
        "intro": "Secure API design controls for HTTP-based interfaces and machine-to-machine integrations.",
    },
    "Supplier&3rdParty": {
        "title": "Supplier and third-party delivery",
        "intro": "Requirements for supplier involvement, remote access, and shared delivery boundaries.",
    },
    "Web&Mobile": {
        "title": "Web and mobile controls",
        "intro": "Web application requirements, WAF expectations, and mobile application security controls.",
    },
    "VOIP": {
        "title": "VOIP specialist controls",
        "intro": "Specialist VOIP and telephony requirements that normally need architect review.",
    },
    "CPE": {
        "title": "CPE specialist controls",
        "intro": "Specialist customer-premise-equipment controls and hardware-centric requirements.",
    },
    "Info-API Security Checklist": {
        "title": "Supplemental API checklist",
        "intro": "Supplemental reference sheet retained for traceability.",
    },
}


def _module_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _catalog_path() -> Path:
    return _module_root() / "data" / "document_requirement_catalog.json"


def _template_workbook_path() -> Path:
    return _module_root() / "data" / SOURCE_WORKBOOK_NAME


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, Any]:
    return json.loads(_catalog_path().read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _load_template_bytes() -> bytes:
    return _template_workbook_path().read_bytes()


def _normalize_answer(value: str | None) -> str:
    return (value or "").strip()


def _answer_is_yes(value: str | None) -> bool:
    return _normalize_answer(value).upper() == _YES


def _lower_blob(*parts: str) -> str:
    return " ".join(part for part in parts if part).casefold()


def _slugify(value: str) -> str:
    candidate = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return candidate or "generated"


def _parse_answer_options(value: str) -> list[str]:
    text = (value or "").strip()
    if not text:
        return []
    if "\n" in text:
        return [part.strip() for part in text.splitlines() if part.strip()]
    return [part.strip() for part in re.split(r"\s{2,}|(?<!\w)/(?!\w)", text) if part.strip()]


def _sanitize_profile(profile: dict[str, Any] | None) -> dict[str, str]:
    source = profile or {}
    return {
        "project_name": str(source.get("project_name", "") or "").strip(),
        "requester_name": str(source.get("requester_name", "") or "").strip(),
        "team_name": str(source.get("team_name", "") or "").strip(),
        "jira_reference": str(source.get("jira_reference", "") or "").strip(),
        "service_summary": str(source.get("service_summary", "") or "").strip(),
        "architecture_notes": str(source.get("architecture_notes", "") or "").strip(),
        "interface_notes": str(source.get("interface_notes", "") or "").strip(),
        "deployment_notes": str(source.get("deployment_notes", "") or "").strip(),
    }


def _sanitize_base_answers(base_answers: dict[str, Any] | None) -> dict[str, str]:
    source = base_answers or {}
    return {
        key: str(source.get(key, "") or "").strip()
        for key in _QUESTION_OPTIONS
        if str(source.get(key, "") or "").strip()
    }


def _sanitize_requirement_answers(requirement_answers: dict[str, Any] | None) -> dict[str, dict[str, dict[str, str | None]]]:
    clean: dict[str, dict[str, dict[str, str | None]]] = {}
    for sheet, raw_sheet_answers in (requirement_answers or {}).items():
        if not isinstance(raw_sheet_answers, dict):
            continue
        sheet_answers: dict[str, dict[str, str | None]] = {}
        for item_id, raw_answer in raw_sheet_answers.items():
            if not isinstance(raw_answer, dict):
                continue
            compliance = str(raw_answer.get("compliance", "") or "").strip()
            if compliance and compliance not in _COMPLIANCE_OPTIONS:
                continue
            project_response = str(raw_answer.get("project_response", "") or "").strip()
            if not compliance and not project_response:
                continue
            sheet_answers[str(item_id)] = {
                "compliance": compliance or None,
                "project_response": project_response,
            }
        if sheet_answers:
            clean[str(sheet)] = sheet_answers
    return clean


def canonicalize_document_patch(
    *,
    profile: dict[str, Any] | None,
    base_answers: dict[str, Any] | None,
    requirement_answers: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "profile": _sanitize_profile(profile),
        "base_answers": _sanitize_base_answers(base_answers),
        "requirement_answers": _sanitize_requirement_answers(requirement_answers),
    }


def build_document_model() -> dict[str, Any]:
    catalog = _load_catalog()
    base_questions: list[dict[str, Any]] = []
    for question in catalog.get("base_questionnaire", []):
        question_id = str(question.get("id", "") or "").strip()
        if not question_id:
            continue
        group = next(
            (group_name for group_name, members in _QUESTION_GROUPS.items() if question_id in members),
            "project_frame",
        )
        base_questions.append(
            {
                "id": question_id,
                "row": int(question.get("row", 0) or 0),
                "prompt": str(question.get("prompt", "") or "").strip(),
                "instruction": str(question.get("instruction", "") or "").strip(),
                "comments": str(question.get("comments", "") or "").strip(),
                "guideline": str(question.get("guideline", "") or "").strip(),
                "group": group,
                "required": question_id != "0.1.7",
                "depends_on": "0.1.6" if question_id == "0.1.7" else None,
                "expected_when": _YES if question_id == "0.1.7" else None,
                "options": [
                    {"value": option, "label": option}
                    for option in _QUESTION_OPTIONS.get(question_id, [])
                ],
            }
        )
    sections: list[dict[str, Any]] = []
    for section in catalog.get("sections", []):
        sheet = str(section.get("sheet", "") or "").strip()
        if not sheet:
            continue
        section_items: list[dict[str, Any]] = []
        for item in section.get("items", []):
            item_id = str(item.get("id", "") or "").strip()
            section_items.append(
                {
                    "row": int(item.get("row", 0) or 0),
                    "id": item_id,
                    "type": str(item.get("type", "requirement") or "requirement"),
                    "title_or_requirement": str(item.get("title_or_requirement", "") or "").strip(),
                    "questionnaire_prompt": str(item.get("questionnaire_prompt", "") or "").strip(),
                    "answer_options": str(item.get("answer_options", "") or "").strip(),
                    "question_options": _parse_answer_options(str(item.get("answer_options", "") or "")),
                    "requirement_text": str(item.get("requirement_text", "") or "").strip(),
                    "security_comment": str(item.get("security_comment", "") or "").strip(),
                    "policy_reference": str(item.get("policy_reference", "") or "").strip(),
                }
            )
        copy = _SECTION_COPY.get(sheet, {})
        sections.append(
            {
                "sheet": sheet,
                "mode": str(section.get("mode", "") or "").strip(),
                "title": copy.get("title", sheet),
                "intro": copy.get("intro", ""),
                "item_count": int(section.get("item_count", 0) or 0),
                "items": section_items,
            }
        )
    return {
        "source_workbook": SOURCE_WORKBOOK_NAME,
        "question_groups": dict(_QUESTION_GROUPS),
        "base_questions": base_questions,
        "sections": sections,
        "recommendation_catalog": list(_RECOMMENDATION_CATALOG),
    }


def _visible_base_questions(base_answers: dict[str, str]) -> list[str]:
    visible = list(_QUESTION_GROUPS["project_frame"]) + [
        question_id
        for question_id in _QUESTION_GROUPS["specialist_flags"]
        if question_id != "0.1.7"
    ]
    if _answer_is_yes(base_answers.get("0.1.6")):
        visible.insert(visible.index("0.1.8"), "0.1.7")
    return visible


def _section_catalog_map() -> dict[str, dict[str, Any]]:
    return {
        str(section.get("sheet", "") or "").strip(): section
        for section in _load_catalog().get("sections", [])
    }


def _active_item_ids_for_section(
    *,
    sheet: str,
    status: str,
    base_answers: dict[str, str],
    profile: dict[str, str],
) -> list[str]:
    section = _section_catalog_map().get(sheet)
    if not section or status != "in_scope":
        return []
    items = section.get("items", [])
    if sheet != "Web&Mobile":
        return [str(item.get("id", "") or "").strip() for item in items if str(item.get("id", "") or "").strip()]

    external_interface = "external" in _normalize_answer(base_answers.get("0.1.2")).casefold()
    customer_facing = _answer_is_yes(base_answers.get("0.1.4"))
    api_usage = _answer_is_yes(base_answers.get("api_usage"))
    mobile = _answer_is_yes(base_answers.get("0.1.8"))
    web_required = external_interface or customer_facing or api_usage
    mobile_required = mobile
    active: list[str] = []
    for item in items:
        item_id = str(item.get("id", "") or "").strip()
        if not item_id:
            continue
        if re.match(r"^9\.[1-5](\.|$)", item_id):
            if web_required:
                active.append(item_id)
            continue
        if re.match(r"^9\.(6|7|8|9|10)(\.|$)", item_id):
            if mobile_required:
                active.append(item_id)
    if not active:
        summary_blob = _lower_blob(
            profile.get("service_summary", ""),
            profile.get("interface_notes", ""),
        )
        if any(keyword in summary_blob for keyword in ("web", "portal", "frontend", "ui")):
            active.extend(
                [
                    str(item.get("id", "") or "").strip()
                    for item in items
                    if re.match(r"^9\.[1-5](\.|$)", str(item.get("id", "") or "").strip())
                ]
            )
    return active


def compute_scope_summary(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
) -> list[dict[str, Any]]:
    summary_blob = _lower_blob(
        profile.get("project_name", ""),
        profile.get("service_summary", ""),
        profile.get("architecture_notes", ""),
        profile.get("interface_notes", ""),
        profile.get("deployment_notes", ""),
    )
    external_interface = "external" in _normalize_answer(base_answers.get("0.1.2")).casefold()
    customer_facing = _answer_is_yes(base_answers.get("0.1.4"))
    data_sensitive = _answer_is_yes(base_answers.get("0.1.5"))
    api_usage = _answer_is_yes(base_answers.get("api_usage"))
    third_party = _answer_is_yes(base_answers.get("0.1.6"))
    mobile = _answer_is_yes(base_answers.get("0.1.8"))
    cpe = _answer_is_yes(base_answers.get("0.1.9"))
    black_box = _answer_is_yes(base_answers.get("0.1.10"))
    logging_trackable = _answer_is_yes(base_answers.get("0.1.11"))
    voip_detected = any(keyword in summary_blob for keyword in ("voip", "telephony", "sip", "ip phone", "voice", "uc "))

    decisions: list[dict[str, Any]] = []
    for section in build_document_model()["sections"]:
        sheet = str(section["sheet"])
        reasons: list[str]
        status: str
        if sheet == "Hygiene&Essentials":
            status = "in_scope"
            reasons = ["Mandatory baseline sheet for every SbD document."]
        elif sheet == "Logging&Monitoring":
            status = "in_scope"
            reasons = [
                "Mandatory logging baseline for every deployment.",
                "Requester must explain any area where logging cannot be tracked."
                if not logging_trackable
                else "Requester confirmed admin and user activity can be tracked.",
            ]
        elif sheet == "User&Accounts":
            status = "in_scope"
            reasons = ["Mandatory access and authentication controls for every deployment."]
        elif sheet == "DataProtection":
            if data_sensitive:
                status = "in_scope"
                reasons = ["Project handles personal, C3, or C4 data."]
            else:
                status = "out_of_scope"
                reasons = ["Requester did not declare personal, C3, or C4 data processing."]
        elif sheet == "APIs":
            if api_usage:
                status = "in_scope"
                reasons = ["Requester confirmed HTTP-based API exposure or consumption."]
            else:
                status = "out_of_scope"
                reasons = ["Requester did not declare SOAP, REST, or JSON API usage."]
        elif sheet == "Supplier&3rdParty":
            if third_party:
                status = "in_scope"
                reasons = ["Requester confirmed third-party involvement in delivery or operations."]
            else:
                status = "out_of_scope"
                reasons = ["No third-party development, maintenance, integration, testing, or support declared."]
        elif sheet == "Web&Mobile":
            if external_interface or customer_facing or api_usage or mobile:
                status = "in_scope"
                reasons = []
                if external_interface or customer_facing:
                    reasons.append("Web-facing controls apply because the service has external or customer-facing exposure.")
                if api_usage:
                    reasons.append("HTTP-based API usage suggests web-facing security controls should stay visible.")
                if mobile:
                    reasons.append("Requester confirmed mobile application development or usage.")
            else:
                status = "out_of_scope"
                reasons = ["No external, customer-facing, API-driven, or mobile application exposure was declared."]
        elif sheet == "VOIP":
            if voip_detected:
                status = "in_scope"
                reasons = ["Project notes include VOIP, SIP, telephony, or voice-service indicators."]
            else:
                status = "architect_review"
                reasons = ["VOIP remains specialist scope and should be confirmed by the security architect."]
        elif sheet == "CPE":
            if cpe:
                status = "in_scope"
                reasons = ["Requester confirmed customer premise equipment is part of the scope."]
            elif black_box:
                status = "architect_review"
                reasons = ["Appliance or black-box delivery was declared and may overlap with specialist hardware scope."]
            else:
                status = "out_of_scope"
                reasons = ["Requester did not declare customer premise equipment."]
        else:
            status = "architect_review"
            reasons = ["Supplemental or specialist sheet retained for traceability."]

        active_item_ids = _active_item_ids_for_section(
            sheet=sheet,
            status=status,
            base_answers=base_answers,
            profile=profile,
        )
        answered_requirements = 0
        total_requirements = 0
        sheet_answers = requirement_answers.get(sheet, {})
        for item in section["items"]:
            if item["type"] != "requirement":
                continue
            if status == "in_scope" and item["id"] not in active_item_ids:
                continue
            if status != "in_scope":
                continue
            total_requirements += 1
            if sheet_answers.get(item["id"], {}).get("compliance"):
                answered_requirements += 1
        decisions.append(
            {
                "sheet": sheet,
                "mode": section["mode"],
                "status": status,
                "reasons": reasons,
                "active_item_ids": active_item_ids,
                "answered_requirements": answered_requirements,
                "total_requirements": total_requirements,
            }
        )
    return decisions


def _build_validation(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
    scope_summary: list[dict[str, Any]],
) -> dict[str, Any]:
    missing_profile_fields = [
        field_name
        for field_name in ("project_name", "service_summary", "requester_name")
        if not profile.get(field_name, "").strip()
    ]
    missing_base_questions = [
        question_id
        for question_id in _visible_base_questions(base_answers)
        if not base_answers.get(question_id, "").strip()
    ]
    missing_requirement_answers: list[dict[str, str]] = []
    missing_project_responses: list[dict[str, str]] = []
    model = build_document_model()
    section_map = {section["sheet"]: section for section in model["sections"]}
    for decision in scope_summary:
        if decision["status"] != "in_scope":
            continue
        section = section_map[decision["sheet"]]
        sheet_answers = requirement_answers.get(decision["sheet"], {})
        active_ids = set(decision["active_item_ids"])
        for item in section["items"]:
            if item["type"] != "requirement" or item["id"] not in active_ids:
                continue
            answer = sheet_answers.get(item["id"], {})
            compliance = str(answer.get("compliance", "") or "").strip()
            project_response = str(answer.get("project_response", "") or "").strip()
            if not compliance:
                missing_requirement_answers.append(
                    {
                        "sheet": decision["sheet"],
                        "requirement_id": item["id"],
                        "prompt": item["questionnaire_prompt"] or item["requirement_text"],
                    }
                )
                continue
            if compliance in {"Yes", "Partial", "Not applicable"} and not project_response:
                missing_project_responses.append(
                    {
                        "sheet": decision["sheet"],
                        "requirement_id": item["id"],
                    }
                )
    warnings: list[str] = []
    if _answer_is_yes(base_answers.get("0.1.6")) and not _answer_is_yes(base_answers.get("0.1.7")):
        warnings.append("Third-party involvement is declared but the Supplier Cyber Security Questionnaire is not confirmed.")
    if _answer_is_yes(base_answers.get("0.1.10")):
        warnings.append("Appliance or black-box scope usually needs deeper architect review and security evidence.")
    if not _answer_is_yes(base_answers.get("0.1.11")):
        warnings.append("The requester has not confirmed that admin and user activity can be tracked.")
    return {
        "missing_profile_fields": missing_profile_fields,
        "missing_base_questions": missing_base_questions,
        "missing_requirement_answers": missing_requirement_answers,
        "missing_project_responses": missing_project_responses,
        "warnings": warnings,
        "ready_for_architect_review": not (
            missing_profile_fields
            or missing_base_questions
            or missing_requirement_answers
            or missing_project_responses
        ),
    }


def _build_completion(
    *,
    base_answers: dict[str, str],
    scope_summary: list[dict[str, Any]],
    validation: dict[str, Any],
) -> dict[str, Any]:
    total_base_questions = len(_visible_base_questions(base_answers))
    answered_base_questions = total_base_questions - len(validation["missing_base_questions"])
    total_requirements = sum(
        int(decision["total_requirements"])
        for decision in scope_summary
        if decision["status"] == "in_scope"
    )
    answered_requirements = sum(
        int(decision["answered_requirements"])
        for decision in scope_summary
        if decision["status"] == "in_scope"
    )
    return {
        "answered_base_questions": answered_base_questions,
        "total_base_questions": total_base_questions,
        "answered_requirements": answered_requirements,
        "total_requirements": total_requirements,
        "ready_for_architect_review": bool(validation["ready_for_architect_review"]),
    }


def build_session_payload(
    *,
    document_id: str,
    status: str,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
    updated_at: datetime,
) -> dict[str, Any]:
    clean_profile = _sanitize_profile(profile)
    clean_base_answers = _sanitize_base_answers(base_answers)
    clean_requirement_answers = _sanitize_requirement_answers(requirement_answers)
    scope_summary = compute_scope_summary(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
    )
    validation = _build_validation(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
        scope_summary=scope_summary,
    )
    completion = _build_completion(
        base_answers=clean_base_answers,
        scope_summary=scope_summary,
        validation=validation,
    )
    return {
        "id": document_id,
        "status": status,
        "source_workbook": SOURCE_WORKBOOK_NAME,
        "profile": clean_profile,
        "base_answers": clean_base_answers,
        "requirement_answers": clean_requirement_answers,
        "scope_summary": scope_summary,
        "validation": validation,
        "completion": completion,
        "updated_at": updated_at,
    }


def _add_recommendation(
    recommendations: list[dict[str, Any]],
    *,
    key: str,
    status: str,
    rationale: str,
    source: str,
) -> None:
    if any(existing["key"] == key for existing in recommendations):
        return
    label = next(
        (item["label"] for item in _RECOMMENDATION_CATALOG if item["key"] == key),
        key.replace("_", " ").title(),
    )
    recommendations.append(
        {
            "key": key,
            "label": label,
            "status": status,
            "rationale": rationale,
            "source": source,
            "provisional_component": False,
        }
    )


def build_next_steps(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
) -> dict[str, Any]:
    clean_profile = _sanitize_profile(profile)
    clean_base_answers = _sanitize_base_answers(base_answers)
    clean_requirement_answers = _sanitize_requirement_answers(requirement_answers)
    scope_summary = compute_scope_summary(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
    )
    validation = _build_validation(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
        scope_summary=scope_summary,
    )

    summary_blob = _lower_blob(
        clean_profile.get("service_summary", ""),
        clean_profile.get("architecture_notes", ""),
        clean_profile.get("interface_notes", ""),
        clean_profile.get("deployment_notes", ""),
    )
    lifecycle_answer = _normalize_answer(clean_base_answers.get("0.1.1")).casefold()
    external_interface = "external" in _normalize_answer(clean_base_answers.get("0.1.2")).casefold()
    customer_facing = _answer_is_yes(clean_base_answers.get("0.1.4"))
    data_sensitive = _answer_is_yes(clean_base_answers.get("0.1.5"))
    api_usage = _answer_is_yes(clean_base_answers.get("api_usage"))
    third_party = _answer_is_yes(clean_base_answers.get("0.1.6"))
    mobile = _answer_is_yes(clean_base_answers.get("0.1.8"))
    cpe = _answer_is_yes(clean_base_answers.get("0.1.9"))
    black_box = _answer_is_yes(clean_base_answers.get("0.1.10"))
    logging_trackable = _answer_is_yes(clean_base_answers.get("0.1.11"))
    new_or_changed_service = bool(lifecycle_answer)
    containerized = any(
        keyword in summary_blob for keyword in ("container", "kubernetes", "docker", "helm", "pod")
    )
    database_backed = any(
        keyword in summary_blob for keyword in ("database", " db", "sql", "oracle", "postgres", "mysql")
    )
    web_or_api_exposure = external_interface or customer_facing or api_usage or any(
        keyword in summary_blob for keyword in ("web", "portal", "frontend", "website", "browser", "rest api", "api gateway")
    )
    windows_hosted = any(
        keyword in summary_blob for keyword in ("windows", "iis", "active directory", "powershell", ".net", "mssql")
    )
    unix_hosted = containerized or any(
        keyword in summary_blob for keyword in ("linux", "unix", "ubuntu", "debian", "red hat", "rhel", "nginx", "apache")
    )
    privileged_access = any(
        keyword in summary_blob for keyword in ("admin", "administrator", "privileged", "root", "sudo", "service account", "cyberark")
    )
    voip_like = any(keyword in summary_blob for keyword in ("voip", "telephony", "sip", "voice", "ip phone"))

    recommendations: list[dict[str, Any]] = []
    _add_recommendation(
        recommendations,
        key="secure_by_design_assesment",
        status="required",
        rationale="Every new SbD review request should explicitly investigate the Secure by Design assessment track.",
        source="SbD workflow",
    )
    _add_recommendation(
        recommendations,
        key="network_segment_placement",
        status="required",
        rationale="Network placement and segmentation are baseline architecture checks for every SbD review.",
        source="Hygiene&Essentials",
    )
    _add_recommendation(
        recommendations,
        key="application_logging",
        status="required",
        rationale="Application logging is part of the mandatory Logging & Monitoring sheet.",
        source="Logging&Monitoring",
    )
    _add_recommendation(
        recommendations,
        key="vulnerability_scan_tenable",
        status="required",
        rationale="A deployable service should be investigated for infrastructure vulnerability scanning during SbD review.",
        source="SbD workflow",
    )
    if new_or_changed_service:
        _add_recommendation(
            recommendations,
            key="archer_inventory_update",
            status="suggested",
            rationale="A new or changed service usually needs its governance inventory updated alongside the SbD review.",
            source="Project lifecycle",
        )
    if logging_trackable or customer_facing or external_interface:
        _add_recommendation(
            recommendations,
            key="arcsight_new_update_alert_request",
            status="suggested",
            rationale="Central alerting should be investigated when the service needs operational and security event monitoring.",
            source="Logging&Monitoring",
        )
    if unix_hosted:
        _add_recommendation(
            recommendations,
            key="operating_system_logging_unix",
            status="required",
            rationale="Deployment notes indicate Unix or Linux style hosting that should use the Unix operating system logging track.",
            source="Deployment notes",
        )
    if windows_hosted:
        _add_recommendation(
            recommendations,
            key="operating_system_logging_windows",
            status="required",
            rationale="Deployment notes indicate Windows hosting that should use the Windows operating system logging track.",
            source="Deployment notes",
        )
    if database_backed:
        _add_recommendation(
            recommendations,
            key="database_logging",
            status="suggested",
            rationale="Project notes suggest database components that should be investigated for database logging.",
            source="Architecture notes",
        )
    if web_or_api_exposure:
        _add_recommendation(
            recommendations,
            key="penetration_testing",
            status="required",
            rationale="Customer-facing or externally exposed services typically need penetration testing before handoff.",
            source="Exposure",
        )
        _add_recommendation(
            recommendations,
            key="waf_integration",
            status="suggested",
            rationale="The workbook explicitly calls out WAF for critical or internet-published web services.",
            source="Web&Mobile 9.5.2",
        )
        _add_recommendation(
            recommendations,
            key="dast",
            status="suggested",
            rationale="Dynamic testing is a common follow-up for externally reachable web services.",
            source="Exposure",
        )
        _add_recommendation(
            recommendations,
            key="proxy_definition",
            status="required",
            rationale="Externally exposed web or API services usually need proxy positioning defined as part of the review.",
            source="APIs",
        )
        _add_recommendation(
            recommendations,
            key="web_certificate_request",
            status="suggested",
            rationale="Customer-facing or externally published web services usually need certificate handling investigated.",
            source="Web exposure",
        )
    if external_interface:
        _add_recommendation(
            recommendations,
            key="access_point_integration",
            status="suggested",
            rationale="External exposure should trigger investigation of the relevant access point integration path.",
            source="Base Questionnaire",
        )
    if api_usage or web_or_api_exposure or new_or_changed_service:
        _add_recommendation(
            recommendations,
            key="sast",
            status="suggested",
            rationale="Code-bearing services should usually be investigated for SAST during the SbD review.",
            source="Application delivery",
        )
        _add_recommendation(
            recommendations,
            key="scs",
            status="suggested",
            rationale="Source code security checks should be investigated for application delivery changes.",
            source="Application delivery",
        )
        _add_recommendation(
            recommendations,
            key="software_composition_analysis_sca",
            status="suggested",
            rationale="Dependency and package composition risk should be investigated for application delivery changes.",
            source="Application delivery",
        )
    if data_sensitive or black_box or cpe or voip_like:
        _add_recommendation(
            recommendations,
            key="risk_assesment",
            status="required",
            rationale="Sensitive data, specialist platforms, or opaque delivery models should trigger the formal risk assessment track.",
            source="Risk indicators",
        )
    if mobile or privileged_access or black_box or cpe:
        _add_recommendation(
            recommendations,
            key="privileged_user_access_management_integrations_cyberark",
            status="suggested",
            rationale="Projects with privileged administration paths should investigate Cyberark-based privileged access handling.",
            source="User&Accounts",
        )
    if third_party:
        _add_recommendation(
            recommendations,
            key="onetrust_supplier_security_assesment",
            status="required",
            rationale="Third-party involvement should trigger the OneTrust supplier security assessment track.",
            source="Supplier&3rdParty",
        )
    if black_box or data_sensitive or external_interface:
        _add_recommendation(
            recommendations,
            key="file_integrity_monitoring_integration",
            status="suggested",
            rationale="Higher-risk deployments should investigate file integrity monitoring as part of runtime protection.",
            source="Risk indicators",
        )
    if windows_hosted or privileged_access:
        _add_recommendation(
            recommendations,
            key="cyberark_epm",
            status="suggested",
            rationale="Windows-heavy or privileged-admin environments should investigate Cyberark-EPM applicability.",
            source="Deployment notes",
        )
    if containerized:
        _add_recommendation(
            recommendations,
            key="container_security_scan",
            status="suggested",
            rationale="Project notes mention containers or orchestration artifacts that should trigger container security scanning.",
            source="Architecture notes",
        )
        _add_recommendation(
            recommendations,
            key="container_native_firewall",
            status="suggested",
            rationale="Containerized workloads should also investigate the relevant container-native firewall controls.",
            source="Architecture notes",
        )

    architect_review: list[str] = []
    for decision in scope_summary:
        if decision["status"] == "architect_review":
            architect_review.append(f"{decision['sheet']}: {' '.join(decision['reasons'])}")
    requester_expectations = [
        "The generated workbook should be reviewed with the assigned security architect before Jira closure.",
        "Any specialist areas flagged for architect review stay visible so the requester knows what will be discussed next.",
        "Suggested Jira components and sub-tasks now use the official SbD component list that the team provided.",
    ]
    return {
        "recommendations": recommendations,
        "requester_expectations": requester_expectations,
        "architect_review": architect_review,
        "validation_warnings": list(validation["warnings"]),
    }


def build_guidance_summary(
    *,
    profile: dict[str, str],
    next_steps: dict[str, Any],
) -> str:
    clean_profile = _sanitize_profile(profile)
    recommendations = list(next_steps.get("recommendations", []))
    architect_review = list(next_steps.get("architect_review", []))
    validation_warnings = list(next_steps.get("validation_warnings", []))
    project_name = clean_profile.get("project_name", "").strip() or "This SbD request"

    required = [item["label"] for item in recommendations if item.get("status") == "required"]
    suggested = [item["label"] for item in recommendations if item.get("status") != "required"]
    lead_items = required[:3] or suggested[:3]

    summary_parts = [
        f"{project_name} can continue in the module without a manual Excel session.",
    ]
    if lead_items:
        summary_parts.append(
            "The strongest follow-up areas right now are "
            + ", ".join(lead_items[:-1] + [f"and {lead_items[-1]}"] if len(lead_items) > 1 else lead_items)
            + "."
        )
    if architect_review:
        summary_parts.append(
            "Specialist review is still needed for "
            + ", ".join(entry.split(":", 1)[0] for entry in architect_review[:3])
            + "."
        )
    if validation_warnings:
        summary_parts.append(
            "There are still validation gaps to close before the generated workbook is fully ready for architect review."
        )
    else:
        summary_parts.append(
            "The current answers are consistent enough to generate the workbook and continue to architect review."
        )
    return " ".join(summary_parts)


def build_jira_draft(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
) -> dict[str, Any]:
    clean_profile = _sanitize_profile(profile)
    clean_base_answers = _sanitize_base_answers(base_answers)
    clean_requirement_answers = _sanitize_requirement_answers(requirement_answers)
    session = build_session_payload(
        document_id="preview",
        status="draft",
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
        updated_at=utc_now(),
    )
    next_steps = build_next_steps(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
    )
    project_name = clean_profile.get("project_name", "").strip() or "Unnamed SbD request"
    workbook_filename = f"sbd-nfr-{_slugify(project_name)}.xlsx"
    in_scope_sections = [
        decision["sheet"]
        for decision in session["scope_summary"]
        if decision["status"] == "in_scope"
    ]
    suggested_sub_tasks = [recommendation["label"] for recommendation in next_steps["recommendations"]]
    description_lines = [
        f"Project: {project_name}",
        f"Requester: {clean_profile.get('requester_name', '') or 'Not provided'}",
        f"Team: {clean_profile.get('team_name', '') or 'Not provided'}",
        "",
        "Service Summary:",
        clean_profile.get("service_summary", "") or "Not provided",
        "",
        "In-Scope Workbook Sections:",
        *[f"- {section}" for section in in_scope_sections],
        "",
        "Architect Review Flags:",
        *([f"- {note}" for note in next_steps["architect_review"]] or ["- None currently flagged."]),
        "",
        "Suggested SbD Follow-Up:",
        *[f"- {recommendation['label']}: {recommendation['rationale']}" for recommendation in next_steps["recommendations"]],
        "",
        "Validation Warnings:",
        *([f"- {warning}" for warning in session["validation"]["warnings"]] or ["- None."]),
    ]
    return {
        "summary": f"SbD NFR - {project_name}",
        "description_markdown": "\n".join(description_lines).strip(),
        "suggested_components": suggested_sub_tasks,
        "suggested_sub_tasks": suggested_sub_tasks,
        "workbook_filename": workbook_filename,
        "component_mapping_status": "confirmed_from_official_sbd_component_list",
        "labels": ["sbd", "nfr", "generated-workbook"],
    }


def _qname(name: str) -> str:
    return f"{{{_MAIN_NS}}}{name}"


def _ensure_row(sheet_data: ET.Element, row_number: int) -> ET.Element:
    for row in sheet_data.findall("a:row", _NS):
        if int(row.attrib.get("r", "0") or "0") == row_number:
            return row
    return ET.SubElement(sheet_data, _qname("row"), {"r": str(row_number)})


def _ensure_cell(sheet_root: ET.Element, cell_ref: str) -> ET.Element:
    cell = sheet_root.find(f".//a:c[@r='{cell_ref}']", _NS)
    if cell is not None:
        return cell
    match = re.match(r"([A-Z]+)(\d+)$", cell_ref)
    if match is None:
        raise ValueError(f"Invalid cell reference '{cell_ref}'.")
    sheet_data = sheet_root.find("a:sheetData", _NS)
    if sheet_data is None:
        raise ValueError("Worksheet is missing sheetData.")
    row = _ensure_row(sheet_data, int(match.group(2)))
    return ET.SubElement(row, _qname("c"), {"r": cell_ref})


def _set_cell_text(sheet_root: ET.Element, cell_ref: str, value: str) -> None:
    cell = _ensure_cell(sheet_root, cell_ref)
    for child in list(cell):
        cell.remove(child)
    if not value:
        cell.attrib.pop("t", None)
        return
    cell.set("t", "inlineStr")
    inline = ET.SubElement(cell, _qname("is"))
    text = ET.SubElement(inline, _qname("t"))
    if value[:1].isspace() or value[-1:].isspace() or "\n" in value:
        text.set(_XML_SPACE, "preserve")
    text.text = value


def _render_workbook(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
) -> tuple[bytes, list[dict[str, Any]]]:
    session = build_session_payload(
        document_id="generated",
        status="draft",
        profile=profile,
        base_answers=base_answers,
        requirement_answers=requirement_answers,
        updated_at=utc_now(),
    )
    scope_map = {decision["sheet"]: decision for decision in session["scope_summary"]}
    catalog = _load_catalog()
    section_map = {section["sheet"]: section for section in catalog.get("sections", [])}
    source_buffer = BytesIO(_load_template_bytes())
    output_buffer = BytesIO()
    with ZipFile(source_buffer, "r") as source_zip, ZipFile(output_buffer, "w", ZIP_DEFLATED) as output_zip:
        for entry in source_zip.infolist():
            payload = source_zip.read(entry.filename)
            if entry.filename == _SECTION_SHEET_PATHS["0.Base Questionnaire"]:
                sheet_root = ET.fromstring(payload)
                for question in catalog.get("base_questionnaire", []):
                    row = int(question.get("row", 0) or 0)
                    question_id = str(question.get("id", "") or "").strip()
                    _set_cell_text(sheet_root, f"C{row}", base_answers.get(question_id, ""))
                payload = ET.tostring(sheet_root, encoding="utf-8", xml_declaration=True)
            elif entry.filename in _SECTION_SHEET_PATHS.values():
                section_name = next(
                    (
                        sheet
                        for sheet, path in _SECTION_SHEET_PATHS.items()
                        if path == entry.filename and sheet != "0.Base Questionnaire"
                    ),
                    None,
                )
                if section_name and section_name in section_map and section_name in _SECTION_LAYOUTS:
                    sheet_root = ET.fromstring(payload)
                    layout = _SECTION_LAYOUTS[section_name]
                    decision = scope_map.get(
                        section_name,
                        {"status": "out_of_scope", "active_item_ids": [], "answered_requirements": 0, "total_requirements": 0},
                    )
                    active_ids = set(decision.get("active_item_ids", []))
                    sheet_answers = requirement_answers.get(section_name, {})
                    for item in section_map[section_name].get("items", []):
                        row = int(item.get("row", 0) or 0)
                        item_id = str(item.get("id", "") or "").strip()
                        if not item_id:
                            continue
                        compliance_cell = f"{layout['compliance_column']}{row}"
                        response_cell = f"{layout['response_column']}{row}"
                        if decision["status"] != "in_scope" or item_id not in active_ids:
                            _set_cell_text(sheet_root, compliance_cell, "NOT IN SCOPE")
                            _set_cell_text(sheet_root, response_cell, "")
                            continue
                        if str(item.get("type", "requirement")) != "requirement":
                            _set_cell_text(sheet_root, compliance_cell, "")
                            _set_cell_text(sheet_root, response_cell, "")
                            continue
                        answer = sheet_answers.get(item_id, {})
                        _set_cell_text(sheet_root, compliance_cell, str(answer.get("compliance", "") or ""))
                        _set_cell_text(sheet_root, response_cell, str(answer.get("project_response", "") or ""))
                    payload = ET.tostring(sheet_root, encoding="utf-8", xml_declaration=True)
            output_zip.writestr(entry, payload)
    return output_buffer.getvalue(), [
        {
            "sheet": decision["sheet"],
            "status": decision["status"],
            "answered_requirements": decision["answered_requirements"],
            "total_requirements": decision["total_requirements"],
        }
        for decision in session["scope_summary"]
    ]


def build_workbook_payload(
    *,
    profile: dict[str, str],
    base_answers: dict[str, str],
    requirement_answers: dict[str, dict[str, dict[str, str | None]]],
) -> dict[str, Any]:
    clean_profile = _sanitize_profile(profile)
    clean_base_answers = _sanitize_base_answers(base_answers)
    clean_requirement_answers = _sanitize_requirement_answers(requirement_answers)
    session = build_session_payload(
        document_id="generated",
        status="draft",
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
        updated_at=utc_now(),
    )
    workbook_bytes, section_summaries = _render_workbook(
        profile=clean_profile,
        base_answers=clean_base_answers,
        requirement_answers=clean_requirement_answers,
    )
    project_name = clean_profile.get("project_name", "").strip() or "sbd-nfr"
    filename = f"sbd-nfr-{_slugify(project_name)}.xlsx"
    validation = session["validation"]
    pending_fields = (
        len(validation["missing_profile_fields"])
        + len(validation["missing_base_questions"])
        + len(validation["missing_requirement_answers"])
        + len(validation["missing_project_responses"])
    )
    return {
        "filename": filename,
        "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "content_base64": base64.b64encode(workbook_bytes).decode("ascii"),
        "generated_at": utc_now(),
        "pending_fields": pending_fields,
        "ready_for_architect_review": bool(validation["ready_for_architect_review"]),
        "section_summaries": section_summaries,
    }
