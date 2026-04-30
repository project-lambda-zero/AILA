"""AILA NFR Assessment Workbook Extraction Script.

Reads the existing document_requirement_catalog.json (already extracted from the
AILA NFR Security Workbook) and the _RECOMMENDATION_CATALOG / _QUESTION_OPTIONS /
_SECTION_COPY constants from document_engine.py, then produces five canonical
seed JSON files consumed by seed_data() during module initialisation.

Run directly:
    python -m aila.modules.sbd_nfr.scripts.extract_nfr

The script is idempotent — re-running it overwrites the seed files with the
same content derived from the same source data.

Output files (all under src/aila/modules/sbd_nfr/data/):
  seed_subtasks.json    -- 25 SbD sub-task component definitions
  seed_sections.json    -- scope + 9 NFR sections with subgroups
  seed_questions.json   -- all questions with semantic IDs
  seed_options.json     -- per-question answer options + __COMPLIANCE__ template
  seed_mappings.json    -- question-to-subtask coverage matrix
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_log = __import__("logging").getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_SCRIPTS_DIR = Path(__file__).resolve().parent
_MODULE_ROOT = _SCRIPTS_DIR.parent
_DATA_DIR = _MODULE_ROOT / "data"
_CATALOG_PATH = _DATA_DIR / "document_requirement_catalog.json"

# ---------------------------------------------------------------------------
# Source constants from document_engine (kept here to avoid import coupling)
# ---------------------------------------------------------------------------

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
}

# ---------------------------------------------------------------------------
# Section → semantic prefix + skip logic mapping
# ---------------------------------------------------------------------------

# Each entry: (section_key, label, prefix, display_order, depends_on_question_id, expected_when, is_specialist)
_SECTION_META: list[tuple[str, str, str, int, str | None, str | None, bool]] = [
    ("scope", "Scope Assessment", "SCOPE", 0, None, None, False),
    ("hygiene_essentials", "Security Hygiene & Essentials", "HYGN", 1, None, None, False),
    ("data_protection", "Data Protection", "DPROT", 2, "SCOPE-05", "YES", False),
    ("logging_monitoring", "Logging & Monitoring", "LOG", 3, None, None, False),
    ("user_accounts", "User & Accounts", "UACC", 4, None, None, False),
    ("apis", "APIs", "APIS", 5, "SCOPE-02", "YES", False),
    ("supplier_third_party", "Supplier & 3rd Party", "SUPP", 6, "SCOPE-06", "YES", False),
    ("web_mobile", "Web & Mobile", "WEBM", 7, "SCOPE-04", "YES", False),
    ("voip", "VOIP", "VOIP", 8, "SCOPE-09", "YES", True),
    ("cpe", "CPE", "CPE", 9, "SCOPE-11", "YES", True),
]

# Map catalog sheet names to section_keys
_SHEET_TO_SECTION: dict[str, str] = {
    "Hygiene&Essentials": "hygiene_essentials",
    "DataProtection": "data_protection",
    "Logging&Monitoring": "logging_monitoring",
    "User&Accounts": "user_accounts",
    "APIs": "apis",
    "Supplier&3rdParty": "supplier_third_party",
    "Web&Mobile": "web_mobile",
    "VOIP": "voip",
    "CPE": "cpe",
}

# ---------------------------------------------------------------------------
# Scope question definitions (from base_questionnaire in catalog + supplements)
# ---------------------------------------------------------------------------

# Structured scope questions mapped to SCOPE-XX IDs with skip logic
_SCOPE_QUESTIONS: list[dict] = [
    {
        "id": "SCOPE-01",
        "label": "Is this a new service or an enhancement to an existing one?",
        "instruction": "If there is a Secure by Design Jira Task already evaluated, task number must be linked.",
        "guideline": None,
        "help_text": "If your service/product is not developed by this model, select the phase which comes closest to your situation.",
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["New service for immediate commercial sale", "Enhancement to an existing service"],
    },
    {
        "id": "SCOPE-02",
        "label": "Does the solution provide or access an API using HTTP-based interfaces (SOAP, REST, JSON)?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-03",
        "label": "What will be the interfaces of the system?",
        "instruction": "Hygiene and API design pages must be filled.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["External (APN; customer facing; private access)", "Internal"],
    },
    {
        "id": "SCOPE-04",
        "label": "Will there be a customer-facing interface rather than an internal interface?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-05",
        "label": "Does the project process, store and/or transfer personal data, C3 or C4 data?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-06",
        "label": "Is any third-party company involved in development, maintenance, integration, testing, or support?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-07",
        "label": "If a vendor is included, is the vendor subject to the Corporate Supplier Cyber Security Risk Questionnaire (SCS)?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": False,
        "depends_on_question_id": "SCOPE-06",
        "expected_when": "YES",
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-08",
        "label": "Does the project include the development or usage of mobile applications?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-09",
        "label": "Does the project deal with Voice over IP (VOIP) or unified communications?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-10",
        "label": "On which environment will the set-up be done?",
        "instruction": "Please answer the additional requirements in [Red Flag] Sheets.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["3rd Party Storage", "Corporate Environments"],
    },
    {
        "id": "SCOPE-11",
        "label": "Does the project deal with Customer Premise Equipment (CPE)?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-12",
        "label": "Does the project include an appliance or black-box environment?",
        "instruction": "No additional action required.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
    {
        "id": "SCOPE-13",
        "label": "Is it possible to track system admin/user activity logs?",
        "instruction": "Explain the reason why this system cannot log issues.",
        "guideline": None,
        "help_text": None,
        "answer_type": "single_choice",
        "is_required": True,
        "depends_on_question_id": None,
        "expected_when": None,
        "options": ["YES", "NO"],
    },
]

# ---------------------------------------------------------------------------
# Sub-task mapping: section → relevant subtask keys
# ---------------------------------------------------------------------------
# Maps each section key to the list of subtask keys that are most relevant.
# This drives seed_mappings.json.  All 25 subtask keys must appear at least once.

_SECTION_SUBTASK_MAP: dict[str, list[str]] = {
    "hygiene_essentials": [
        "network_segment_placement",
        "vulnerability_scan_tenable",
        "penetration_testing",
        "sast",
        "dast",
        "scs",
        "software_composition_analysis_sca",
        "risk_assesment",
        "secure_by_design_assesment",
        "file_integrity_monitoring_integration",
    ],
    "data_protection": [
        "risk_assesment",
        "secure_by_design_assesment",
    ],
    "logging_monitoring": [
        "application_logging",
        "database_logging",
        "operating_system_logging_unix",
        "operating_system_logging_windows",
        "arcsight_new_update_alert_request",
        "archer_inventory_update",
    ],
    "user_accounts": [
        "cyberark_epm",
        "privileged_user_access_management_integrations_cyberark",
    ],
    "apis": [
        "proxy_definition",
        "access_point_integration",
        "web_certificate_request",
    ],
    "supplier_third_party": [
        "onetrust_supplier_security_assesment",
        "scs",
    ],
    "web_mobile": [
        "waf_integration",
        "web_certificate_request",
        "dast",
        "sast",
    ],
    "voip": [
        "access_point_integration",
        "proxy_definition",
        "network_segment_placement",
    ],
    "cpe": [
        "container_native_firewall",
        "container_security_scan",
        "vulnerability_scan_tenable",
    ],
}

# ---------------------------------------------------------------------------
# Icon hints per subtask key
# ---------------------------------------------------------------------------

_ICON_HINTS: dict[str, str] = {
    "access_point_integration": "wifi",
    "application_logging": "file-text",
    "archer_inventory_update": "database",
    "arcsight_new_update_alert_request": "bell",
    "container_native_firewall": "shield",
    "container_security_scan": "search",
    "cyberark_epm": "lock",
    "dast": "bug",
    "database_logging": "database",
    "file_integrity_monitoring_integration": "file-check",
    "network_segment_placement": "network",
    "onetrust_supplier_security_assesment": "clipboard-check",
    "operating_system_logging_unix": "terminal",
    "operating_system_logging_windows": "monitor",
    "penetration_testing": "crosshair",
    "privileged_user_access_management_integrations_cyberark": "key",
    "proxy_definition": "layers",
    "risk_assesment": "alert-triangle",
    "sast": "code",
    "scs": "shield-check",
    "secure_by_design_assesment": "settings",
    "software_composition_analysis_sca": "package",
    "vulnerability_scan_tenable": "scan",
    "waf_integration": "filter",
    "web_certificate_request": "certificate",
}

_DESCRIPTIONS: dict[str, str] = {
    "access_point_integration": "Integrate the system with the network access point infrastructure.",
    "application_logging": "Implement centralised application-level logging to the SIEM platform.",
    "archer_inventory_update": "Register and update the asset inventory record in Archer GRC.",
    "arcsight_new_update_alert_request": "Submit a new or updated alert rule request to the ArcSight SIEM team.",
    "container_native_firewall": "Configure and enforce container-native firewall policies.",
    "container_security_scan": "Run automated container image scanning for vulnerabilities and misconfigurations.",
    "cyberark_epm": "Enrol endpoints into CyberArk Endpoint Privilege Manager (EPM).",
    "dast": "Execute dynamic application security testing (DAST) against the running application.",
    "database_logging": "Enable database-level audit logging forwarded to the central SIEM.",
    "file_integrity_monitoring_integration": "Integrate file integrity monitoring (FIM) for critical system paths.",
    "network_segment_placement": "Define and validate the correct network segment and zoning placement.",
    "onetrust_supplier_security_assesment": "Complete the OneTrust supplier security assessment for third-party vendors.",
    "operating_system_logging_unix": "Configure Unix OS-level audit logging forwarded to the central SIEM.",
    "operating_system_logging_windows": "Configure Windows OS-level audit logging forwarded to the central SIEM.",
    "penetration_testing": "Schedule and execute penetration testing before go-live.",
    "privileged_user_access_management_integrations_cyberark": "Integrate privileged accounts with CyberArk PAM.",
    "proxy_definition": "Define and configure the outbound proxy for the service.",
    "risk_assesment": "Complete a formal risk assessment covering the system threat model.",
    "sast": "Run static application security testing (SAST) on the source code.",
    "scs": "Complete the Supplier Cyber Security questionnaire for vendor involvement.",
    "secure_by_design_assesment": "Conduct the Secure by Design assessment with the security architect.",
    "software_composition_analysis_sca": "Analyse third-party software components for known vulnerabilities (SCA).",
    "vulnerability_scan_tenable": "Run an authenticated vulnerability scan using Tenable.",
    "waf_integration": "Integrate the web application firewall (WAF) in front of the service.",
    "web_certificate_request": "Request and configure a valid TLS certificate for the service.",
}


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _load_catalog() -> dict:
    return json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))


def _clean_text(value: str | None) -> str:
    return (value or "").strip()


def _is_valid_requirement(item: dict) -> bool:
    """Return True for requirement rows that have enough content to be questions."""
    if item.get("type") != "requirement":
        return False
    req_text = _clean_text(item.get("requirement_text"))
    return bool(req_text)


def _deduplicate_requirements(items: list[dict]) -> list[dict]:
    """Remove requirement items with identical requirement_text (case-insensitive).

    Per D-04 / QSCHEMA-02: merge items with identical requirement_text across
    subgroups.  First occurrence wins.
    """
    seen: set[str] = set()
    deduped: list[dict] = []
    for item in items:
        key = _clean_text(item.get("requirement_text", "")).casefold()
        if key and key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


# ---------------------------------------------------------------------------
# 1. seed_subtasks.json
# ---------------------------------------------------------------------------


def build_subtasks() -> list[dict]:
    """Return the 25 SbD sub-task component records."""
    result = []
    for order, entry in enumerate(_RECOMMENDATION_CATALOG, start=1):
        key = entry["key"]
        result.append(
            {
                "key": key,
                "label": entry["label"],
                "category": entry["category"],
                "description": _DESCRIPTIONS.get(key, ""),
                "icon_hint": _ICON_HINTS.get(key, "shield"),
                "display_order": order,
                "is_active": True,
            }
        )
    return result


# ---------------------------------------------------------------------------
# 2. seed_sections.json
# ---------------------------------------------------------------------------


def _build_subgroups_for_section(section_key: str, catalog: dict) -> list[dict]:
    """Extract subgroup (group headers) from the catalog section items."""
    if section_key == "scope":
        return [
            {"subgroup_key": "scope_main", "label": "Project Scope", "display_order": 0}
        ]

    sheet_name = next(
        (s for s, k in _SHEET_TO_SECTION.items() if k == section_key), None
    )
    if not sheet_name:
        return []

    section_data = next(
        (s for s in catalog.get("sections", []) if s["sheet"] == sheet_name), None
    )
    if not section_data:
        return []

    subgroups = []
    for order, item in enumerate(section_data.get("items", [])):
        if item.get("type") == "group":
            raw_label = _clean_text(item.get("title_or_requirement", ""))
            if not raw_label:
                continue
            slug = item["id"].replace(".", "_").replace(" ", "_").lower()
            subgroups.append(
                {
                    "subgroup_key": f"{section_key}_{slug}",
                    "label": raw_label,
                    "display_order": len(subgroups),
                }
            )
    return subgroups


def build_sections(catalog: dict) -> list[dict]:
    """Return section records with subgroups."""
    result = []
    for section_key, label, _prefix, display_order, dep_q, exp_when, _is_specialist in _SECTION_META:
        subgroups = _build_subgroups_for_section(section_key, catalog)
        copy_data = _SECTION_COPY.get(
            next(
                (s for s, k in _SHEET_TO_SECTION.items() if k == section_key),
                "",
            ),
            {},
        )
        result.append(
            {
                "section_key": section_key,
                "label": label,
                "description": copy_data.get("intro", ""),
                "display_order": display_order,
                "depends_on_question_id": dep_q,
                "expected_when": exp_when,
                "is_active": True,
                "subgroups": subgroups,
            }
        )
    return result


# ---------------------------------------------------------------------------
# 3. seed_questions.json
# ---------------------------------------------------------------------------


def _subgroup_key_for_group_id(section_key: str, group_id: str) -> str:
    slug = group_id.replace(".", "_").replace(" ", "_").lower()
    return f"{section_key}_{slug}"


_SPECIALIST_SECTIONS: frozenset[str] = frozenset({"voip", "cpe"})


def _extract_section_questions(
    section_key: str, prefix: str, catalog: dict
) -> list[dict]:
    """Extract requirement questions from a catalog section."""
    sheet_name = next(
        (s for s, k in _SHEET_TO_SECTION.items() if k == section_key), None
    )
    if not sheet_name:
        return []

    section_data = next(
        (s for s in catalog.get("sections", []) if s["sheet"] == sheet_name), None
    )
    if not section_data:
        return []

    all_items = section_data.get("items", [])
    requirement_items = [i for i in all_items if _is_valid_requirement(i)]
    requirement_items = _deduplicate_requirements(requirement_items)

    # Track which subgroup each item belongs to (group immediately above it)
    current_subgroup_key = f"{section_key}_ungrouped"
    subgroup_map: dict[str, str] = {}
    for item in all_items:
        if item.get("type") == "group":
            current_subgroup_key = _subgroup_key_for_group_id(
                section_key, item["id"]
            )
        subgroup_map[item["id"]] = current_subgroup_key

    # Depth level: VOIP and CPE are specialist-domain questions (D-19)
    depth = "specialist" if section_key in _SPECIALIST_SECTIONS else "standard"

    questions = []
    for counter, item in enumerate(requirement_items, start=1):
        q_id = f"{prefix}-{counter:02d}"
        req_text = _clean_text(item.get("requirement_text", ""))
        questionnaire_prompt = _clean_text(item.get("questionnaire_prompt", ""))
        security_comment = _clean_text(item.get("security_comment", ""))
        policy_reference = _clean_text(item.get("policy_reference", ""))
        item_subgroup = subgroup_map.get(item["id"], f"{section_key}_ungrouped")

        # help_text: Turkish questionnaire prompt (if different from English label),
        #            else security_comment from the workbook
        help_text = None
        if questionnaire_prompt and questionnaire_prompt != req_text:
            help_text = questionnaire_prompt
        elif security_comment:
            help_text = security_comment

        questions.append(
            {
                "id": q_id,
                "subgroup_key": item_subgroup,
                "question_type": "requirement",
                "depth_level": depth,
                "answer_type": "compliance",
                "label": req_text,
                "instruction": None,
                "guideline": policy_reference or None,
                "help_text": help_text,
                "is_required": True,
                "depends_on_question_id": None,
                "expected_when": None,
                "display_order": counter,
            }
        )
    return questions


def build_questions(catalog: dict) -> list[dict]:
    """Return all question records: scope questions + all NFR section questions."""
    questions: list[dict] = []

    # --- Scope questions ---
    for counter, sq in enumerate(_SCOPE_QUESTIONS, start=1):
        questions.append(
            {
                "id": sq["id"],
                "subgroup_key": "scope_main",
                "question_type": "scope",
                "depth_level": "scope",
                "answer_type": "single_choice",
                "label": sq["label"],
                "instruction": sq.get("instruction"),
                "guideline": sq.get("guideline"),
                "help_text": sq.get("help_text"),
                "is_required": sq["is_required"],
                "depends_on_question_id": sq["depends_on_question_id"],
                "expected_when": sq["expected_when"],
                "display_order": counter,
            }
        )

    # --- NFR section questions ---
    for section_key, _label, prefix, _display_order, _dep_q, _exp_when, _is_specialist in _SECTION_META:
        if section_key == "scope":
            continue
        section_qs = _extract_section_questions(section_key, prefix, catalog)
        questions.extend(section_qs)

    return questions


# ---------------------------------------------------------------------------
# 4. seed_options.json
# ---------------------------------------------------------------------------


def build_options() -> list[dict]:
    """Return option records for scope questions + __COMPLIANCE__ template."""
    options: list[dict] = []

    # Per-scope-question options
    for sq in _SCOPE_QUESTIONS:
        for order, opt_value in enumerate(sq.get("options", []), start=1):
            options.append(
                {
                    "question_id": sq["id"],
                    "value": opt_value,
                    "label": opt_value,
                    "description": None,
                    "display_order": order,
                }
            )

    # Compliance template marker (seed_data() expands this to all compliance questions)
    compliance_options = [
        ("Yes", "Requirement is fully met"),
        ("Partial", "Requirement is partially met — compensating controls or exceptions apply"),
        ("No", "Requirement is not met"),
        ("Not applicable", "Requirement does not apply to this project"),
    ]
    for order, (value, description) in enumerate(compliance_options, start=1):
        options.append(
            {
                "question_id": "__COMPLIANCE__",
                "value": value,
                "label": value,
                "description": description,
                "display_order": order,
            }
        )

    return options


# ---------------------------------------------------------------------------
# 5. seed_mappings.json
# ---------------------------------------------------------------------------


def build_mappings(questions: list[dict]) -> list[dict]:
    """Return question-to-subtask mapping records.

    Maps each section's questions to relevant subtask keys so that when the
    wizard captures answers the LLM resolution step knows which sub-tasks to
    consider.  All 25 subtask keys must appear at least once.

    Strategy: every question in a section is mapped to every subtask that the
    section is relevant for.  This gives broad coverage (all questions inform
    the resolution) instead of sparse 1:1 assignment.
    """
    # Build index: section_key -> list of question IDs in that section
    section_questions: dict[str, list[str]] = {}
    for q in questions:
        if q["question_type"] != "requirement":
            continue
        subgroup = q["subgroup_key"]
        for sk in _SECTION_SUBTASK_MAP:
            if subgroup.startswith(sk + "_") or subgroup == sk:
                section_questions.setdefault(sk, []).append(q["id"])
                break

    mappings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    covered_subtasks: set[str] = set()

    for section_key, subtask_keys in _SECTION_SUBTASK_MAP.items():
        q_ids = section_questions.get(section_key, [])
        if not q_ids:
            continue

        # Map every question in section to every relevant subtask
        for q_id in q_ids:
            for subtask_key in subtask_keys:
                pair = (q_id, subtask_key)
                if pair not in seen:
                    seen.add(pair)
                    mappings.append({"question_id": q_id, "subtask_key": subtask_key})
                    covered_subtasks.add(subtask_key)

    # Verify all 25 subtask keys are covered (defensive check)
    all_keys = {entry["key"] for entry in _RECOMMENDATION_CATALOG}
    missing = all_keys - covered_subtasks
    if missing:
        _log.warning("Some subtask keys not covered in mappings: %s", missing)

    return mappings


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: object) -> None:
    content = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(content, encoding="utf-8")
    _log.info("Wrote %s (%d items)", path.name, len(data) if isinstance(data, list) else 1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run(data_dir: Path | None = None) -> None:
    """Execute the extraction and write all 5 seed JSON files."""
    out_dir = data_dir or _DATA_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    catalog = _load_catalog()

    subtasks = build_subtasks()
    _write_json(out_dir / "seed_subtasks.json", subtasks)

    sections = build_sections(catalog)
    _write_json(out_dir / "seed_sections.json", sections)

    questions = build_questions(catalog)
    _write_json(out_dir / "seed_questions.json", questions)

    options = build_options()
    _write_json(out_dir / "seed_options.json", options)

    mappings = build_mappings(questions)
    _write_json(out_dir / "seed_mappings.json", mappings)

    _log.info(
        "Extraction complete: %d subtasks, %d sections, %d questions, %d options, %d mappings",
        len(subtasks),
        len(sections),
        len(questions),
        len(options),
        len(mappings),
    )


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    run()
