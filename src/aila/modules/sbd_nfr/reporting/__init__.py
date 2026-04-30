"""Reporting package for the SbD NFR module.

Artifact generation services for the SbD NFR assessment module:

  Plan 02: report_service   — HTML/PDF pre-meeting report generation
  Plan 02: pdf_service      — WeasyPrint PDF renderer (async-safe)
  Plan 03: excel_service    — openpyxl NFR workbook generation
  Plan 03: jira_service     — Jira work-item draft assembly (no API calls)

Public API:
    generate_report_html(session_id) -> str
    generate_report_pdf(session_id) -> bytes
    html_to_pdf(html_string) -> bytes
    generate_workbook(session_id) -> bytes
    generate_jira_draft(session_id) -> JiraWorkItemDraft
"""

from __future__ import annotations

from .excel_service import generate_workbook
from .jira_service import generate_jira_draft
from .pdf_service import html_to_pdf
from .report_service import generate_report_html, generate_report_pdf

__all__ = [
    "generate_report_html",
    "generate_report_pdf",
    "html_to_pdf",
    "generate_workbook",
    "generate_jira_draft",
]
