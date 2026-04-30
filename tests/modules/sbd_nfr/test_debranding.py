"""Debranding verification tests.

Confirms zero Vodafone/VFTR/VF references in the sbd_nfr module output surfaces
(templates, services, contracts, reporting).

Exclusions:
  - document_requirement_catalog.json: raw third-party source catalog preserved verbatim.

The debranding requirement applies to:
  - all rendered output (HTML templates, report content, API responses)
  - all user-facing labels, help text, and question labels
  - all scripts, services, and contracts
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# D-15 through D-18: Zero Vodafone/VFTR/VF brand references in output surfaces
# ---------------------------------------------------------------------------


def test_zero_vodafone_references_in_output_surfaces():
    """Grep across sbd_nfr module returns zero VF/VFTR/Vodafone matches
    in user-facing output surfaces (D-15 through D-18).

    Excludes:
      - document_requirement_catalog.json (raw source catalog)
    """
    result = subprocess.run(
        [
            "grep", "-rn",
            r"VF\|VFTR\|Vodafone\|vodafone",
            "src/aila/modules/sbd_nfr/",
            "--include=*.py",
            "--include=*.json",
            "--include=*.html",
            "--include=*.css",
            "--exclude-dir=__pycache__",
            "--exclude=document_requirement_catalog.json",
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[3]),
    )
    assert result.stdout.strip() == "", (
        f"Found Vodafone/VFTR/VF references that should have been debranded:\n{result.stdout}"
    )


def test_extract_nfr_script_exists():
    """extract_nfr.py must exist (renamed from extract_vftr.py per D-15).

    The script was debranded in Plan 01.
    """
    scripts_dir = Path(__file__).resolve().parents[3] / "src" / "aila" / "modules" / "sbd_nfr" / "scripts"
    assert (scripts_dir / "extract_nfr.py").exists(), (
        "extract_nfr.py must exist in scripts/ (renamed from extract_vftr.py)"
    )


def test_extract_vftr_script_does_not_exist():
    """extract_vftr.py must NOT exist — it should have been renamed to extract_nfr.py."""
    scripts_dir = Path(__file__).resolve().parents[3] / "src" / "aila" / "modules" / "sbd_nfr" / "scripts"
    assert not (scripts_dir / "extract_vftr.py").exists(), (
        "extract_vftr.py still exists — should have been renamed to extract_nfr.py in Plan 01"
    )


def test_workbook_source_file_renamed():
    """nfr_security_workbook_source.xlsx must exist (renamed from vftr_*.xlsx per D-15)."""
    data_dir = Path(__file__).resolve().parents[3] / "src" / "aila" / "modules" / "sbd_nfr" / "data"
    assert (data_dir / "nfr_security_workbook_source.xlsx").exists(), (
        "nfr_security_workbook_source.xlsx must exist in data/ directory"
    )


def test_no_vftr_xlsx_in_data_dir():
    """No files named vftr_*.xlsx should remain in the data directory."""
    data_dir = Path(__file__).resolve().parents[3] / "src" / "aila" / "modules" / "sbd_nfr" / "data"
    vftr_files = list(data_dir.glob("vftr_*.xlsx"))
    assert len(vftr_files) == 0, (
        f"Found undebranded VFTR xlsx files: {[str(f) for f in vftr_files]}"
    )
