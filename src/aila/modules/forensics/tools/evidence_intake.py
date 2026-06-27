"""Evidence directory scanning and classification tool."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "evidence_intake"
CAPABILITY = "Scan evidence directory on analyzer machine, classify files by type, and compute SHA-256 hashes."

__all__ = ["EvidenceIntakeTool"]


class EvidenceIntakeTool(Tool):
    """Scan an evidence directory over SSH and classify each file."""

    name = "evidence_intake"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "Must be 'scan'."},
        "evidence_directory": {"type": "string", "description": "Absolute path on analyzer machine."},
        "integration": {"type": "object", "description": "SSH integration fields."},
        "analyzer_os": {"type": "string", "description": "Target OS: linux or windows.", "nullable": True},
    }
    output_type = "object"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "scan",
        evidence_directory: str = "",
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> dict:
        """Scan the evidence directory and return classified file listing.

        Args:
            action: Must be 'scan'.
            evidence_directory: Path on analyzer machine.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Dict with 'files' list of classified evidence items.
        """
        if action != "scan":
            raise ValueError(f"EvidenceIntakeTool only supports 'scan', got '{action}'.")
        if not evidence_directory:
            raise ValueError("evidence_directory is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.services.evidence_classifier import classify_evidence_directory
        return await classify_evidence_directory(self.settings, integration, evidence_directory, analyzer_os=analyzer_os)


def create_tool(settings: Settings) -> EvidenceIntakeTool:
    """Construct an EvidenceIntakeTool with the given settings."""
    return EvidenceIntakeTool(settings)
