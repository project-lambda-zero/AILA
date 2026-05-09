"""dd disk imaging and raw data extraction runner — over SSH.

Supports raw disk/partition copying, evidence acquisition, selective block
extraction, disk-to-image conversion, and raw data slicing for carving.
On Windows, falls back to PowerShell-based equivalents.
"""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "dd_runner"
CAPABILITY = (
    "Run dd for raw disk imaging, partition extraction, block-level data "
    "slicing, evidence acquisition, and byte-range carving via SSH."
)

_ACTIONS = (
    "image_disk, image_partition, extract_bytes, extract_mbr, "
    "extract_vbr, slice_file, wipe_verify, disk_info"
)

__all__ = ["DdRunnerTool"]


def _build_dd_command(
    action: str,
    source: str,
    destination: str | None,
    block_size: str,
    skip_blocks: int | None,
    count_blocks: int | None,
    analyzer_os: str,
) -> str:
    """Build the SSH command for the requested dd action."""
    dest = destination or "/dev/stdout"
    bs = block_size

    _DD_COMMANDS: dict[str, str] = {
        "image_disk": (
            f"dd if={source} of={dest} bs={bs} status=progress conv=noerror,sync"
            if analyzer_os != "windows"
            else f'powershell -Command "& {{ $src=[IO.File]::OpenRead(\'{source}\'); '
                 f'$dst=[IO.File]::Create(\'{dest}\'); $src.CopyTo($dst); '
                 f'$src.Close(); $dst.Close() }}"'
        ),
        "image_partition": (
            f"dd if={source} of={dest} bs={bs} status=progress conv=noerror,sync"
            if analyzer_os != "windows"
            else f'powershell -Command "& {{ $src=[IO.File]::OpenRead(\'{source}\'); '
                 f'$dst=[IO.File]::Create(\'{dest}\'); $src.CopyTo($dst); '
                 f'$src.Close(); $dst.Close() }}"'
        ),
        "extract_bytes": (
            f"dd if={source} of={dest} bs={bs}"
            + (f" skip={skip_blocks}" if skip_blocks else "")
            + (f" count={count_blocks}" if count_blocks else "")
            + " status=progress"
            if analyzer_os != "windows"
            else _ps_extract_bytes(source, dest, bs, skip_blocks, count_blocks)
        ),
        "extract_mbr": (
            f"dd if={source} of={dest} bs=512 count=1 status=progress"
            if analyzer_os != "windows"
            else _ps_extract_bytes(source, dest, "512", 0, 1)
        ),
        "extract_vbr": (
            f"dd if={source} of={dest} bs=512 skip=1 count=1 status=progress"
            if analyzer_os != "windows"
            else _ps_extract_bytes(source, dest, "512", 1, 1)
        ),
        "slice_file": (
            f"dd if={source} of={dest} bs={bs}"
            + (f" skip={skip_blocks}" if skip_blocks else "")
            + (f" count={count_blocks}" if count_blocks else "")
            + " status=progress"
            if analyzer_os != "windows"
            else _ps_extract_bytes(source, dest, bs, skip_blocks, count_blocks)
        ),
        "wipe_verify": (
            f"dd if={source} bs={bs} count=100 status=none | xxd | head -20"
            if analyzer_os != "windows"
            else f'powershell -Command "& {{ $f=[IO.File]::OpenRead(\'{source}\'); '
                 f'$buf=New-Object byte[] 512; $f.Read($buf,0,512); $f.Close(); '
                 f'($buf | ForEach-Object {{ $_.ToString(\"X2\") }}) -join \' \' }}"'
        ),
        "disk_info": (
            f"fdisk -l {source} 2>/dev/null || parted {source} print 2>/dev/null"
            if analyzer_os != "windows"
            else 'powershell -Command "Get-Disk | Format-List; Get-Partition | Format-List"'
        ),
    }

    cmd = _DD_COMMANDS.get(action)
    if cmd is None:
        raise ValueError(f"Unknown dd action '{action}'. Supported: {_ACTIONS}.")
    return cmd


def _ps_extract_bytes(
    source: str, dest: str, bs: str, skip: int | None, count: int | None,
) -> str:
    """PowerShell equivalent of dd byte extraction."""
    bs_int = int(bs) if bs.isdigit() else 512
    offset = (skip or 0) * bs_int
    length = (count or 1) * bs_int
    return (
        f'powershell -Command "& {{ '
        f'$f=[IO.File]::OpenRead(\'{source}\'); '
        f'$f.Seek({offset},[IO.SeekOrigin]::Begin) | Out-Null; '
        f'$buf=New-Object byte[] {length}; '
        f'$f.Read($buf,0,{length}) | Out-Null; $f.Close(); '
        f'[IO.File]::WriteAllBytes(\'{dest}\',$buf) }}"'
    )


class DdRunnerTool(Tool):
    """Execute dd and disk imaging commands on the analyzer machine."""

    name = "dd_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": f"One of: {_ACTIONS}."},
        "source": {"type": "string", "description": "Source path (device, image, or file)."},
        "destination": {"type": "string", "description": "Destination path for output.", "nullable": True},
        "block_size": {"type": "string", "description": "Block size (default 4096).", "nullable": True},
        "skip_blocks": {"type": "integer", "description": "Number of blocks to skip from input.", "nullable": True},
        "count_blocks": {"type": "integer", "description": "Number of blocks to copy.", "nullable": True},
        "extra_args": {"type": "string", "description": "Additional arguments.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "image_disk",
        source: str = "",
        destination: str | None = None,
        block_size: str | None = None,
        skip_blocks: int | None = None,
        count_blocks: int | None = None,
        extra_args: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not source:
            raise ValueError("source is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        cmd = _build_dd_command(
            action, source, destination,
            block_size or "4096", skip_blocks, count_blocks, analyzer_os,
        )
        if extra_args:
            cmd += f" {extra_args}"

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=3600.0)


def create_tool(settings: Settings) -> DdRunnerTool:
    """Construct a DdRunnerTool with the given settings."""
    return DdRunnerTool(settings)
