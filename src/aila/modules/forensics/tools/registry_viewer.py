"""Windows Registry viewer -- navigates and queries registry hives via SSH.

Uses Dissect's registry parser (``dissect.regf``) and Python's built-in
``winreg`` (on Windows analyzers) to browse hives, list keys/values,
search for patterns, and extract common forensic artifacts.
"""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools import Tool

TOOL_ALIAS = "registry_viewer"
CAPABILITY = (
    "Browse Windows registry hives -- list keys, read values, search patterns, "
    "and extract forensic artifacts (MRU, services, autoruns, USB, shellbags) via SSH."
)

_ACTIONS = (
    "list_keys, read_value, search, autoruns, services, usb_history, "
    "user_accounts, installed_software, recent_docs, shellbags, "
    "network_interfaces, mru_lists, amcache, bam, shimcache"
)

__all__ = ["RegistryViewerTool"]

_FORENSIC_QUERIES: dict[str, str] = {
    "autoruns": "regf",
    "services": "services",
    "usb_history": "usb",
    "user_accounts": "sam",
    "installed_software": "regf",
    "recent_docs": "regf",
    "shellbags": "shellbags",
    "network_interfaces": "regf",
    "mru_lists": "regf",
    "amcache": "amcache",
    "bam": "bam",
    "shimcache": "shimcache",
}


_HIVE_ROOTS: dict[str, str] = {
    "SAM": "HKLM\\SAM",
    "SYSTEM": "HKLM\\SYSTEM",
    "SOFTWARE": "HKLM\\SOFTWARE",
    "SECURITY": "HKLM\\SECURITY",
    "NTUSER": "HKCU",
    "DEFAULT": "HKU\\.DEFAULT",
}


def _build_registry_command(
    action: str,
    py: str,
    evidence: str,
    registry_key: str | None,
    search_pattern: str | None,
    hive: str | None,
) -> str:
    """Build the SSH command for the requested registry action.

    When ``hive`` is provided (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER),
    it scopes navigation commands to the corresponding root key.
    """
    if action in _FORENSIC_QUERIES:
        return _forensic_query(py, evidence, action)

    effective_key = registry_key
    if hive and not registry_key:
        effective_key = _HIVE_ROOTS.get(hive.upper())

    _nav_builders = {
        "list_keys": lambda: _list_keys(py, evidence, effective_key),
        "read_value": lambda: _read_value(py, evidence, effective_key or _require("registry_key")),
        "search": lambda: _search(py, evidence, search_pattern or _require("search_pattern")),
    }
    builder = _nav_builders.get(action)
    if builder is None:
        raise ValueError(f"Unknown registry action '{action}'. Supported: {_ACTIONS}.")
    return builder()


def _require(param: str) -> str:
    raise ValueError(f"{param} is required for this action.")


def _forensic_query(py: str, evidence: str, action: str) -> str:
    query_fn = _FORENSIC_QUERIES[action]
    if query_fn in ("services", "sam", "usb", "shellbags", "amcache", "bam", "shimcache"):
        return f"{py} -m dissect.target.tools.query -f {query_fn} {evidence}"
    queries: dict[str, str] = {
        "autoruns": (
            f'{py} -c "'
            "from dissect.target import Target;"
            f"t = Target.open('{evidence}');"
            "regs = ["
            "  'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"
            "  'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce',"
            "  'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"
            "  'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon',"
            "  'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services',"
            "];"
            "[print(f'{r}: {list(t.registry.key(r).values())}') for r in regs if t.registry.key(r)]"
            '"'
        ),
        "installed_software": (
            f"{py} -m dissect.target.tools.query -f apps.installed {evidence}"
        ),
        "recent_docs": (
            f'{py} -c "'
            "from dissect.target import Target;"
            f"t = Target.open('{evidence}');"
            "mru = t.registry.key('HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\RecentDocs');"
            "[print(f'{v.name}: {v.value}') for v in mru.values()]"
            '"'
        ),
        "network_interfaces": (
            f'{py} -c "'
            "from dissect.target import Target;"
            f"t = Target.open('{evidence}');"
            "key = t.registry.key('HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\\\Interfaces');"
            "[print(f'{sk.name}: DhcpIPAddress={[v for v in sk.values() if v.name==\"DhcpIPAddress\"]}') for sk in key.subkeys()]"
            '"'
        ),
        "mru_lists": (
            f'{py} -c "'
            "from dissect.target import Target;"
            f"t = Target.open('{evidence}');"
            "paths = ["
            "  'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\RunMRU',"
            "  'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\TypedPaths',"
            "  'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ComDlg32\\\\OpenSavePidlMRU',"
            "];"
            "[print(f'{p}: {[(v.name, v.value) for v in t.registry.key(p).values()]}') for p in paths if t.registry.key(p)]"
            '"'
        ),
    }
    return queries.get(action, f"{py} -m dissect.target.tools.query -f regf {evidence}")


def _list_keys(py: str, evidence: str, key: str | None) -> str:
    target_key = key or "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
    return (
        f'{py} -c "'
        "from dissect.target import Target;"
        f"t = Target.open('{evidence}');"
        f"k = t.registry.key('{target_key}');"
        "print(f'Key: {k.path}');"
        "print(f'Subkeys ({len(list(k.subkeys()))}):');"
        "[print(f'  {sk.name}') for sk in k.subkeys()];"
        "print(f'Values ({len(list(k.values()))}):');"
        "[print(f'  {v.name} = {v.value}') for v in k.values()]"
        '"'
    )


def _read_value(py: str, evidence: str, key: str) -> str:
    return (
        f'{py} -c "'
        "from dissect.target import Target;"
        f"t = Target.open('{evidence}');"
        f"k = t.registry.key('{key}');"
        "[print(f'{v.name} ({v.type}): {v.value}') for v in k.values()]"
        '"'
    )


def _search(py: str, evidence: str, pattern: str) -> str:
    return (
        f'{py} -c "'
        "import re;"
        "from dissect.target import Target;"
        f"t = Target.open('{evidence}');"
        f"pat = re.compile('{pattern}', re.IGNORECASE);"
        "found = 0;"
        "for key in t.registry.keys('HKLM\\\\SOFTWARE'):"
        "  for v in key.values():"
        "    s = str(v.value);"
        "    if pat.search(v.name) or pat.search(s):"
        "      print(f'{key.path}\\\\{v.name} = {s[:200]}');"
        "      found += 1;"
        "    if found >= 100: break;"
        "  if found >= 100: break;"
        "print(f'\\nMatches: {found}')"
        '"'
    )


class RegistryViewerTool(Tool):
    """Navigate and query Windows registry hives on the analyzer machine."""

    name = "registry_viewer"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": f"One of: {_ACTIONS}."},
        "evidence_path": {"type": "string", "description": "Path to disk image or registry hive file."},
        "registry_key": {"type": "string", "description": "Registry key path for list_keys/read_value.", "nullable": True},
        "search_pattern": {"type": "string", "description": "Regex pattern for search action.", "nullable": True},
        "hive": {"type": "string", "description": "Specific hive: SAM, SYSTEM, SOFTWARE, NTUSER, SECURITY.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "list_keys",
        evidence_path: str = "",
        registry_key: str | None = None,
        search_pattern: str | None = None,
        hive: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not evidence_path:
            raise ValueError("evidence_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service, python_cmd

        py = python_cmd(analyzer_os)
        cmd = _build_registry_command(action, py, evidence_path, registry_key, search_pattern, hive)

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=600.0)


def create_tool(settings: Settings) -> RegistryViewerTool:
    """Construct a RegistryViewerTool with the given settings."""
    return RegistryViewerTool(settings)
