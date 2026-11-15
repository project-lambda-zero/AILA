"""Analyzer actions for the forensics free-flow investigator.

Script and shell execution on the analyzer host, the analyzer.run_command
tool_run contract, and the project context loaders that feed each
investigator turn. The investigator owns the loop and step persistence;
this module owns what touches the analyzer and the forensics project tables.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select

from aila.config import Settings
from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.forensics.db_models import (
    AnalystDirectiveRecord,
    ArtifactRecord,
    ForensicsProjectRecord,
    LeadRecord,
    ProjectEvidenceRecord,
)
from aila.modules.forensics.tools import _ssh_helper, artifact_query, script_tool
from aila.modules.forensics.tools.script_guard import script_rejection
from aila.platform.contracts.reasoning import ReasoningOperatorSteering
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

__all__ = [
    "STDOUT_KEEP_BYTES",
    "ToolRunContractError",
    "execute_artifact_query",
    "execute_command",
    "execute_script",
    "load_operator_steering",
    "load_project_context",
    "parse_tool_run_command",
    "render_previous",
    "sanitize_for_postgres_text",
    "snapshot_artifacts",
]

_log = logging.getLogger(__name__)

_TOOL_RUN_TOOL_NAME = "analyzer.run_command"


class ToolRunContractError(ValueError):
    """A tool_run command does not satisfy the analyzer.run_command contract."""


def parse_tool_run_command(command: str) -> str:
    """Return the shell command carried by a tool_run JSON envelope.

    The envelope MUST be {"tool": "analyzer.run_command", "args": {"command": "<shell>"}}.
    Any other shape raises ToolRunContractError.
    """
    try:
        payload = json.loads(command)
    except json.JSONDecodeError as exc:
        raise ToolRunContractError(
            f"tool_run command must be a JSON object naming {_TOOL_RUN_TOOL_NAME!r}: {exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise ToolRunContractError(
            f"tool_run command must be a JSON object naming {_TOOL_RUN_TOOL_NAME!r}"
        )
    tool = payload.get("tool")
    if tool != _TOOL_RUN_TOOL_NAME:
        raise ToolRunContractError(
            f"unsupported tool {tool!r} in tool_run; the only supported tool is {_TOOL_RUN_TOOL_NAME!r}"
        )
    args = payload.get("args")
    if not isinstance(args, dict):
        raise ToolRunContractError(f"{_TOOL_RUN_TOOL_NAME} requires args to be a JSON object")
    shell = args.get("command")
    if not isinstance(shell, str) or not shell.strip():
        raise ToolRunContractError(
            f"{_TOOL_RUN_TOOL_NAME} requires a non-blank string in args.command"
        )
    return shell


async def _read_float_config(key: str) -> float:
    """Resolve a forensics float-typed config value via ConfigRegistry.

    Falls back to the ForensicsConfigSchema field default on registry
    read failure or non-numeric value so a transient DB blip never
    replaces a bounded timeout with 0 (which would fire instantly).
    """
    default = float(ForensicsConfigSchema.model_fields[key].default)
    try:
        raw = await ConfigRegistry().get("forensics", key)
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("forensics.%s registry read failed (%s); using default %.2f", key, exc, default)
        return default
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        _log.warning("forensics.%s config value %r not coercible to float; using default %.2f", key, raw, default)
        return default



# Shell-command blocklist for the ``tool_run`` path. Dynamic analysis is
# strictly prohibited: we never detonate the sample, never fetch remote
# resources named in the evidence, and never contact an IOC we derived
# from the investigation. Static analysis only.
_COMMAND_BLOCKLIST: tuple[str, ...] = (
    # network fetchers
    "curl ", "wget ", "aria2c", "fetch ", "lynx ", "links ", "w3m ",
    "iwr ", "invoke-webrequest", "invoke-restmethod",
    "bitsadmin", "certutil -urlcache", "certutil /urlcache",
    "powershell -c \"iex", "powershell -c 'iex", "iex(new-object",
    # direct transports
    "ncat ", "ncat.exe", "nc ", "nc.exe ", "socat ",
    "telnet ", "ssh ", "scp ", "sftp ", "rsync ",
    "ftp ", "tftp ",
    # packet / scan
    "nmap ", "masscan ", "zmap ", "hping3 ", "arp-scan",
    "ping -c", "ping -n", "ping6 ", "tracert ", "traceroute ",
    "nslookup ", "dig ", "host ", "whois ",
    # sample detonation
    "./a.out", "./sample", "./main.exe", "./server",
    "wine ", "mono ",
    "start malware", "start sample", "rundll32 ", "regsvr32 ",
    "msiexec ", "mshta ", "cscript ", "wscript ",
    # container / VM escape surfaces
    "docker run", "podman run", "lxc-start", "virsh start",
)



def _command_rejection(command: str) -> str | None:
    low = command.lower()
    for needle in _COMMAND_BLOCKLIST:
        if needle in low:
            return (
                f"blocked: dynamic-analysis prohibited -- command contains "
                f"'{needle.strip()}'. Static analysis only: do NOT execute "
                f"the sample, do NOT contact remote hosts, do NOT probe "
                f"IOCs."
            )
    return None

# Max bytes of stdout to keep per turn in the persisted record. Sized
# to fit complete forensic windows (multi-entry security logs, full
# commits.diff blobs, Action-log zip listings) without truncation.
# The persisted record is ~512 KB; modern Postgres TEXT handles this
# easily and the LLM context window (~200K tokens for opus-4-6) has
# room to spare.
STDOUT_KEEP_BYTES = 512_000

# Max bytes of stdout to render per *historical* turn into the next
# turn's prompt. The most recent turn is always rendered uncut so the
# agent can see the full output of the script it just ran.
_HISTORY_STDOUT_PER_TURN = 80_000



def sanitize_for_postgres_text(s: str | None) -> str | None:
    """Strip bytes that PostgreSQL TEXT columns refuse to store.

    PostgreSQL rejects ``\\x00`` (NUL) bytes in TEXT/VARCHAR columns
    with ``CharacterNotInRepertoireError``. They appear in our pipeline
    when the agent runs ``strings`` or raw byte-carving against packed
    binaries. If they reach the agent_steps INSERT they kill the whole
    investigation: the worker catches the exception, the dispatcher
    records "no response", and the row is left frozen in ``running``
    forever.

    Replace NULs with the unicode replacement character so the bytes
    are still visible to the LLM on the next turn (it can see "binary
    block, replaced ``\ufffd`` chars") without poisoning the DB write.
    ``None`` is preserved as ``None`` so nullable columns stay null.
    """
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "\ufffd")



def render_previous(prev: list[dict[str, Any]]) -> str:
    if not prev:
        return ""

    def _trunc(label: str, value: str | None, limit: int | None) -> str | None:
        if not value:
            return None
        s = str(value)
        if limit is None or len(s) <= limit:
            return f"  {label}: {s}"
        kept = s[:limit]
        dropped = len(s) - limit
        return (
            f"  {label}: {kept}\n"
            f"  ...[truncated {dropped:,} more bytes -- re-run with grep/head/tail "
            f"to view more]"
        )

    out: list[str] = []
    last_idx = len(prev) - 1
    for i, s in enumerate(prev):
        is_last = (i == last_idx)
        # The most recent turn is rendered uncut so the agent can
        # act on the freshest evidence. Older turns get a generous
        # per-turn budget (_HISTORY_STDOUT_PER_TURN) instead of the
        # old 600-char cap that was hiding multi-entry log dumps.
        stdout_limit = None if is_last else _HISTORY_STDOUT_PER_TURN
        stderr_limit = None if is_last else 4_000
        reasoning_limit = None if is_last else 2_000

        out.append(
            f"[turn {s.get('step_number', '?')}] "
            f"action={s.get('action', '?')}"
            + ("  (most recent)" if is_last else "")
        )
        line = _trunc("reasoning", s.get("reasoning"), reasoning_limit)
        if line:
            out.append(line)
        line = _trunc("command  ", s.get("command"), 1_000)
        if line:
            out.append(line)
        line = _trunc("script   ", s.get("script_content"), 4_000)
        if line:
            out.append(line)
        if s.get("exit_code") is not None:
            out.append(f"  exit     : {s['exit_code']}")
        line = _trunc("stdout   ", s.get("stdout"), stdout_limit)
        if line:
            out.append(line)
        line = _trunc("stderr   ", s.get("stderr"), stderr_limit)
        if line:
            out.append(line)
    return "\n".join(out)



async def execute_script(
    *,
    settings: Settings,
    integration: dict[str, Any],
    analyzer_os: str,
    investigation_id: str,
    script_content: str,
) -> dict[str, Any]:
    """Execute a Python script on the analyzer via ``ScriptExecutorTool``.

    Safety blocklist is applied here; all SSH, temp-file handling, and
    OS dispatch are owned by the tool.
    """
    rejection = script_rejection(script_content)
    if rejection is not None:
        _log.warning("script blocked for investigation %s: %s", investigation_id, rejection)
        return {"stdout": "", "stderr": rejection, "exit_code": 1}

    # Pre-flight syntax check -- catch IndentationError/SyntaxError before
    # wasting an SSH round-trip and a turn on broken Python.
    try:
        compile(script_content, '<investigator_script>', 'exec')
    except SyntaxError as syn_err:
        msg = f'SyntaxError before execution (line {syn_err.lineno}): {syn_err.msg}'
        _log.warning('script syntax error for investigation %s: %s', investigation_id, msg)
        return {'stdout': '', 'stderr': msg, 'exit_code': 1}

    # Pre-flight dissect API lint -- catch the top mistakes before SSH.
    _dissect_mistakes = [
        ('Target(', 'Target.open(', 'Use Target.open(path), not Target(path)'),
        ('.rglob(', '.walk(', 'RootFilesystem has no rglob(). Use t.fs.walk() or t.fs.path().iterdir()'),
        ('.get_value(', '.value(', 'RegfKey has no get_value(). Use key.value(name)'),
        ('.iter_values(', '.values()', 'RegfKey has no iter_values(). Use key.values()'),
        ('.get_subkey(', '.subkeys()', 'RegfKey has no get_subkey(). Use key.subkeys()'),
        ('hive.get_key(', 't.registry.key(', 'Do not open raw regf hives. Use t.registry.key(path)'),
        ('RegistryHive(', 't.registry.key(', 'Do not open raw regf hives. Use t.registry.key(path)'),
    ]
    for bad, good, explanation in _dissect_mistakes:
        if bad not in script_content:
            continue
        if bad == 'Target(' and 'Target.open(' in script_content.split(bad, maxsplit=1)[0][-20:]:
            continue
        msg = f'API mistake: found `{bad}` -- {explanation}. Use `{good}` instead.'
        _log.warning('script API lint for investigation %s: %s', investigation_id, msg)
        return {'stdout': '', 'stderr': msg, 'exit_code': 1}

    tool = script_tool.ScriptExecutorTool(settings)
    result = await tool.forward(
        script_content=script_content,
        integration=integration,
        analyzer_os=analyzer_os,
        timeout_seconds=await _read_float_config("script_execution_timeout_seconds"),
    )
    stdout = sanitize_for_postgres_text(
        (result.get("stdout") or "")[:STDOUT_KEEP_BYTES]
    )
    return {
        "stdout": stdout,
        "stderr": sanitize_for_postgres_text(result.get("stderr") or ""),
        "exit_code": result.get("exit_code", 0),
    }



async def execute_command(
    *,
    settings: Settings,
    integration: dict[str, Any],
    investigation_id: str,
    command: str,
) -> dict[str, Any]:
    """Run a shell command on the analyzer via the platform SSH service.

    The ``_command_rejection`` guard enforces static-analysis-only
    policy: network fetchers (curl, wget, invoke-webrequest),
    transports (ncat, ssh, ftp), scanners (nmap, ping), sample
    detonators (rundll32, mshta, wine) and container launchers are
    refused before they reach SSH.
    """
    rejection = _command_rejection(command)
    if rejection is not None:
        _log.warning("command blocked for investigation %s: %s", investigation_id, rejection)
        return {"stdout": "", "stderr": rejection, "exit_code": 1}

    ssh = await _ssh_helper.get_ssh_service(settings)
    try:
        stdout = await ssh.run_command(
            integration, command,
            timeout_seconds=await _read_float_config("ssh_command_timeout_seconds"),
        )
        return {
            "stdout": sanitize_for_postgres_text((stdout or "")[:STDOUT_KEEP_BYTES]),
            "stderr": "",
            "exit_code": 0,
        }
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        return {
            "stdout": "",
            "stderr": sanitize_for_postgres_text(str(exc)[:2000]),
            "exit_code": 1,
        }


async def execute_artifact_query(
    *,
    settings: Settings,
    project_id: str,
    search_text: str,
    artifact_family: str,
    artifact_type: str,
) -> dict[str, Any]:
    """Search the project's normalized artifacts via ``ArtifactQueryTool``.

    Empty ``search_text`` lists artifacts; a non-empty one runs a text search
    over the stored artifact data. Empty ``artifact_family`` / ``artifact_type``
    mean no filter. The result carries a ``command`` line describing the query
    on success and only ``stderr`` on failure, so the step record shows what
    was asked whenever the store answered.
    """
    tool = artifact_query.ArtifactQueryTool(settings)
    try:
        query_result = await tool.forward(
            action="search" if search_text else "list",
            project_id=project_id,
            artifact_family=artifact_family or None,
            artifact_type=artifact_type or None,
            search_text=search_text or None,
            limit=20,
        )
    except (ValueError, RuntimeError, OSError, KeyError) as exc:
        return {"stderr": f"artifact_query failed: {exc}", "exit_code": 1}
    return {
        "stdout": json.dumps(query_result, default=str)[:STDOUT_KEEP_BYTES],
        "exit_code": 0,
        "command": (
            f"artifact_query search={search_text!r} "
            f"family={artifact_family!r} type={artifact_type!r}"
        ),
    }



async def load_project_context(
    *,
    project_id: str,
) -> tuple[str, str, str, str | None]:
    """Return ``(evidence_listing, evidence_dir, project_kind, team_id)``."""
    async with UnitOfWork() as uow:
        project = (await uow.session.exec(
            select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
        )).first()
        evidence_rows = (await uow.session.exec(
            select(ProjectEvidenceRecord).where(
                ProjectEvidenceRecord.project_id == project_id
            )
        )).all()

    evidence_dir = project.evidence_directory if project else "/evidence"
    project_kind = project.project_kind if project else "disk_evidence"
    team_id = project.team_id if project else None
    if not evidence_rows:
        return "", evidence_dir, project_kind, team_id
    lines = [
        f"- {r.file_path} ({r.evidence_type}, {r.size_bytes or '?'} bytes)"
        for r in evidence_rows
    ]
    return "\n".join(lines[:80]), evidence_dir, project_kind, team_id



async def load_operator_steering(
    *,
    project_id: str,
    investigation_id: str,
) -> ReasoningOperatorSteering:
    """Return structured analyst steering for the current turn.

    Project-wide directives apply first, then investigation-scoped ones.
    Structured fields (``strategy_family`` / ``required_artifact``) take
    precedence over legacy text conventions like ``strategy: <family>``.
    """
    async with UnitOfWork() as uow:
        stmt = select(AnalystDirectiveRecord).where(
            AnalystDirectiveRecord.project_id == project_id,
            AnalystDirectiveRecord.active.is_(True),  # type: ignore[union-attr]
            (AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
            | (AnalystDirectiveRecord.investigation_id == investigation_id),
        )
        rows = (await uow.session.exec(stmt)).all()
    if not rows:
        return ReasoningOperatorSteering()
    rows_sorted = sorted(rows, key=lambda r: (r.investigation_id is not None, r.created_at))

    steering = ReasoningOperatorSteering()
    for row in rows_sorted:
        scope = "I" if row.investigation_id else "P"
        stamp = row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "?"
        text = (row.text or "").strip().replace("\n", " ")
        if len(text) > 600:
            text = text[:597] + "..."
        line = f"[{scope}] {stamp} -- {text}"
        if row.strategy_family and row.verdict is None:
            steering.pinned_strategy_family = row.strategy_family
        if row.required_artifact and row.verdict is None:
            steering.required_artifacts.append(f"[{scope}] {row.required_artifact}")

        lowered = text.lower()
        if lowered.startswith("strategy:") and row.verdict is None and steering.pinned_strategy_family is None:
            candidate = text.split(":", 1)[1].strip().lower()
            if candidate in {
                "filesystem_triage",
                "persistence_hunt",
                "memory_forensics",
                "network_forensics",
                "malware_static",
                "vulnerability_research",
                "web_pentest",
                "mobile_reverse",
                "generic",
            }:
                steering.pinned_strategy_family = candidate  # type: ignore[assignment]
                continue
        if lowered.startswith("artifact:") and row.verdict is None and not row.required_artifact:
            artifact = text.split(":", 1)[1].strip()
            if artifact:
                steering.required_artifacts.append(f"[{scope}] {artifact}")
                continue
        if row.verdict == "true":
            steering.confirmed_facts.append(line)
        elif row.verdict == "false":
            steering.disproved_hypotheses.append(line)
        else:
            steering.guidance.append(line)
    return steering



async def snapshot_artifacts(
    *,
    project_id: str,
) -> str:
    """Compact artefact snapshot for prompt injection.

    Unlike the old agent, this function does NOT inject CTF-shaped
    keywords (``win_apis``, ``telegram_overlay_root``, …). It emits a
    neutral shape: family -> type -> top records -> key=value fields.
    """
    async with UnitOfWork() as uow:
        artifacts = (await uow.session.exec(
            select(ArtifactRecord)
            .where(ArtifactRecord.project_id == project_id)
            .order_by(ArtifactRecord.lead_score.desc())
            .limit(60)
        )).all()
        leads = (await uow.session.exec(
            select(LeadRecord)
            .where(LeadRecord.project_id == project_id)
            .order_by(LeadRecord.score.desc())
            .limit(10)
        )).all()

    if not artifacts and not leads:
        return ""

    sections: list[str] = []

    if leads:
        sections.append("== LEADS (highest score) ==")
        for lead in leads:
            sections.append(
                f"  [lead:{lead.id}] family={lead.artifact_family} score={lead.score:.0f} reason={lead.reason[:200]}"
            )

    by_family: dict[str, list[ArtifactRecord]] = {}
    for art in artifacts:
        by_family.setdefault(art.artifact_family or "unknown", []).append(art)

    for family, arts in sorted(by_family.items(), key=lambda x: -max((a.lead_score or 0) for a in x[1])):
        sections.append(f"\n== {family.upper()} ({len(arts)} artefacts) ==")
        for art in arts[:8]:
            try:
                data = json.loads(art.data_json) if art.data_json else {}
            except (json.JSONDecodeError, TypeError):
                data = {}
            head = f"  [art:{art.id}] type={art.artifact_type} score={art.lead_score or 0:.0f}"
            if isinstance(data, dict):
                flat: list[str] = []
                for k, v in list(data.items())[:8]:
                    if k.startswith("_"):
                        continue
                    if v in (None, "", [], {}):
                        continue
                    if isinstance(v, (list, dict)):
                        rendered = json.dumps(v, default=str)[:140]
                    else:
                        rendered = str(v)[:140]
                    flat.append(f"{k}={rendered}")
                if flat:
                    head = head + " | " + " | ".join(flat)
            sections.append(head)
            if isinstance(data, dict):
                records = data.get("records")
                if isinstance(records, list):
                    real = [r for r in records if isinstance(r, dict) and r.get("_type") != "recorddescriptor"]
                    for rec in real[:6]:
                        pairs = [
                            f"{k}={str(v)[:120]}"
                            for k, v in list(rec.items())[:6]
                            if not k.startswith("_") and v not in (None, "", [], {})
                        ]
                        if pairs:
                            sections.append("    - " + " | ".join(pairs))

    return "\n".join(sections)[:18_000]
