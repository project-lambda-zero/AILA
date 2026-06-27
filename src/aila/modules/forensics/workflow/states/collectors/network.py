"""PCAP collector -- runs tshark, parses rows, emits structured artifacts.

This replaced the original "dump raw stdout into a text blob" design. Every
collected category is a parsed list of typed dicts that the API hands to
the frontend verbatim. An optional LLM commentary pass runs at the end to
narrate the findings per subject (hosts, DNS, HTTP, TLS, beacons,
anomalies) -- when the LLM is disabled, the structured data still stands
on its own.

Honest scope:
- No live IOC enrichment, no ASN lookup, no external calls.
- No custom parsers beyond what tshark already hands us in TSV/JSON.
- Beacon detection is a cheap Python pass over packet timings; we do not
  try to classify specific malware families.
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from aila.modules.forensics.services.pcap_enrich import (
    aggregate_dns,
    aggregate_hosts,
    build_llm_summary,
    classify_tld,
    detect_beacons,
    dga_shape_score,
    group_packets_by_flow,
    is_rfc1918,
    is_suspicious_ua,
    rank_top,
)
from aila.platform.exceptions import AILAError
from aila.platform.services.factory import ServiceFactory

from ._helpers import err_sink, safe_emit, sq

__all__ = ["collect_network_artifacts"]

_log = logging.getLogger(__name__)

# Tshark field-row hard cap per query. We hoist these into memory for
# parsing; anything beyond this is already a signal of noise, not a
# missed finding.
_ROW_CAP = 5000


async def _resolve_tshark_cmd(
    ssh: Any, integration: dict, analyzer_os: str,
) -> str:
    """Return the shell token that invokes tshark on the analyzer."""
    if analyzer_os != "windows":
        return "tshark"
    probe = (
        'where tshark.exe 2>NUL || '
        'where /R "C:\\Program Files\\Wireshark" tshark.exe 2>NUL || '
        'where /R "C:\\Program Files (x86)\\Wireshark" tshark.exe 2>NUL'
    )
    try:
        out = await ssh.run_command(integration, probe, timeout_seconds=15.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("tshark path probe failed: %s -- falling back to bare tshark", exc)
        return "tshark"
    first = next((line.strip() for line in out.splitlines() if line.strip()), "")
    return f'"{first}"' if first else "tshark"


# ---------------------------------------------------------------- helpers


def _split_fields(line: str, n: int) -> list[str]:
    """Split a tshark TSV field row, padding to ``n`` columns."""
    parts = line.split("\t")
    if len(parts) < n:
        parts.extend([""] * (n - len(parts)))
    return parts[:n]


def _int_or_zero(s: str) -> int:
    try:
        return int(s.strip())
    except (ValueError, AttributeError):
        return 0


def _float_or_zero(s: str) -> float:
    try:
        return float(s.strip())
    except (ValueError, AttributeError):
        return 0.0


def _epoch_to_iso(s: str) -> str:
    """Convert a tshark ``frame.time_epoch`` value to an ISO-8601 UTC string.

    ``frame.time`` (tshark's default) is a locale-formatted human string
    (e.g. ``"Mar 15, 2024 10:23:45.123456789 EDT"``) that front-ends
    cannot parse reliably and that drifts with the analyzer's TZ.
    ``frame.time_epoch`` is a stable float of UNIX seconds; we normalise
    it here to the same ISO-8601 shape the timeline endpoint already
    understands.
    """
    raw = (s or "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.fromtimestamp(float(raw), tz=UTC)
    except (ValueError, OSError, OverflowError):
        return raw  # preserve whatever tshark gave us rather than losing it
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


async def _run_tshark(
    ssh: Any, integration: dict, cmd: str, timeout: float = 180.0,
) -> str:
    """Execute a tshark command over SSH, swallowing expected error classes."""
    try:
        return await ssh.run_command(integration, cmd, timeout_seconds=timeout)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("tshark command failed: %s -> %s", cmd[:160], exc)
        return ""


# -------------------------------------------- per-category parsers


def _parse_conv_block(output: str, proto: str) -> list[dict[str, Any]]:
    """Parse ``-z conv,tcp`` / ``conv,udp`` output into structured rows.

    tshark prints a fixed-width table like::

        ================================================================================
        TCP Conversations
        Filter:<No Filter>
                                               |       <-     | |       ->     | ...
                                               | Frames  Bytes| | Frames  Bytes| ...
        10.0.0.5:443 <-> 10.0.0.9:51234           42   5,120    38  3,200 ...

    We extract the src:sport <-> dst:dport endpoints and the packet/byte
    totals (both directions summed) plus the relative start + duration
    columns when present.
    """
    rows: list[dict[str, Any]] = []
    line_re = re.compile(
        r"^([\d\.:a-f]+):(\d+)\s+<->\s+([\d\.:a-f]+):(\d+)\s+"
        r"([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+"
        r"([\d,]+)\s+([\d,]+)"
        r"(?:\s+([\d\.]+)\s+([\d\.]+))?"
    )
    for line in output.splitlines():
        m = line_re.match(line.strip())
        if not m:
            continue
        src, sport, dst, dport = m.group(1), m.group(2), m.group(3), m.group(4)
        pkts_a = _int_or_zero(m.group(5).replace(",", ""))
        bytes_a = _int_or_zero(m.group(6).replace(",", ""))
        pkts_b = _int_or_zero(m.group(7).replace(",", ""))
        bytes_b = _int_or_zero(m.group(8).replace(",", ""))
        pkts_total = _int_or_zero(m.group(9).replace(",", ""))
        bytes_total = _int_or_zero(m.group(10).replace(",", ""))
        start = _float_or_zero(m.group(11)) if m.group(11) else 0.0
        duration = _float_or_zero(m.group(12)) if m.group(12) else 0.0
        bps = (bytes_total / duration) if duration > 0 else 0.0
        rows.append({
            "src": src,
            "sport": _int_or_zero(sport),
            "dst": dst,
            "dport": _int_or_zero(dport),
            "protocol": proto,
            "packets": pkts_total or (pkts_a + pkts_b),
            "bytes": bytes_total or (bytes_a + bytes_b),
            "pkts_client_to_server": pkts_a,
            "pkts_server_to_client": pkts_b,
            "bytes_client_to_server": bytes_a,
            "bytes_server_to_client": bytes_b,
            "start_rel_s": round(start, 3),
            "duration_s": round(duration, 3),
            "bytes_per_sec": round(bps, 1),
            "is_long_lived": duration >= 600.0,
        })
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return rows[:_ROW_CAP]


def _parse_dns(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, qname, qtype, a, aaaa, rcode = _split_fields(line, 6)
        if not qname:
            continue
        answers = [x for x in (a.split(","), aaaa.split(",")) for x in x if x]
        rows.append({
            "ts": _epoch_to_iso(ts),
            "qname": qname.strip().lower(),
            "qtype": qtype.strip() or "A",
            "answers": answers,
            "rcode": rcode.strip(),
        })
    return rows[:_ROW_CAP]


def _parse_http_requests(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, src, dst, host, method, uri, ua, ct = _split_fields(line, 8)
        sus, tag = is_suspicious_ua(ua if ua else None)
        rows.append({
            "ts": _epoch_to_iso(ts),
            "src": src.strip(),
            "dst": dst.strip(),
            "host": host.strip(),
            "method": (method.strip() or "GET").upper(),
            "uri": uri.strip(),
            "user_agent": ua.strip(),
            "content_type": ct.strip(),
            "is_suspicious_ua": sus,
            "ua_tag": tag,
        })
    return rows[:_ROW_CAP]


def _parse_http_responses(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, src, code, ct, clen = _split_fields(line, 5)
        try:
            code_i = int(code)
        except (ValueError, TypeError):
            code_i = 0
        rows.append({
            "ts": _epoch_to_iso(ts),
            "src": src.strip(),
            "status": code_i,
            "content_type": ct.strip(),
            "content_length": _int_or_zero(clen),
            "is_error": code_i >= 400,
        })
    return rows[:_ROW_CAP]


def _parse_tls_ch(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, src, dst, dport, sni, ja3, ja3_hash, version = _split_fields(line, 8)
        rows.append({
            "ts": _epoch_to_iso(ts),
            "src": src.strip(),
            "dst": dst.strip(),
            "dport": _int_or_zero(dport),
            "sni": sni.strip(),
            "ja3_full": ja3.strip(),
            "ja3": ja3_hash.strip() or ja3.strip()[:32],
            "tls_version": version.strip(),
        })
    return rows[:_ROW_CAP]


def _parse_protocol_hierarchy(output: str) -> list[dict[str, Any]]:
    """Parse ``-z io,phs`` output into protocol rows.

    tshark prints lines like:
        eth                                      frames:20000 bytes:15000000
          ip                                     frames:19900 bytes:14900000
            tcp                                  frames:15000 bytes:12000000
    """
    rows: list[dict[str, Any]] = []
    line_re = re.compile(
        r"^(\s*)([\w\-\.]+)\s+frames:(\d+)\s+bytes:(\d+)"
    )
    total_frames = 0
    for line in output.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        depth = len(m.group(1)) // 2
        proto, frames, bts = m.group(2), int(m.group(3)), int(m.group(4))
        if depth == 0:
            total_frames = max(total_frames, frames)
        rows.append({
            "protocol": proto,
            "depth": depth,
            "packets": frames,
            "bytes": bts,
        })
    if total_frames > 0:
        for r in rows:
            r["percent"] = round((r["packets"] / total_frames) * 100.0, 2)
    rows.sort(key=lambda r: r["packets"], reverse=True)
    return rows


def _parse_capture_summary(output: str) -> dict[str, Any]:
    """Pull ``capinfos``-style overview from ``-z io,stat,0`` output.

    The header block looks like::

        =====================================
        | IO Statistics                     |
        |                                   |
        | Duration: 112.453 secs            |
        | Interval:  112.453 secs           |
        =====================================
        |               |1 <> 2     |
        | Interval      | Frames |  Bytes   |
        |-----------------------------------|
        | 0.0 <> 112.4  |  20000 | 15000000 |
        =====================================

    We extract duration + total frames/bytes. Missing pieces default to
    0 so downstream rendering never has to special-case.
    """
    out = {"packet_count": 0, "byte_count": 0, "duration_s": 0.0}
    m = re.search(r"Duration:\s+([\d\.]+)\s+secs?", output)
    if m:
        out["duration_s"] = round(float(m.group(1)), 3)
    interval_re = re.compile(
        r"\|\s*[\d\.]+\s+<>\s+[\d\.]+\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|"
    )
    for m in interval_re.finditer(output):
        out["packet_count"] = int(m.group(1))
        out["byte_count"] = int(m.group(2))
    return out


def _parse_credentials(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, src, dst, auth, ftp_cmd, ftp_arg, smtp_cmd, smtp_param = _split_fields(
            line, 8
        )
        rows.append({
            "ts": _epoch_to_iso(ts),
            "src": src.strip(),
            "dst": dst.strip(),
            "http_authorization": auth.strip(),
            "ftp_command": ftp_cmd.strip(),
            "ftp_arg": ftp_arg.strip(),
            "smtp_command": smtp_cmd.strip(),
            "smtp_param": smtp_param.strip(),
            "kind": _credential_kind(auth, ftp_cmd, smtp_cmd),
        })
    return rows[:_ROW_CAP]


def _credential_kind(auth: str, ftp: str, smtp: str) -> str:
    if auth.strip():
        if auth.strip().lower().startswith("basic"):
            return "http_basic"
        return "http_auth"
    if ftp.strip().upper() in ("USER", "PASS"):
        return f"ftp_{ftp.strip().lower()}"
    if smtp.strip().upper() == "AUTH":
        return "smtp_auth"
    return "unknown"


def _parse_packet_flow_rows(output: str) -> list[dict[str, Any]]:
    """Parse per-packet TSV used by beacon detection.

    Fields: frame.time_epoch  ip.src  ip.dst  tcp.dstport  udp.dstport  frame.len
    """
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        ts, src, dst, tcp_dp, udp_dp, size = _split_fields(line, 6)
        if not src or not dst:
            continue
        dport_s = tcp_dp.strip() or udp_dp.strip()
        proto = "tcp" if tcp_dp.strip() else "udp"
        rows.append({
            "ts_epoch": ts.strip(),
            "src": src.strip(),
            "dst": dst.strip(),
            "dport": dport_s,
            "proto": proto,
            "size": size.strip(),
        })
    return rows[:_ROW_CAP]


def _parse_user_agents(output: str) -> list[dict[str, Any]]:
    counts: Counter = Counter()
    for line in output.splitlines():
        ua = line.strip()
        if ua:
            counts[ua] += 1
    rows: list[dict[str, Any]] = []
    for ua, n in counts.most_common(200):
        sus, tag = is_suspicious_ua(ua)
        rows.append({
            "user_agent": ua,
            "count": n,
            "is_suspicious": sus,
            "tag": tag,
        })
    return rows


def _parse_unusual_ports(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        src, dst, dport = _split_fields(line, 3)
        if not dport:
            continue
        rows.append({
            "src": src.strip(),
            "dst": dst.strip(),
            "dport": _int_or_zero(dport),
        })
    # Dedupe by (src,dst,dport)
    seen: set[tuple[str, str, int]] = set()
    unique: list[dict[str, Any]] = []
    for r in rows:
        key = (r["src"], r["dst"], r["dport"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    unique.sort(key=lambda r: r["dport"])
    return unique[:_ROW_CAP]


# -------------------------------------------- LLM commentary


async def _resolve_zeek_cmd(
    ssh: Any, integration: dict, analyzer_os: str,
) -> str | None:
    """Return the shell token that invokes ``zeek`` on the analyzer, or None."""
    if analyzer_os == "windows":
        probe = 'where zeek.exe 2>NUL'
    else:
        probe = 'command -v zeek 2>/dev/null'
    try:
        out = await ssh.run_command(integration, probe, timeout_seconds=10.0)
    except (OSError, TimeoutError, RuntimeError, AILAError):
        return None
    first = next((line.strip() for line in out.splitlines() if line.strip()), "")
    if not first:
        return None
    return f'"{first}"' if analyzer_os == "windows" else first


async def _run_zeek_carve(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str,
    emitter: Any,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Run Zeek with file-extraction enabled and return carved-file artefacts.

    Returns ``(carved_artifacts, mime_histogram)``. When Zeek is not
    installed on the analyzer the function emits a ``zeek_skipped``
    event and returns empty values -- the overall pcap collection still
    completes with tshark-only output.
    """
    zeek_cmd = await _resolve_zeek_cmd(ssh, integration, analyzer_os)
    if not zeek_cmd:
        await safe_emit(
            emitter, "zeek_skipped",
            "network: zeek not installed on analyzer -- pcap file-carving skipped",
            {"path": path, "reason": "zeek_not_installed"},
        )
        return [], {}

    # Per-pcap scratch directory. We hash the path so a re-run on the
    # same pcap reuses the slot and doesn't fill up %TEMP%.
    import hashlib as _hashlib
    slot = _hashlib.sha1(path.encode("utf-8", "ignore")).hexdigest()[:10]
    if analyzer_os == "windows":
        scratch = f"C:\\Windows\\Temp\\aila_zeek_{slot}"
        mkdir_cmd = (
            f'powershell -NoProfile -Command '
            f'"New-Item -ItemType Directory -Force -Path \'{scratch}\' '
            f'| Out-Null"'
        )
        list_cmd = (
            f'powershell -NoProfile -Command '
            f'"Get-ChildItem -Path \'{scratch}\\extract_files\' -File '
            f'-ErrorAction SilentlyContinue | '
            f'ForEach-Object {{ '
            f'$_.FullName + \'|\' + $_.Length + \'|\' + '
            f'(Get-FileHash $_.FullName -Algorithm SHA256).Hash }}"'
        )
        files_log = f"{scratch}\\files.log"
        cat_files_log = (
            f'powershell -NoProfile -Command '
            f'"if (Test-Path \'{files_log}\') '
            f'{{ Get-Content -Raw -Path \'{files_log}\' }}"'
        )
    else:
        scratch = f"/tmp/aila_zeek_{slot}"
        mkdir_cmd = f"mkdir -p {sq(scratch, analyzer_os)}"
        list_cmd = (
            f"find {sq(scratch, analyzer_os)}/extract_files -maxdepth 1 -type f "
            f"-printf '%p|%s|' -exec sha256sum {{}} \\; 2>/dev/null "
            f"| awk '{{print $1 $2}}'"
        )
        files_log = f"{scratch}/files.log"
        cat_files_log = f"cat {sq(files_log, analyzer_os)} 2>/dev/null"

    try:
        await ssh.run_command(integration, mkdir_cmd, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(
            emitter, "zeek_scratch_failed",
            f"network: zeek scratch dir creation failed -- {exc}",
            {"path": path, "scratch": scratch, "error": str(exc)[:200]},
        )
        return [], {}

    # Zeek with the `file-extraction` policy extracts every file seen
    # over any protocol to ``extract_files/`` next to the log files.
    #   -r <pcap>               : read from pcap instead of live iface
    #   LogAscii::use_json=T    : emit JSON log lines
    #   FileExtract::prefix=... : where carved bytes land
    # We wrap in cd so output lands inside the scratch dir.
    cd_then = (
        f'cd /d "{scratch}"' if analyzer_os == "windows" else
        f"cd {sq(scratch, analyzer_os)}"
    )
    zeek_invocation = (
        f"{zeek_cmd} -r {sq(path, analyzer_os)} "
        f"LogAscii::use_json=T "
        f'FileExtract::prefix="extract_files/" '
        f"file-extraction"
    )
    run_cmd = f"{cd_then} && {zeek_invocation}"

    await safe_emit(
        emitter, "zeek_begin",
        f"network: zeek file-extraction starting on {path}",
        {"path": path, "scratch": scratch},
    )
    try:
        await ssh.run_command(integration, run_cmd, timeout_seconds=900.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(
            emitter, "zeek_failed",
            f"network: zeek run failed -- {exc}",
            {"path": path, "error": str(exc)[:300]},
        )
        return [], {}

    # Pull metadata from the files.log so we can cross-reference hashes
    # against connection info (src/dst/protocol, filename if HTTP).
    try:
        files_log_text = await ssh.run_command(
            integration, cat_files_log, timeout_seconds=30.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError):
        files_log_text = ""

    meta_by_sha: dict[str, dict[str, Any]] = {}
    for line in (files_log_text or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        sha = rec.get("sha256") or rec.get("sha1") or rec.get("md5")
        if not sha:
            continue
        meta_by_sha[str(sha)] = {
            "protocol": rec.get("source") or rec.get("conn_ids") or "",
            "mime_type": rec.get("mime_type"),
            "filename": rec.get("filename"),
            "tx_hosts": rec.get("tx_hosts") or [],
            "rx_hosts": rec.get("rx_hosts") or [],
            "total_bytes": rec.get("total_bytes"),
            "seen_bytes": rec.get("seen_bytes"),
            "ts_first_seen": rec.get("ts"),
            "fuid": rec.get("fuid"),
        }

    # List the actually extracted files (some may have been filtered out
    # by Zeek's own size/policy rules).
    try:
        listing = await ssh.run_command(
            integration, list_cmd, timeout_seconds=60.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(
            emitter, "zeek_list_failed",
            f"network: cannot list carved files -- {exc}",
            {"path": path, "error": str(exc)[:200]},
        )
        return [], {}

    carved: list[dict[str, Any]] = []
    mime_hist: dict[str, int] = {}
    for raw in (listing or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split("|", 2)
        if len(parts) < 3:
            continue
        carved_path, size_str, sha = parts[0].strip(), parts[1].strip(), parts[2].strip().lower()
        try:
            size = int(size_str)
        except (TypeError, ValueError):
            size = 0
        meta = meta_by_sha.get(sha, {})
        mime = (meta.get("mime_type") or "application/octet-stream").lower()
        mime_hist[mime] = mime_hist.get(mime, 0) + 1
        carved.append({
            "sha256": sha,
            "size_bytes": size,
            "carved_path": carved_path,
            "mime_type": mime,
            "filename_guess": meta.get("filename"),
            "protocol": meta.get("protocol"),
            "tx_hosts": meta.get("tx_hosts") or [],
            "rx_hosts": meta.get("rx_hosts") or [],
            "ts_first_seen": meta.get("ts_first_seen"),
            "zeek_fuid": meta.get("fuid"),
            "source_pcap": path,
        })

    await safe_emit(
        emitter, "zeek_carved",
        f"network: zeek extracted {len(carved)} file(s) from {path}",
        {"path": path, "count": len(carved)},
    )
    return carved, mime_hist


async def _try_llm_commentary(
    summary_text: str, emitter: Any,
) -> list[dict[str, Any]]:
    """Ask the LLM to narrate the summary as structured commentary.

    Returns a list of commentary objects: ``{subject, narrative, severity}``.
    Fails soft -- on any error we emit a ``commentary_skipped`` event and
    return an empty list so the overall collection run does not fail.
    """
    system = (
        "You are a senior network-forensics analyst. You are given a compact "
        "factual summary of a pcap capture. Produce short, specific, cited "
        "commentary per subject. DO NOT invent data not in the summary. "
        "If there is nothing notable for a subject, say so honestly in one "
        "short sentence rather than padding. Ground every claim in specific "
        "IPs, ports, SNIs, domains, or counts that appear in the summary."
    )
    user = (
        "Return JSON with schema:\n"
        "{\"commentary\": [\n"
        "  {\"subject\": \"overall\" | \"hosts\" | \"dns\" | \"http\" | "
        "\"tls\" | \"beacons\" | \"anomalies\","
        " \"narrative\": \"2-6 sentences, concrete\","
        " \"severity\": \"info\" | \"low\" | \"medium\" | \"high\"}\n"
        "]}\n\n"
        "One object per subject. Severity reflects only what is visible in "
        "the summary. Keep narratives under ~450 chars.\n\n"
        "=== SUMMARY ===\n" + summary_text
    )
    schema = {
        "type": "object",
        "properties": {
            "commentary": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "narrative": {"type": "string"},
                        "severity": {"type": "string"},
                    },
                    "required": ["subject", "narrative", "severity"],
                },
            }
        },
        "required": ["commentary"],
    }
    try:
        client = ServiceFactory().llm_client
        resp = await client.chat_json(
            task_type="forensics_freeflow",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            schema=schema,
        )
        if resp.disabled:
            await safe_emit(
                emitter, "commentary_skipped",
                "LLM disabled -- skipping pcap commentary",
                {"reason": "disabled"},
            )
            return []
        payload = json.loads(resp.content) if resp.content else {}
        items = payload.get("commentary") or []
        # Keep only the fields we promised the UI.
        out: list[dict[str, Any]] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            subject = str(it.get("subject") or "").strip()
            narrative = str(it.get("narrative") or "").strip()
            severity = str(it.get("severity") or "info").strip().lower()
            if not subject or not narrative:
                continue
            if severity not in ("info", "low", "medium", "high"):
                severity = "info"
            out.append({
                "subject": subject,
                "narrative": narrative,
                "severity": severity,
            })
        return out
    except (OSError, TimeoutError, RuntimeError, ValueError, KeyError, AILAError) as exc:
        _log.warning("network commentary LLM call failed: %s", exc, exc_info=True)
        await safe_emit(
            emitter, "commentary_skipped",
            f"LLM commentary failed: {exc}",
            {"reason": "error", "error": str(exc)[:300]},
        )
        return []


# -------------------------------------------- main entrypoint


async def collect_network_artifacts(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str = "linux",
    emitter: Any = None,
    on_artifact: Any = None,
) -> list[dict[str, Any]]:
    """Run structured tshark queries, parse rows, enrich, and emit artifacts.

    Emits one artifact per semantic category (not one per raw stdout dump):
    ``capture_stats``, ``protocol_hierarchy``, ``hosts``, ``sessions``,
    ``dns``, ``http_requests``, ``http_responses``, ``tls_client_hellos``,
    ``unusual_ports``, ``user_agents``, ``credentials``, ``beacons``,
    ``commentary``.
    """
    esink = err_sink(analyzer_os)
    qpath = sq(path, analyzer_os)
    ts = await _resolve_tshark_cmd(ssh, integration, analyzer_os)
    await safe_emit(
        emitter, "tshark_resolved",
        f"network: tshark resolved to {ts}",
        {"path": path, "tshark_cmd": ts, "analyzer_os": analyzer_os},
    )

    artifacts: list[dict[str, Any]] = []

    async def _emit(atype: str, data: dict[str, Any]) -> None:
        art = {
            "family": "network",
            "type": atype,
            "source_tool": "tshark",
            "data": {"evidence_path": path, **data},
        }
        artifacts.append(art)
        if on_artifact:
            await on_artifact(art)
        await safe_emit(
            emitter, "artifact_added", f"network[{atype}]: ok",
            {"path": path, "query": atype},
        )

    # 1. Capture summary ----------------------------------------------------
    await safe_emit(emitter, "stats_begin", "network: capture summary",
                    {"path": path})
    stats_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -q -z io,stat,0 {esink}",
        timeout=120.0,
    )
    stats = _parse_capture_summary(stats_out)
    await _emit("capture_stats", {"stats": stats})

    # 2. Protocol hierarchy -------------------------------------------------
    phs_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -q -z io,phs {esink}",
        timeout=120.0,
    )
    phs_rows = _parse_protocol_hierarchy(phs_out)
    await _emit("protocol_hierarchy", {"rows": phs_rows})

    # 3. Conversations (TCP + UDP) -----------------------------------------
    tcp_conv = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -q -z conv,tcp {esink}",
        timeout=180.0,
    )
    udp_conv = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -q -z conv,udp {esink}",
        timeout=180.0,
    )
    sessions_rows = _parse_conv_block(tcp_conv, "tcp") + _parse_conv_block(udp_conv, "udp")
    await _emit("sessions", {"rows": sessions_rows})

    # 4. Derived hosts table -----------------------------------------------
    hosts_rows = aggregate_hosts(sessions_rows)
    await _emit("hosts", {"rows": hosts_rows})

    # 5. DNS ---------------------------------------------------------------
    dns_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -Y dns -T fields "
        f"-e frame.time_epoch -e dns.qry.name -e dns.qry.type "
        f"-e dns.a -e dns.aaaa -e dns.flags.rcode "
        f"-E separator=/t {esink}",
        timeout=180.0,
    )
    dns_rows_raw = _parse_dns(dns_out)
    dns_rows = aggregate_dns(dns_rows_raw)
    await _emit("dns", {"rows": dns_rows})

    # 6. HTTP requests / responses -----------------------------------------
    http_req_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -Y http.request -T fields "
        f"-e frame.time_epoch -e ip.src -e ip.dst -e http.host "
        f"-e http.request.method -e http.request.uri "
        f"-e http.user_agent -e http.content_type "
        f"-E separator=/t {esink}",
        timeout=180.0,
    )
    http_req_rows = _parse_http_requests(http_req_out)
    await _emit("http_requests", {"rows": http_req_rows})

    http_resp_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -Y http.response -T fields "
        f"-e frame.time_epoch -e ip.src -e http.response.code "
        f"-e http.content_type -e http.content_length "
        f"-E separator=/t {esink}",
        timeout=180.0,
    )
    http_resp_rows = _parse_http_responses(http_resp_out)
    await _emit("http_responses", {"rows": http_resp_rows})

    # 7. TLS Client Hellos (SNI + JA3) -------------------------------------
    tls_out = await _run_tshark(
        ssh, integration,
        f'{ts} -r {qpath} -Y "tls.handshake.type == 1" -T fields '
        f'-e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport '
        f'-e tls.handshake.extensions_server_name '
        f'-e tls.handshake.ja3_full -e tls.handshake.ja3 '
        f'-e tls.handshake.version '
        f'-E separator=/t {esink}',
        timeout=180.0,
    )
    tls_rows = _parse_tls_ch(tls_out)
    await _emit("tls_client_hellos", {"rows": tls_rows})

    # 8. Unusual ports -----------------------------------------------------
    unusual_out = await _run_tshark(
        ssh, integration,
        f'{ts} -r {qpath} -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 '
        f'and tcp.dstport > 1024 and tcp.dstport != 8080 '
        f'and tcp.dstport != 8443 and tcp.dstport != 3306 '
        f'and tcp.dstport != 5432" -T fields '
        f'-e ip.src -e ip.dst -e tcp.dstport '
        f'-E separator=/t {esink}',
        timeout=180.0,
    )
    unusual_rows = _parse_unusual_ports(unusual_out)
    await _emit("unusual_ports", {"rows": unusual_rows})

    # 9. User agents -------------------------------------------------------
    ua_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -Y http.user_agent -T fields -e http.user_agent "
        f"{esink}",
        timeout=180.0,
    )
    ua_rows = _parse_user_agents(ua_out)
    await _emit("user_agents", {"rows": ua_rows})

    # 10. Credential-bearing frames ----------------------------------------
    creds_out = await _run_tshark(
        ssh, integration,
        f'{ts} -r {qpath} -Y "http.authorization or ftp.request.command '
        f'== \\"USER\\" or ftp.request.command == \\"PASS\\" or '
        f'smtp.req.command == \\"AUTH\\"" -T fields '
        f'-e frame.time_epoch -e ip.src -e ip.dst '
        f'-e http.authorization -e ftp.request.command -e ftp.request.arg '
        f'-e smtp.req.command -e smtp.req.parameter '
        f'-E separator=/t {esink}',
        timeout=180.0,
    )
    creds_rows = _parse_credentials(creds_out)
    await _emit("credentials", {"rows": creds_rows})

    # 11. Beacon detection -------------------------------------------------
    flow_out = await _run_tshark(
        ssh, integration,
        f"{ts} -r {qpath} -T fields "
        f"-e frame.time_epoch -e ip.src -e ip.dst "
        f"-e tcp.dstport -e udp.dstport -e frame.len "
        f"-E separator=/t {esink}",
        timeout=240.0,
    )
    flow_rows = _parse_packet_flow_rows(flow_out)
    flows = group_packets_by_flow(flow_rows)
    beacons = detect_beacons(flows)
    beacon_dicts = [
        {
            "src": b.src, "dst": b.dst, "dport": b.dport,
            "protocol": b.protocol,
            "packet_count": b.packet_count,
            "mean_interval_s": b.mean_interval_s,
            "interval_stdev_s": b.interval_stdev_s,
            "regularity": b.regularity,
            "constant_size": b.constant_size,
        }
        for b in beacons[:200]
    ]
    await _emit("beacons", {"rows": beacon_dicts})

    # 12. Anomalies roll-up -------------------------------------------------
    anomalies: list[dict[str, Any]] = []
    nx_rows = [d for d in dns_rows if d.get("nxdomain_count", 0) > 0]
    if nx_rows:
        total_nx = sum(d["nxdomain_count"] for d in nx_rows)
        anomalies.append({
            "kind": "dns_nxdomain",
            "detail": f"{len(nx_rows)} distinct name(s)",
            "count": total_nx,
            "examples": [d["qname"] for d in nx_rows[:5]],
        })
    dga_rows = [d for d in dns_rows if d.get("classification") == "dga_shape"]
    if dga_rows:
        anomalies.append({
            "kind": "dga_shape_dns",
            "detail": "DNS names with DGA-like character distribution",
            "count": len(dga_rows),
            "examples": [d["qname"] for d in dga_rows[:5]],
        })
    sus_tld_rows = [d for d in dns_rows if d.get("classification") == "suspicious"]
    if sus_tld_rows:
        anomalies.append({
            "kind": "suspicious_tld",
            "detail": "DNS names on abuse-heavy TLDs",
            "count": len(sus_tld_rows),
            "examples": [d["qname"] for d in sus_tld_rows[:5]],
        })
    sus_ua_rows = [u for u in ua_rows if u.get("is_suspicious")]
    if sus_ua_rows:
        anomalies.append({
            "kind": "suspicious_user_agent",
            "detail": "LOLbin / scanner / missing User-Agent",
            "count": sum(u["count"] for u in sus_ua_rows),
            "examples": [u["user_agent"] for u in sus_ua_rows[:5]],
        })
    http_errs = [r for r in http_resp_rows if r.get("is_error")]
    if http_errs:
        anomalies.append({
            "kind": "http_4xx_5xx",
            "detail": "HTTP error responses",
            "count": len(http_errs),
        })
    long_flows = [s for s in sessions_rows if s.get("is_long_lived")]
    if long_flows:
        anomalies.append({
            "kind": "long_lived_flow",
            "detail": "TCP flows > 10 min",
            "count": len(long_flows),
            "examples": [
                f"{s['src']}:{s['sport']} -> {s['dst']}:{s['dport']}"
                for s in long_flows[:5]
            ],
        })
    await _emit("anomalies", {"rows": anomalies})

    # 13. LLM commentary ---------------------------------------------------
    await safe_emit(emitter, "commentary_begin",
                    "network: requesting LLM commentary", {"path": path})
    summary = build_llm_summary(
        stats=stats,
        hosts=rank_top(hosts_rows, "bytes_total", 10),
        dns=rank_top(dns_rows, "count", 15),
        http=http_req_rows[:20],
        tls=tls_rows[:20],
        beacons=beacon_dicts[:10],
        anomalies=anomalies,
        protocol_hierarchy=phs_rows[:10],
    )
    commentary = await _try_llm_commentary(summary, emitter)
    if commentary:
        await _emit("commentary", {
            "rows": commentary,
            "summary_prompt": summary,  # kept for audit; UI can hide
        })
    else:
        await safe_emit(emitter, "commentary_empty",
                        "network: no commentary produced", {"path": path})

    # Enriched DNS-by-qname signals also leave a dedicated top-N artifact
    # used by the "DGA / Rare TLD" panel.
    top_suspicious_dns = [
        d for d in dns_rows
        if d.get("classification") in ("suspicious", "dga_shape")
    ][:100]
    await _emit("suspicious_dns", {"rows": top_suspicious_dns})

    # 14. Zeek file-carving stage -----------------------------------------
    # Pulls every file transferred over any protocol out of the pcap
    # (HTTP, SMTP, SMB, FTP, TLS certs, …). Each carved file gets a
    # ``carved_file`` artifact with sha256/size/mime; a single summary
    # ``carved_file_types`` artifact carries the MIME histogram so the
    # UI can render the "most common file types" panel without scanning
    # every row.
    carved, mime_hist = await _run_zeek_carve(
        ssh, integration, path, analyzer_os, emitter,
    )
    if carved is None:
        carved = []
    if carved:
        for cf in carved:
            await _emit("carved_file", cf)
    else:
        # Even the zero-carved case emits a skeleton summary artifact so
        # the UI panel can surface the "nothing carved / Zeek missing"
        # state honestly instead of rendering as if the collector hadn't
        # run at all.
        await safe_emit(
            emitter, "zeek_empty",
            f"network: no files carved from {path}",
            {"path": path},
        )

    mime_rows = sorted(
        ({"mime_type": m, "count": n} for m, n in mime_hist.items()),
        key=lambda r: -r["count"],
    )
    await _emit("carved_file_types", {
        "rows": mime_rows,
        "total_carved": len(carved),
        "unique_mimes": len(mime_hist),
    })

    return artifacts


# Silence "import used only for enrichment helpers" linters on the helpers
# we re-export indirectly through the collector.
_REF = (classify_tld, dga_shape_score, is_rfc1918)
