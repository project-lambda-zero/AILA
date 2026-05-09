"""Lead promotion state handler.

Scores artifacts, promotes high-confidence leads, and builds a
structured **Valuable Items** summary organized by category. The
summary is persisted so that the freeflow agent can inject it as
context before every investigation step.
"""
from __future__ import annotations

import json
import logging
from typing import Any

__all__ = ["state_promotion"]

_log = logging.getLogger(__name__)

state_promotion_parallel_safe = False
state_promotion_writes_fields = ["leads", "valuable_items"]

_SUSPICIOUS_INDICATORS: dict[str, float] = {
    "execution": 40.0,
    "malware": 80.0,
    "network": 30.0,
    "filesystem": 15.0,
    "host": 10.0,
    "user": 10.0,
    "browser": 15.0,
    "memory": 35.0,
    "container": 20.0,
    "log": 10.0,
}

import re


# Each entry: (display_keyword, compiled_pattern, score_boost).
#
# Short / ambiguous keywords use word boundaries so that "c2" does not match
# "x64", "abc2def", "section c2 of..." etc. Generic terms ("suspicious",
# "encrypted") were removed because they fire on schema field names and
# descriptive prose rather than actual evidence.
def _kw(display: str, pattern: str, boost: float) -> tuple[str, re.Pattern[str], float]:
    return display, re.compile(pattern, re.IGNORECASE), boost


_SCORE_BOOST_KEYWORDS: list[tuple[str, re.Pattern[str], float]] = [
    _kw("c2",            r"\bc2\b",                         20.0),
    _kw("reverse_shell", r"reverse[_ -]?shell",             30.0),
    _kw("persistence",   r"\bpersistence\b",                25.0),
    _kw("injection",     r"\b(?:process|dll|code)[_ -]?injection\b|\binjection\b", 25.0),
    _kw("shellcode",     r"\bshellcode\b",                  30.0),
    _kw("credential",    r"\bcredential(?:s|_dump)?\b",     20.0),
    _kw("malicious",     r"\bmalicious\b",                  25.0),
    _kw("rootkit",       r"\brootkit\b",                    35.0),
    _kw("malfind",       r"\bmalfind\b",                    25.0),
    _kw("hook",          r"\b(?:hooked|hooking|api[_ -]?hook)\b", 20.0),
    _kw("exfiltration",  r"\bexfiltrat",                    20.0),
    _kw("trojan",        r"\btrojan\b",                     25.0),
    _kw("backdoor",      r"\bbackdoor\b",                   25.0),
    _kw("dropper",       r"\bdropper\b",                    20.0),
    _kw("infostealer",   r"\b(?:info[_ -]?stealer|stealer)\b", 25.0),
    _kw("keylogger",     r"\bkey[_ -]?log",                 20.0),
]

# Keys we never want to match keywords against — they are schema markers
# (e.g. every enriched record carries "suspicious_reasons" by design; matching
# on the key name would blindly fire the "suspicious" boost on every artifact).
_REASON_SKIP_KEYS: frozenset[str] = frozenset({
    "suspicious_reasons",
    "_classification",
    "_generated",
    "_source",
    "_version",
    "_type",
    "record_type",
    "record_name",
})

# Path segments that name the *scanner*, not the evidence. A dissect
# `browser.credentials` plugin legitimately puts the word "credentials" in its
# plugin / query_function field on every browser scan — that's not a finding.
_REASON_SKIP_PATH_SEGMENTS: frozenset[str] = frozenset({
    "plugin",
    "query_function",
    "tool",
    "source_tool",
    "artifact_type",
    "artifact_family",
    "family",
    "dump_os",
    "analyzer",
    "collector",
    "stage",
})

# Max characters of surrounding context to show for each matched value.
_MATCH_EXCERPT_LEN = 160


async def state_promotion(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Score investigator-emitted artefacts and build the Valuable Items summary.

    **Lead source rule (honest):** only artefacts with a
    ``source_investigation_id`` — i.e. rows the investigator itself
    wrote during a turn — are promoted. Collector-side rows never
    become leads; they populate Valuable Items / Findings but NOT the
    Top Leads panel. The latter is a panel of agent conclusions, not
    keyword heuristics over raw tool output.
    """
    project_id = input.get("project_id", "")

    await services.emitter.emit("promotion", "Scoring investigator findings and building Valuable Items list...")

    from sqlmodel import select

    from aila.modules.forensics.db_models import ArtifactRecord, LeadRecord
    from aila.platform.uow import UnitOfWork

    leads_created = 0
    top_leads: list[dict[str, Any]] = []
    all_artifacts: list[Any] = []

    async with UnitOfWork() as uow:
        artifacts = (await uow.session.exec(
            select(ArtifactRecord).where(ArtifactRecord.project_id == project_id)
        )).all()
        all_artifacts = list(artifacts)

        investigator_rows = [
            a for a in artifacts if a.source_investigation_id
        ]

        for artifact in investigator_rows:
            score = _score_investigator_artifact(artifact)
            if score <= 0:
                continue

            artifact.lead_score = score
            uow.session.add(artifact)

            reason, evidence = _build_investigator_reason(artifact, score)
            related_ids = _find_related_artifact_ids(artifact, artifacts)
            lead = LeadRecord(
                project_id=project_id,
                artifact_id=artifact.id,
                score=score,
                reason=reason,
                artifact_family=artifact.artifact_family,
                related_artifact_ids_json=json.dumps(related_ids),
            )
            uow.session.add(lead)
            leads_created += 1

            top_leads.append({
                "artifact_id": artifact.id,
                "score": score,
                "family": artifact.artifact_family,
                "type": artifact.artifact_type,
                "reason": reason,
                "evidence": evidence,
            })

        await uow.commit()

    top_leads.sort(key=lambda x: x["score"], reverse=True)
    valuable_items = _build_valuable_items(all_artifacts)

    await services.emitter.emit(
        "promotion",
        f"Promoted {leads_created} leads. Valuable Items: {sum(len(v) for v in valuable_items.values())} items across {len(valuable_items)} categories.",
        {"lead_count": leads_created, "high_confidence": len(top_leads), "vi_categories": list(valuable_items.keys())},
    )

    from aila.platform.workflows.types import StateResult

    return StateResult(
        next_state="resolution",
        output={
            "lead_count": leads_created,
            "top_leads": top_leads[:50],
            "valuable_items": valuable_items,
            "project_id": project_id,
            "integration": input.get("integration", {}),
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": input.get("analyzer_os", "linux"),
        },
    )


def _build_valuable_items(artifacts: list[Any]) -> dict[str, list[dict[str, Any]]]:
    """Build a structured Valuable Items summary from all artifacts.

    Organized into categories that the freeflow agent can directly reference:
    - **identities**: Users, emails, accounts, password hints
    - **malware_samples**: Hashes, capabilities, file names, classifications
    - **network_iocs**: IPs, domains, URLs, C2 endpoints, ports
    - **execution_traces**: Processes, command lines, services, persistence
    - **browser_activity**: Downloads, history, extensions, credentials
    - **filesystem_hotspots**: Suspicious files, paths, hashes
    - **memory_findings**: Injected processes, hooked syscalls, loaded modules
    - **container_metadata**: Docker images, mounts, overlay paths
    """
    vi: dict[str, list[dict[str, Any]]] = {
        "identities": [],
        "malware_samples": [],
        "network_iocs": [],
        "execution_traces": [],
        "browser_activity": [],
        "filesystem_hotspots": [],
        "memory_findings": [],
        "container_metadata": [],
    }

    for art in artifacts:
        try:
            data = json.loads(art.data_json) if art.data_json else {}
        except (json.JSONDecodeError, TypeError):
            data = {}

        family = art.artifact_family
        atype = art.artifact_type

        if family == "user" or atype in ("users", "hostname"):
            vi["identities"].append(_vi_entry(art, data))
        elif family == "malware" or atype in ("capa_capabilities", "strings_iocs", "floss_decoded_strings"):
            vi["malware_samples"].append(_vi_entry(art, data))
        elif family == "network":
            vi["network_iocs"].append(_vi_entry(art, data))
        elif family == "execution":
            vi["execution_traces"].append(_vi_entry(art, data))
        elif family == "browser":
            vi["browser_activity"].append(_vi_entry(art, data))
        elif family == "filesystem" or atype == "sha256_hash":
            vi["filesystem_hotspots"].append(_vi_entry(art, data))
        elif family == "memory":
            vi["memory_findings"].append(_vi_entry(art, data))
        elif family == "container":
            vi["container_metadata"].append(_vi_entry(art, data))

    for category in list(vi.keys()):
        if not vi[category]:
            del vi[category]

    return vi


def _vi_entry(artifact: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Build a single Valuable Item entry from an artifact."""
    entry: dict[str, Any] = {
        "type": artifact.artifact_type,
        "tool": artifact.source_tool,
    }
    if artifact.lead_score is not None and artifact.lead_score > 0:
        entry["score"] = artifact.lead_score

    if "ips" in data and data["ips"]:
        entry["ips"] = data["ips"][:10]
    if "urls" in data and data["urls"]:
        entry["urls"] = data["urls"][:5]
    if "domains" in data and data["domains"]:
        entry["domains"] = data["domains"][:10]
    if "win_apis" in data and data["win_apis"]:
        entry["apis"] = data["win_apis"][:10]
    if "hash" in data:
        entry["sha256"] = data["hash"]
    if "file_path" in data:
        entry["file_path"] = data["file_path"]
    if "evidence_path" in data:
        entry["evidence_path"] = data["evidence_path"]
    if "plugin" in data:
        entry["plugin"] = data["plugin"]
    if "dump_os" in data:
        entry["dump_os"] = data["dump_os"]
    if "query_function" in data:
        entry["query_function"] = data["query_function"]

    raw = data.get("raw_output", "")
    if raw:
        entry["preview"] = raw[:500]

    return entry


def _find_related_artifact_ids(target: Any, all_artifacts: list[Any]) -> list[str]:
    """Find artifact IDs related to the target by shared evidence path or family."""
    try:
        target_data = json.loads(target.data_json) if target.data_json else {}
    except (json.JSONDecodeError, TypeError):
        target_data = {}

    target_path = target_data.get("file_path") or target_data.get("evidence_path", "")
    related: list[str] = []

    for art in all_artifacts:
        if art.id == target.id:
            continue
        if art.artifact_family == target.artifact_family and art.id not in related:
            try:
                art_data = json.loads(art.data_json) if art.data_json else {}
            except (json.JSONDecodeError, TypeError):
                art_data = {}
            art_path = art_data.get("file_path") or art_data.get("evidence_path", "")
            if target_path and art_path and target_path == art_path:
                related.append(art.id)

    return related[:20]


def _walk_string_values(
    data: Any,
    path: str = "",
) -> list[tuple[str, str]]:
    """Yield ``(json_path, stringified_value)`` for every leaf value in ``data``.

    Skips keys in ``_REASON_SKIP_KEYS`` so schema markers (e.g. the
    ``suspicious_reasons`` list every enriched record carries) don't
    trigger false keyword matches. Also skips any leaf whose **final** path
    segment is a scanner-metadata key (``plugin``, ``query_function``, etc.)
    — those name the collector, not the evidence.
    """
    out: list[tuple[str, str]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k in _REASON_SKIP_KEYS:
                continue
            child_path = f"{path}.{k}" if path else k
            out.extend(_walk_string_values(v, child_path))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            out.extend(_walk_string_values(v, f"{path}[{i}]"))
    elif isinstance(data, str):
        if data and not _path_is_scanner_metadata(path):
            out.append((path, data))
    elif isinstance(data, (int, float, bool)) and not _path_is_scanner_metadata(path):
        out.append((path, str(data)))
    return out


def _path_is_scanner_metadata(path: str) -> bool:
    """True when the last path segment names the scanner/collector, not the data."""
    if not path:
        return False
    last = path.rsplit(".", 1)[-1]
    # Drop a trailing [idx] suffix before comparing.
    if "[" in last:
        last = last.split("[", 1)[0]
    return last in _REASON_SKIP_PATH_SEGMENTS


def _find_keyword_matches(
    data: Any,
) -> dict[str, list[dict[str, str]]]:
    """Scan real string values for each boost keyword.

    Returns ``{keyword: [{"path": ..., "excerpt": ...}, ...]}`` with at most
    three concrete matches per keyword. Uses the precompiled regex patterns
    from ``_SCORE_BOOST_KEYWORDS`` so short / ambiguous keywords only match
    on word boundaries, not inside random substrings.
    """
    leaves = _walk_string_values(data)
    matches: dict[str, list[dict[str, str]]] = {}
    for display, pattern, _boost in _SCORE_BOOST_KEYWORDS:
        hits: list[dict[str, str]] = []
        for path, value in leaves:
            m = pattern.search(value)
            if m is None:
                continue
            idx = m.start()
            match_len = m.end() - m.start()
            start = max(0, idx - 40)
            end = min(len(value), idx + match_len + 80)
            excerpt = value[start:end]
            if start > 0:
                excerpt = "…" + excerpt
            if end < len(value):
                excerpt = excerpt + "…"
            if len(excerpt) > _MATCH_EXCERPT_LEN:
                excerpt = excerpt[:_MATCH_EXCERPT_LEN] + "…"
            hits.append({"path": path, "excerpt": excerpt})
            if len(hits) >= 3:
                break
        if hits:
            matches[display] = hits
    return matches


def _score_investigator_artifact(artifact: Any) -> float:
    """Score an artefact the investigator itself emitted.

    The investigator writes artefacts on submit / per-turn; each carries
    the agent's own confidence signal in ``data`` (typed fields like
    ``confidence``, ``severity``, ``role``, ``is_final``). We map those
    into a 0-100 score — never scrape raw strings for keyword heuristics.
    """
    try:
        data = json.loads(artifact.data_json) if artifact.data_json else {}
    except (json.JSONDecodeError, TypeError):
        data = {}

    # Investigation-level summary rows (written when the agent submits)
    # are the headline leads of a case.
    if artifact.artifact_type in ("investigation_summary", "final_answer"):
        conf = str(data.get("confidence") or "").lower()
        return {"exact": 95.0, "strong": 85.0,
                "medium": 65.0, "caveated": 45.0}.get(conf, 50.0)

    # Typed agent observations — the investigator emits these with an
    # explicit severity/role hint. Keep the ranges modest so a single
    # noisy hypothesis doesn't outscore a confirmed submit row.
    severity = str(data.get("severity") or "").lower()
    severity_score = {"critical": 70.0, "high": 55.0,
                      "medium": 40.0, "low": 25.0, "info": 15.0}.get(severity, 0.0)
    if severity_score:
        return severity_score

    # IOC observations — score by count of the concrete things the
    # investigator saw, capped so a dump of 500 IPs doesn't swamp the
    # panel.
    n_ips = len(data.get("ips") or [])
    n_urls = len(data.get("urls") or [])
    n_domains = len(data.get("domains") or [])
    n_hashes = len(data.get("hashes") or [])
    ioc_count = n_ips + n_urls + n_domains + n_hashes
    if ioc_count > 0:
        return min(25.0 + ioc_count * 3.0, 70.0)

    # Everything else the investigator wrote still matters, but not
    # strongly enough to crowd the top of the panel.
    return 15.0


def _build_investigator_reason(
    artifact: Any, score: float,
) -> tuple[str, list[dict[str, str]]]:
    """Build a human-readable lead reason from an investigator-emitted row."""
    try:
        data = json.loads(artifact.data_json) if artifact.data_json else {}
    except (json.JSONDecodeError, TypeError):
        data = {}

    atype = artifact.artifact_type
    family = artifact.artifact_family
    evidence: list[dict[str, str]] = []

    if atype in ("investigation_summary", "final_answer"):
        q = str(data.get("question") or "")[:180]
        a = str(data.get("answer") or "")[:200]
        conf = str(data.get("confidence") or "").lower() or "unknown"
        inv = str(data.get("investigation_id") or artifact.source_investigation_id or "")[:8]
        parts = [f"Investigator concluded ({conf}, score {score:.0f})"]
        if q:
            parts.append(f"Q: {q}")
        if a:
            parts.append(f"A: {a}")
        if inv:
            parts.append(f"inv={inv}")
        primary = str(data.get("provenance", {}).get("primary_artifact") or "")
        if primary:
            evidence.append({
                "keyword": "primary_artifact",
                "path": "provenance.primary_artifact",
                "excerpt": primary[:240],
            })
        return "; ".join(parts), evidence

    # Typed agent observation (process_injection, persistence_finding,
    # ioc_observation, lnk_dropper, trigger_artifact, etc.)
    severity = str(data.get("severity") or "").lower()
    headline = (
        str(data.get("headline") or data.get("description")
            or data.get("summary") or data.get("answer") or "")[:220]
    )
    evidence_path = (
        str(data.get("primary_artifact") or data.get("evidence_path")
            or data.get("path") or "")
    )
    parts = [f"{family}/{atype} · investigator observation (score {score:.0f})"]
    if severity:
        parts.append(f"severity={severity}")
    if headline:
        parts.append(headline)
    if evidence_path:
        evidence.append({
            "keyword": "evidence_path",
            "path": "data.evidence_path",
            "excerpt": evidence_path[:240],
        })

    # Roll up short IOC samples when present.
    for key, label in (("ips", "IPs"), ("urls", "URLs"),
                       ("domains", "domains"), ("hashes", "hashes")):
        arr = data.get(key) or []
        if arr:
            sample = ", ".join(str(x)[:60] for x in arr[:3])
            parts.append(f"{len(arr)} {label} (e.g. {sample})")
            for item in arr[:3]:
                evidence.append({
                    "keyword": key[:-1] if key.endswith("s") else key,
                    "path": f"data.{key}",
                    "excerpt": str(item)[:160],
                })

    return "; ".join(parts), evidence


def _score_artifact(artifact: Any) -> float:
    """Compute a lead score for an artifact based on family and data content.

    Only counts a keyword if it appears in actual string *values* — not key
    names or schema markers — so the reason we report to the analyst is the
    same thing we scored on.
    """
    score = _SUSPICIOUS_INDICATORS.get(artifact.artifact_family, 10.0)

    try:
        data = json.loads(artifact.data_json) if artifact.data_json else {}
    except (json.JSONDecodeError, TypeError):
        data = {}

    matches = _find_keyword_matches(data)
    for display, _pattern, boost in _SCORE_BOOST_KEYWORDS:
        if display in matches:
            score += boost

    if data.get("ips"):
        score += 10.0
    if data.get("urls"):
        score += 10.0
    if data.get("win_apis"):
        score += 15.0

    return min(score, 100.0)


def _build_reason(artifact: Any, score: float) -> tuple[str, list[dict[str, str]]]:
    """Generate a concrete reason for a lead promotion.

    Returns ``(reason_text, evidence_matches)``. ``evidence_matches`` is a
    flat list of ``{keyword, path, excerpt}`` dicts the UI can render so the
    analyst sees *what* matched, *where*, and the *actual text* from the
    artifact — not a vague "contains 'c2' indicator".
    """
    family = artifact.artifact_family
    atype = artifact.artifact_type
    parts = [f"{family}/{atype} artifact (score: {score:.1f})"]

    try:
        data = json.loads(artifact.data_json) if artifact.data_json else {}
    except (json.JSONDecodeError, TypeError):
        data = {}

    evidence: list[dict[str, str]] = []
    matches = _find_keyword_matches(data)
    for display, _pattern, _boost in _SCORE_BOOST_KEYWORDS:
        hits = matches.get(display)
        if not hits:
            continue
        primary = hits[0]
        parts.append(
            f"'{display}' matched at {primary['path']} → \"{primary['excerpt']}\""
        )
        for h in hits:
            evidence.append({
                "keyword": display,
                "path": h["path"],
                "excerpt": h["excerpt"],
            })

    if data.get("ips"):
        sample = ", ".join(str(x) for x in data["ips"][:3])
        parts.append(f"{len(data['ips'])} IPs extracted (e.g. {sample})")
    if data.get("urls"):
        sample = ", ".join(str(x) for x in data["urls"][:2])
        parts.append(f"{len(data['urls'])} URLs extracted (e.g. {sample})")
    if data.get("win_apis"):
        sample = ", ".join(str(x) for x in data["win_apis"][:3])
        parts.append(f"{len(data['win_apis'])} suspicious APIs (e.g. {sample})")

    return "; ".join(parts), evidence


state_promotion.parallel_safe = state_promotion_parallel_safe  # type: ignore[attr-defined]
state_promotion.writes_fields = state_promotion_writes_fields  # type: ignore[attr-defined]
