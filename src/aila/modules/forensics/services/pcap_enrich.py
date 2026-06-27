"""Pure-Python enrichment helpers for PCAP data pulled off the analyzer.

The network collector shells out to ``tshark`` to get raw fields. This
module takes those rows and turns them into forensically useful signals:

- RFC1918 / loopback detection to separate internal from external hosts.
- TLD classification against a high-signal "suspicious TLD" list used in
  commodity-malware C2 and phishing infrastructure.
- Cheap DGA shape heuristic (consonant runs, entropy proxy) so an
  analyst notices random-looking domains without running a full model.
- Beacon detection from inter-arrival times -- a flow is a beacon
  candidate when it has >= ``MIN_BEACON_FLOWS`` packets, low inter-arrival
  stdev, and the payload sizes are constant or near-constant.
- Suspicious User-Agent pattern matching (living-off-the-land + default
  scanner UAs).
- Aggregations used for both the top-N roll-ups shown in the UI and the
  compact factual summary handed to the LLM commentator.

Everything here is deterministic and has zero network dependencies --
it only transforms data the collector already pulled.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

__all__ = [
    "is_rfc1918",
    "is_loopback_or_multicast",
    "classify_tld",
    "dga_shape_score",
    "is_suspicious_ua",
    "detect_beacons",
    "aggregate_dns",
    "aggregate_hosts",
    "rank_top",
    "build_llm_summary",
]


# -------- IP classification ------------------------------------------------

def is_rfc1918(ip: str) -> bool:
    """Return True if ``ip`` is in a private RFC1918 block."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private and not addr.is_loopback


def is_loopback_or_multicast(ip: str) -> bool:
    """Return True for loopback, link-local, multicast, or reserved."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


# -------- DNS / TLD --------------------------------------------------------

# Common-in-phishing / commodity-C2 TLDs as observed by the major threat
# intel outfits (Spamhaus, Abuse.ch, Cisco Umbrella "badness"). Not a
# blocklist -- just enough signal to raise eyebrows in a report.
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "work",
    "click", "fit", "loan", "men", "kim", "cam", "rest", "country",
    "pw", "cc", "buzz", "rest", "support", "win", "party", "bid",
    "bar", "casa", "cyou", "monster", "quest", "surf", "mom", "sbs",
})


def classify_tld(qname: str) -> str:
    """Return ``"common" | "suspicious" | "dga_shape" | "empty"``."""
    if not qname:
        return "empty"
    q = qname.rstrip(".").lower()
    tld = q.rsplit(".", 1)[-1] if "." in q else q
    if tld in _SUSPICIOUS_TLDS:
        return "suspicious"
    if dga_shape_score(q) >= 0.6:
        return "dga_shape"
    return "common"


_VOWELS = set("aeiouy")


def dga_shape_score(qname: str) -> float:
    """Rough DGA-shape score in ``[0, 1]``.

    Blends three cheap signals on the second-level label:
    - character entropy (random strings push this higher),
    - ratio of consonant run lengths > 3 (e.g. ``xqzprmn``),
    - absence of digits *and* absence of recognizable English bigrams.

    Anything above ~0.6 is worth a second look. Below 0.4 is likely
    well-known infra. This is an analyst hint, not a verdict.
    """
    if not qname:
        return 0.0
    labels = qname.rstrip(".").split(".")
    if len(labels) < 2:
        label = labels[0]
    else:
        label = labels[-2]  # second-level domain
    label = re.sub(r"[^a-z0-9-]", "", label.lower())
    if len(label) < 6:
        return 0.0

    # Shannon entropy on the label alphabet.
    counts: dict[str, int] = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(label)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # English second-level labels sit around 3.0-3.5, DGA labels around
    # 4.0-4.5. Normalize to ~[0,1] across the span we care about.
    entropy_score = max(0.0, min(1.0, (entropy - 3.0) / 2.0))

    # Long consonant runs.
    cons_run = 0
    max_cons_run = 0
    for ch in label:
        if ch.isalpha() and ch not in _VOWELS:
            cons_run += 1
            max_cons_run = max(max_cons_run, cons_run)
        else:
            cons_run = 0
    cons_score = max(0.0, min(1.0, (max_cons_run - 3) / 5.0))

    # Vowel ratio; DGAs often vowel-poor.
    vowels = sum(1 for ch in label if ch in _VOWELS)
    vowel_ratio = vowels / max(1, len(label))
    vowel_score = max(0.0, min(1.0, (0.25 - vowel_ratio) * 4.0))

    return 0.5 * entropy_score + 0.3 * cons_score + 0.2 * vowel_score


# -------- HTTP user agents -------------------------------------------------

_SUSPICIOUS_UA_PATTERNS: tuple[tuple[str, str], ...] = (
    ("empty_ua", r"^\s*$"),
    ("curl", r"(?i)\bcurl/"),
    ("wget", r"(?i)\bwget/"),
    ("python_requests", r"(?i)python-requests/"),
    ("python_urllib", r"(?i)python-urllib/"),
    ("powershell", r"(?i)(powershell|windowspowershell|mshta)"),
    ("go_http", r"(?i)\bGo-http-client/"),
    ("java", r"(?i)(Java/|Apache-HttpClient/)"),
    ("nmap", r"(?i)(Nmap NSE|ZGrab|masscan)"),
    ("msxmlhttp", r"(?i)(MSXMLHTTP|WinHttp)"),
    ("sqlmap", r"(?i)sqlmap/"),
    ("empire", r"(?i)(Empire|Mozilla/5\.0 \(Windows NT 6\.1; WOW64; Trident/7\.0\)$)"),
)


def is_suspicious_ua(ua: str | None) -> tuple[bool, str | None]:
    """Return ``(is_suspicious, tag)`` for a User-Agent string."""
    if ua is None:
        return True, "missing_ua"
    for tag, pattern in _SUSPICIOUS_UA_PATTERNS:
        if re.search(pattern, ua):
            return True, tag
    return False, None


# -------- Beacon detection -------------------------------------------------

@dataclass(frozen=True, slots=True)
class BeaconCandidate:
    """A flow that looks like beaconing C2 traffic."""
    src: str
    dst: str
    dport: int
    packet_count: int
    mean_interval_s: float
    interval_stdev_s: float
    regularity: float  # 0..1, higher = more regular
    constant_size: bool
    protocol: str


MIN_BEACON_FLOWS = 6


def detect_beacons(
    packet_times_by_flow: dict[tuple[str, str, int, str], list[tuple[float, int]]],
) -> list[BeaconCandidate]:
    """Given ``{(src,dst,dport,proto): [(ts_seconds, size_bytes), ...]}``
    return flows with beacon-like inter-arrival regularity.

    Regularity = ``1 - (stdev / mean)`` clamped to ``[0, 1]``. A flow
    with exactly uniform intervals gets 1.0; a noisy one trends to 0.
    """
    out: list[BeaconCandidate] = []
    for (src, dst, dport, proto), packets in packet_times_by_flow.items():
        if len(packets) < MIN_BEACON_FLOWS:
            continue
        packets_sorted = sorted(packets)
        times = [t for t, _ in packets_sorted]
        sizes = [s for _, s in packets_sorted]
        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) < MIN_BEACON_FLOWS - 1:
            continue
        m = mean(intervals)
        if m <= 0:
            continue
        stdev = pstdev(intervals)
        regularity = max(0.0, min(1.0, 1.0 - (stdev / m)))
        if regularity < 0.6:
            continue
        size_stdev = pstdev(sizes) if len(sizes) > 1 else 0.0
        constant_size = size_stdev < max(32, 0.05 * max(sizes))
        out.append(BeaconCandidate(
            src=src, dst=dst, dport=dport, protocol=proto,
            packet_count=len(packets_sorted),
            mean_interval_s=round(m, 3),
            interval_stdev_s=round(stdev, 3),
            regularity=round(regularity, 3),
            constant_size=constant_size,
        ))
    out.sort(key=lambda b: (b.regularity, b.packet_count), reverse=True)
    return out


# -------- Roll-ups ---------------------------------------------------------

def aggregate_dns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group DNS rows by qname, return enriched summaries."""
    grouped: dict[str, dict[str, Any]] = {}
    for r in rows:
        qname = (r.get("qname") or "").rstrip(".").lower()
        if not qname:
            continue
        g = grouped.setdefault(qname, {
            "qname": qname,
            "qtypes": Counter(),
            "answers": set(),
            "count": 0,
            "first_seen": r.get("ts"),
            "last_seen": r.get("ts"),
            "nxdomain_count": 0,
        })
        g["count"] += 1
        qtype = r.get("qtype") or "A"
        g["qtypes"][qtype] += 1
        if r.get("rcode") == "3":  # NXDOMAIN
            g["nxdomain_count"] += 1
        for ans in (r.get("answers") or []):
            if ans:
                g["answers"].add(ans)
        ts = r.get("ts")
        if ts:
            if not g["first_seen"] or ts < g["first_seen"]:
                g["first_seen"] = ts
            if not g["last_seen"] or ts > g["last_seen"]:
                g["last_seen"] = ts

    out: list[dict[str, Any]] = []
    for qname, g in grouped.items():
        classification = classify_tld(qname)
        out.append({
            "qname": qname,
            "count": g["count"],
            "qtypes": sorted(g["qtypes"].keys()),
            "answers": sorted(g["answers"])[:10],
            "answer_count": len(g["answers"]),
            "first_seen": g["first_seen"],
            "last_seen": g["last_seen"],
            "nxdomain_count": g["nxdomain_count"],
            "classification": classification,
            "dga_score": round(dga_shape_score(qname), 3),
            "tld": qname.rsplit(".", 1)[-1] if "." in qname else qname,
        })
    out.sort(key=lambda d: d["count"], reverse=True)
    return out


def aggregate_hosts(
    session_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Produce per-IP talker table from session rows."""
    hosts: dict[str, dict[str, Any]] = {}
    for s in session_rows:
        src = s.get("src") or ""
        dst = s.get("dst") or ""
        pkts = int(s.get("packets") or 0)
        bts = int(s.get("bytes") or 0)
        if src:
            h = hosts.setdefault(src, {
                "ip": src, "packets_sent": 0, "packets_recv": 0,
                "bytes_sent": 0, "bytes_recv": 0, "flows": 0,
                "peers": set(), "is_internal": is_rfc1918(src),
            })
            h["packets_sent"] += pkts
            h["bytes_sent"] += bts
            h["flows"] += 1
            if dst:
                h["peers"].add(dst)
        if dst:
            h = hosts.setdefault(dst, {
                "ip": dst, "packets_sent": 0, "packets_recv": 0,
                "bytes_sent": 0, "bytes_recv": 0, "flows": 0,
                "peers": set(), "is_internal": is_rfc1918(dst),
            })
            h["packets_recv"] += pkts
            h["bytes_recv"] += bts
            if src:
                h["peers"].add(src)

    out: list[dict[str, Any]] = []
    for ip, h in hosts.items():
        h["peer_count"] = len(h["peers"])
        h.pop("peers", None)
        h["bytes_total"] = h["bytes_sent"] + h["bytes_recv"]
        out.append(h)
    out.sort(key=lambda d: d["bytes_total"], reverse=True)
    return out


def rank_top(rows: list[dict[str, Any]], key: str, n: int = 10) -> list[dict[str, Any]]:
    """Return top-N rows by numeric ``key`` descending."""
    return sorted(rows, key=lambda r: r.get(key) or 0, reverse=True)[:n]


# -------- LLM summary builder ---------------------------------------------

def build_llm_summary(
    stats: dict[str, Any],
    hosts: list[dict[str, Any]],
    dns: list[dict[str, Any]],
    http: list[dict[str, Any]],
    tls: list[dict[str, Any]],
    beacons: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    protocol_hierarchy: list[dict[str, Any]],
) -> str:
    """Compact factual summary for the LLM commentator.

    Keep under ~3k tokens -- pick the top-N per category, leave the raw
    data for the UI. The LLM's job is to narrate *this*, not re-read the
    full dataset.
    """
    lines: list[str] = []
    lines.append("# Capture statistics")
    for k in ("packet_count", "byte_count", "duration_s", "start_time", "end_time"):
        if stats.get(k) is not None:
            lines.append(f"- {k}: {stats[k]}")

    lines.append("\n# Protocol hierarchy (top 10)")
    for p in protocol_hierarchy[:10]:
        lines.append(
            f"- {p.get('protocol','?')}: {p.get('packets',0)} pkts "
            f"({p.get('percent',0)}%)"
        )

    lines.append("\n# Top 10 talkers (by total bytes)")
    for h in hosts[:10]:
        flag = "INTERNAL" if h.get("is_internal") else "external"
        lines.append(
            f"- {h['ip']} [{flag}] peers={h.get('peer_count',0)} "
            f"flows={h.get('flows',0)} "
            f"bytes={h.get('bytes_total',0)}"
        )

    lines.append("\n# Top 15 DNS names (by query count)")
    for d in dns[:15]:
        tag = d.get("classification", "common")
        nx = f" NXDOMAIN×{d['nxdomain_count']}" if d.get("nxdomain_count") else ""
        lines.append(
            f"- {d['qname']} count={d['count']} [{tag}]"
            f" dga_score={d.get('dga_score',0)}{nx}"
        )

    lines.append("\n# HTTP requests (up to 20, with suspicious-UA flags)")
    for h in http[:20]:
        sus = f" SUS={h.get('ua_tag')}" if h.get("is_suspicious_ua") else ""
        lines.append(
            f"- {h.get('method','?')} {h.get('host','?')}{h.get('uri','')}"
            f" ua={(h.get('user_agent') or '')[:80]!r}{sus}"
        )

    lines.append("\n# TLS SNI (top 20 by client-hello count)")
    for t in tls[:20]:
        lines.append(
            f"- sni={t.get('sni','?')} ja3={t.get('ja3','?')[:32]}"
            f" dst={t.get('dst','?')}:{t.get('dport','?')}"
        )

    lines.append("\n# Beacon candidates (regular inter-arrival intervals)")
    if not beacons:
        lines.append("- none detected")
    for b in beacons[:10]:
        lines.append(
            f"- {b['src']} -> {b['dst']}:{b['dport']} "
            f"({b.get('protocol','?')}) "
            f"pkts={b['packet_count']} "
            f"interval={b['mean_interval_s']}s ±{b['interval_stdev_s']}s "
            f"regularity={b['regularity']} const_size={b['constant_size']}"
        )

    lines.append("\n# Anomalies")
    if not anomalies:
        lines.append("- none flagged")
    for a in anomalies[:20]:
        lines.append(
            f"- {a.get('kind','?')} {a.get('detail','')} "
            f"count={a.get('count','?')}"
        )

    return "\n".join(lines)


def group_packets_by_flow(
    rows: list[dict[str, Any]],
) -> dict[tuple[str, str, int, str], list[tuple[float, int]]]:
    """Bucket per-packet rows into ``(src,dst,dport,proto) -> [(ts,size)...]``."""
    out: dict[tuple[str, str, int, str], list[tuple[float, int]]] = defaultdict(list)
    for r in rows:
        try:
            ts = float(r.get("ts_epoch") or 0.0)
            sz = int(r.get("size") or 0)
            dport = int(r.get("dport") or 0)
        except (TypeError, ValueError):
            continue
        src = r.get("src") or ""
        dst = r.get("dst") or ""
        proto = r.get("proto") or "tcp"
        if not src or not dst:
            continue
        out[(src, dst, dport, proto)].append((ts, sz))
    return dict(out)
