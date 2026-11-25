"""Bounded conntrack flow telemetry for the remote OCI sandbox backend.

Host dependency: Linux with nf_conntrack/ctnetlink and conntrack-tools whose
``conntrack -E -o timestamp,extended,id -e NEW,UPDATES,DESTROY -m MARK`` output
includes conntrack IDs, marks, timestamps, and per-direction packet/byte
counters. The SSH user needs a narrowly scoped passwordless sudo rule for that
exact event command (and for terminating its per-run PID). No conntrack table
dump, journal, packet payload, or HTTP header is read.

The sink is implemented by the caller (the pentest attribution repository in
production). This platform module deliberately has no module or storage imports.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

__all__ = [
    "ConntrackFlowLedger",
    "OciFlowContext",
    "OciFlowEvent",
    "OciFlowHealth",
    "OciFlowSink",
    "OciFlowTelemetry",
    "OciFlowTerminalResult",
    "OciTelemetryMode",
    "conntrack_mark_for_run",
    "parse_conntrack_event",
]

_MAX_LINE_CHARS = 64 * 1024
_MAX_COUNTER = 2**63 - 1
_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:=~-]{0,127}")
_FINGERPRINT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_EVENT_PREFIX = re.compile(r"^\[(\d+)(?:\.(\d+))?\]\s+\[(NEW|UPDATES|UPDATE|DESTROY)\]\s+")
_SUPPORTED_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6", "ipv6-icmp"})
_TCP_STATES = frozenset(
    {
        "SYN_SENT",
        "SYN_RECV",
        "ESTABLISHED",
        "FIN_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "TIME_WAIT",
        "CLOSE",
    }
)


class OciTelemetryMode(StrEnum):
    ENFORCE = "enforce"
    AUDIT = "audit"
    OFF = "off"


class OciFlowTerminalResult(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    RESET = "reset"


class OciFlowSink(Protocol):
    """Asynchronous boundary implemented by the attribution repository.

    Implementations must not retain mutable collector state. Delivery errors
    are reflected in :class:`OciFlowHealth`; they are never hidden as an empty
    successful flow set.
    """

    async def record_oci_flow(self, event: OciFlowEvent) -> None: ...

    async def record_oci_flow_health(self, health: OciFlowHealth) -> None: ...


@dataclass(frozen=True, slots=True)
class OciFlowContext:
    """Backend-owned opaque lineage attached verbatim to every raw flow."""

    fingerprint: str
    campaign_id: str
    action_id: str
    request_id: str
    destination_asset_id: str
    sandbox_identity: str

    def __post_init__(self) -> None:
        if _FINGERPRINT.fullmatch(self.fingerprint) is None:
            raise ValueError("OCI flow fingerprint must be a bounded opaque token")
        for name in (
            "campaign_id",
            "action_id",
            "request_id",
            "destination_asset_id",
            "sandbox_identity",
        ):
            if _OPAQUE_ID.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"OCI flow {name} must be a bounded opaque identifier")


@dataclass(frozen=True, slots=True)
class OciFlowTelemetry:
    """Runtime-only telemetry configuration; no part is planner-controlled."""

    context: OciFlowContext
    sink: OciFlowSink
    mode: OciTelemetryMode = OciTelemetryMode.ENFORCE
    queue_capacity: int = 1024
    max_active_flows: int = 4096
    sink_timeout_s: float = 2.0
    drain_timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if not 1 <= self.queue_capacity <= 65536:
            raise ValueError("OCI flow queue capacity must be between 1 and 65536")
        if not 1 <= self.max_active_flows <= 65536:
            raise ValueError("OCI flow active-flow bound must be between 1 and 65536")
        if not 0.01 <= self.sink_timeout_s <= 60.0:
            raise ValueError("OCI flow sink timeout must be between 0.01 and 60 seconds")
        if not 0.01 <= self.drain_timeout_s <= 60.0:
            raise ValueError("OCI flow drain timeout must be between 0.01 and 60 seconds")


@dataclass(frozen=True, slots=True)
class OciFlowEvent:
    """One terminal kernel-observed connection, never an application request."""

    connection_id: str
    conntrack_id: int
    conntrack_mark: int
    sandbox_run_id: str
    fingerprint: str
    campaign_id: str
    action_id: str
    request_id: str
    destination_asset_id: str
    sandbox_identity: str
    protocol: str
    source_address: str
    source_port: int | None
    destination_address: str
    destination_port: int | None
    icmp_type: int | None
    icmp_code: int | None
    icmp_identifier: int | None
    started_at: datetime
    ended_at: datetime
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    terminal_result: OciFlowTerminalResult
    conntrack_state: str | None
    attribution_mode: OciTelemetryMode


@dataclass(frozen=True, slots=True)
class OciFlowHealth:
    """Final delivery/collector health, including losses invisible to a flow list."""

    sandbox_run_id: str
    campaign_id: str
    action_id: str
    status: str
    fault: str | None
    started_at: datetime
    ended_at: datetime
    received_events: int
    emitted_events: int
    dropped_events: int
    malformed_events: int
    out_of_order_events: int
    dropped_flows: int
    cancelled_flows: int
    sink_failures: int
    queue_high_watermark: int


@dataclass(frozen=True, slots=True)
class _ConntrackEvent:
    kind: str
    timestamp: datetime
    conntrack_id: int
    mark: int
    protocol: str
    source_address: str
    source_port: int | None
    destination_address: str
    destination_port: int | None
    icmp_type: int | None
    icmp_code: int | None
    icmp_identifier: int | None
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    tcp_state: str | None
    assured: bool


@dataclass(slots=True)
class _OpenFlow:
    first: _ConntrackEvent
    latest: _ConntrackEvent


@dataclass(slots=True)
class _HealthState:
    status: str = "healthy"
    fault: str | None = None
    received_events: int = 0
    emitted_events: int = 0
    dropped_events: int = 0
    malformed_events: int = 0
    out_of_order_events: int = 0
    dropped_flows: int = 0
    cancelled_flows: int = 0
    sink_failures: int = 0
    queue_high_watermark: int = 0


def conntrack_mark_for_run(run_id: str) -> int:
    """Return a stable nonzero 32-bit mark private to this sandbox run."""
    value = int.from_bytes(hashlib.sha256(run_id.encode("ascii")).digest()[:4], "big")
    return value or 1


def _timestamp(seconds: str, fraction: str | None) -> datetime:
    micros = int((fraction or "").ljust(6, "0")[:6] or "0")
    return datetime.fromtimestamp(int(seconds), UTC).replace(microsecond=micros)


def _counter(token: str, name: str) -> int:
    if not token.startswith(f"{name}="):
        raise ValueError(f"missing {name}")
    raw = token.split("=", 1)[1]
    if not raw.isdigit():
        raise ValueError(f"invalid {name}")
    value = int(raw)
    if not 0 <= value <= _MAX_COUNTER:
        raise ValueError(f"out-of-range {name}")
    return value


def _port(tokens: list[str], name: str) -> int:
    matches = [token for token in tokens if token.startswith(f"{name}=")]
    if len(matches) != 1:
        raise ValueError(f"missing or duplicate {name}")
    raw = matches[0].split("=", 1)[1]
    if not raw.isdigit() or not 0 <= int(raw) <= 65535:
        raise ValueError(f"invalid {name}")
    return int(raw)


def _one_named_int(tokens: list[str], name: str, *, maximum: int) -> int:
    matches = [token for token in tokens if token.startswith(f"{name}=")]
    if len(matches) != 1:
        raise ValueError(f"missing or duplicate {name}")
    raw = matches[0].split("=", 1)[1]
    if not raw.isdigit() or not 0 <= int(raw) <= maximum:
        raise ValueError(f"invalid {name}")
    return int(raw)


def _last_named_int(tokens: list[str], name: str, *, maximum: int) -> int:
    matches = [token for token in tokens if token.startswith(f"{name}=")]
    if not matches:
        raise ValueError(f"missing {name}")
    raw = matches[-1].split("=", 1)[1]
    if not raw.isdigit() or not 0 <= int(raw) <= maximum:
        raise ValueError(f"invalid {name}")
    return int(raw)


def _address(tokens: list[str], name: str) -> str:
    matches = [token for token in tokens if token.startswith(f"{name}=")]
    if len(matches) != 1:
        raise ValueError(f"missing or duplicate {name}")
    return ipaddress.ip_address(matches[0].split("=", 1)[1]).compressed


def _direction(tokens: list[str]) -> tuple[int, int]:
    """Return cumulative (packets, bytes) for one conntrack direction."""
    packets = [_counter(token, "packets") for token in tokens if token.startswith("packets=")]
    byte_counts = [_counter(token, "bytes") for token in tokens if token.startswith("bytes=")]
    if len(packets) != 1 or len(byte_counts) != 1:
        raise ValueError("extended conntrack counters are required in both directions")
    return packets[0], byte_counts[0]


def parse_conntrack_event(line: str) -> _ConntrackEvent:
    """Parse one extended conntrack event, raising ``ValueError`` on any ambiguity.

    The final ``id=`` token is the conntrack ID requested by ``-o id``. ICMP's
    echo identifier is read only from the original-direction tuple.
    """
    if len(line) > _MAX_LINE_CHARS:
        raise ValueError("conntrack event exceeds the bounded line size")
    match = _EVENT_PREFIX.match(line)
    if match is None:
        raise ValueError("missing conntrack timestamp or event kind")
    tokens = line[match.end() :].split()
    if len(tokens) < 4:
        raise ValueError("incomplete conntrack event")
    protocol = tokens[0].lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        raise ValueError("unsupported conntrack protocol")
    protocol = "icmpv6" if protocol == "ipv6-icmp" else protocol
    tcp_state = tokens[3] if protocol == "tcp" and len(tokens) > 3 else None
    if protocol == "tcp" and tcp_state not in _TCP_STATES:
        raise ValueError("unknown TCP conntrack state")
    source_indexes = [index for index, token in enumerate(tokens) if token.startswith("src=")]
    if len(source_indexes) != 2:
        raise ValueError("conntrack event must contain original and reply tuples")
    original = tokens[source_indexes[0] : source_indexes[1]]
    reply = tokens[source_indexes[1] :]
    sent_packets, sent_bytes = _direction(original)
    received_packets, received_bytes = _direction(reply)
    source_address = _address(original, "src")
    destination_address = _address(original, "dst")
    # Reply tuples are checked too, rather than being accepted as mere padding.
    _address(reply, "src")
    _address(reply, "dst")
    source_port: int | None = None
    destination_port: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_identifier: int | None = None
    if protocol in {"tcp", "udp"}:
        source_port = _port(original, "sport")
        destination_port = _port(original, "dport")
        _port(reply, "sport")
        _port(reply, "dport")
    else:
        icmp_type = _one_named_int(original, "type", maximum=255)
        icmp_code = _one_named_int(original, "code", maximum=255)
        icmp_identifier = _one_named_int(original, "id", maximum=65535)
    conntrack_id = _last_named_int(tokens, "id", maximum=2**64 - 1)
    mark = _last_named_int(tokens, "mark", maximum=2**32 - 1)
    return _ConntrackEvent(
        kind="UPDATE" if match.group(3) == "UPDATES" else match.group(3),
        timestamp=_timestamp(match.group(1), match.group(2)),
        conntrack_id=conntrack_id,
        mark=mark,
        protocol=protocol,
        source_address=source_address,
        source_port=source_port,
        destination_address=destination_address,
        destination_port=destination_port,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_identifier=icmp_identifier,
        bytes_sent=sent_bytes,
        bytes_received=received_bytes,
        packets_sent=sent_packets,
        packets_received=received_packets,
        tcp_state=tcp_state,
        assured="[ASSURED]" in tokens,
    )


def _same_tuple(left: _ConntrackEvent, right: _ConntrackEvent) -> bool:
    fields = (
        "protocol",
        "source_address",
        "source_port",
        "destination_address",
        "destination_port",
        "icmp_type",
        "icmp_code",
        "icmp_identifier",
    )
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def _merged(latest: _ConntrackEvent, current: _ConntrackEvent) -> _ConntrackEvent:
    """Keep the latest state with monotonic cumulative counters."""
    return _ConntrackEvent(
        kind=current.kind,
        timestamp=current.timestamp,
        conntrack_id=current.conntrack_id,
        mark=current.mark,
        protocol=current.protocol,
        source_address=current.source_address,
        source_port=current.source_port,
        destination_address=current.destination_address,
        destination_port=current.destination_port,
        icmp_type=current.icmp_type,
        icmp_code=current.icmp_code,
        icmp_identifier=current.icmp_identifier,
        bytes_sent=max(latest.bytes_sent, current.bytes_sent),
        bytes_received=max(latest.bytes_received, current.bytes_received),
        packets_sent=max(latest.packets_sent, current.packets_sent),
        packets_received=max(latest.packets_received, current.packets_received),
        tcp_state=current.tcp_state,
        assured=latest.assured or current.assured,
    )


def _terminal_result(flow: _OpenFlow) -> OciFlowTerminalResult:
    event = flow.latest
    if event.protocol == "tcp":
        if event.tcp_state in {"SYN_SENT", "SYN_RECV"} and event.bytes_received == 0:
            return OciFlowTerminalResult.TIMED_OUT
        if event.tcp_state == "CLOSE":
            return (
                OciFlowTerminalResult.RESET
                if event.bytes_received > 0
                else OciFlowTerminalResult.TIMED_OUT
            )
        if event.tcp_state in {"TIME_WAIT", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "ESTABLISHED"}:
            return OciFlowTerminalResult.SUCCEEDED
        return OciFlowTerminalResult.FAILED
    # Transport success is not application success: for datagrams it means the
    # kernel observed a reply/assured flow before destroying the entry.
    if event.assured or event.bytes_received > 0:
        return OciFlowTerminalResult.SUCCEEDED
    return OciFlowTerminalResult.TIMED_OUT


class ConntrackFlowLedger:
    """Aggregate one run's events and deliver terminal records through a bounded queue."""

    def __init__(
        self,
        telemetry: OciFlowTelemetry,
        *,
        sandbox_run_id: str,
        conntrack_mark: int,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        if _OPAQUE_ID.fullmatch(sandbox_run_id) is None:
            raise ValueError("sandbox run id must be a bounded opaque identifier")
        if not 0 < conntrack_mark <= 2**32 - 1:
            raise ValueError("conntrack mark must be a nonzero 32-bit integer")
        self.telemetry = telemetry
        self.sandbox_run_id = sandbox_run_id
        self.conntrack_mark = conntrack_mark
        self._clock = clock
        self._queue: asyncio.Queue[OciFlowEvent] = asyncio.Queue(maxsize=telemetry.queue_capacity)
        self._flows: dict[int, _OpenFlow] = {}
        self._health = _HealthState()
        self._buffer = ""
        self._sink_task: asyncio.Task[None] | None = None
        self._started_at: datetime | None = None
        self._ended_at: datetime | None = None
        self._closed = False

    async def start(self) -> None:
        if self._started_at is not None:
            raise RuntimeError("OCI flow ledger cannot be restarted")
        self._started_at = self._clock()
        self._sink_task = asyncio.create_task(self._drain())

    def note_collector_failure(self, fault: str) -> None:
        """Record a structural fault code, never raw stderr or event content."""
        if self._health.fault is None:
            self._health.fault = fault[:64]
        self._health.status = "unavailable"

    def feed_chunk(self, chunk: str) -> None:
        """Consume arbitrary SSH chunk boundaries without retaining payload data."""
        if self._closed:
            return
        self._buffer += chunk
        while True:
            newline = self._buffer.find("\n")
            if newline < 0:
                break
            line, self._buffer = self._buffer[:newline], self._buffer[newline + 1 :]
            self.feed_line(line.rstrip("\r"))
        if len(self._buffer) > _MAX_LINE_CHARS:
            self._health.malformed_events += 1
            self._health.status = "degraded" if self._health.status == "healthy" else self._health.status
            self._buffer = ""

    def feed_line(self, line: str) -> None:
        if self._closed:
            return
        try:
            event = parse_conntrack_event(line)
        except (ValueError, OverflowError, OSError):
            self._health.malformed_events += 1
            if self._health.status == "healthy":
                self._health.status = "degraded"
            return
        if event.mark != self.conntrack_mark:
            return
        self._health.received_events += 1
        flow = self._flows.get(event.conntrack_id)
        if flow is not None and not _same_tuple(flow.first, event):
            # The kernel reused this ID for another tuple without a DESTROY we
            # observed: the old flow ended without a terminal record. Emit it as
            # cancelled, then treat the new tuple as an independent flow.
            del self._flows[event.conntrack_id]
            self._health.cancelled_flows += 1
            self._offer(self._event(flow, terminal=False))
            flow = None
        if event.kind == "DESTROY":
            if flow is None:
                self._health.out_of_order_events += 1
                if self._health.status == "healthy":
                    self._health.status = "degraded"
                return
            del self._flows[event.conntrack_id]
            flow.latest = _merged(flow.latest, event)
            self._offer(self._event(flow, terminal=True))
            return
        if flow is None:
            if event.kind != "NEW":
                self._health.out_of_order_events += 1
                if self._health.status == "healthy":
                    self._health.status = "degraded"
                return
            if len(self._flows) >= self.telemetry.max_active_flows:
                self._health.dropped_flows += 1
                self._health.dropped_events += 1
                if self._health.status == "healthy":
                    self._health.status = "degraded"
                return
            self._flows[event.conntrack_id] = _OpenFlow(first=event, latest=event)
        else:
            flow.latest = _merged(flow.latest, event)

    def _event(self, flow: _OpenFlow, *, terminal: bool) -> OciFlowEvent:
        context = self.telemetry.context
        latest = flow.latest
        ended_at = max(flow.first.timestamp, latest.timestamp) if terminal else self._clock()
        return OciFlowEvent(
            connection_id=f"{self.sandbox_run_id}:{latest.conntrack_id}",
            conntrack_id=latest.conntrack_id,
            conntrack_mark=latest.mark,
            sandbox_run_id=self.sandbox_run_id,
            fingerprint=context.fingerprint,
            campaign_id=context.campaign_id,
            action_id=context.action_id,
            request_id=context.request_id,
            destination_asset_id=context.destination_asset_id,
            sandbox_identity=context.sandbox_identity,
            protocol=latest.protocol,
            source_address=latest.source_address,
            source_port=latest.source_port,
            destination_address=latest.destination_address,
            destination_port=latest.destination_port,
            icmp_type=latest.icmp_type,
            icmp_code=latest.icmp_code,
            icmp_identifier=latest.icmp_identifier,
            started_at=flow.first.timestamp,
            ended_at=ended_at,
            bytes_sent=latest.bytes_sent,
            bytes_received=latest.bytes_received,
            packets_sent=latest.packets_sent,
            packets_received=latest.packets_received,
            terminal_result=(
                _terminal_result(flow) if terminal else OciFlowTerminalResult.CANCELLED
            ),
            conntrack_state=latest.tcp_state,
            attribution_mode=self.telemetry.mode,
        )

    def _offer(self, event: OciFlowEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._health.dropped_events += 1
            if self._health.status == "healthy":
                self._health.status = "degraded"
        else:
            self._health.queue_high_watermark = max(
                self._health.queue_high_watermark, self._queue.qsize()
            )

    async def _drain(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await asyncio.wait_for(
                    self.telemetry.sink.record_oci_flow(event),
                    timeout=self.telemetry.sink_timeout_s,
                )
            except (TimeoutError, OSError, RuntimeError, ValueError):
                self._health.sink_failures += 1
                if self._health.status == "healthy":
                    self._health.status = "degraded"
            else:
                self._health.emitted_events += 1
            finally:
                self._queue.task_done()

    async def finish(self) -> OciFlowHealth:
        """Flush a bounded final snapshot and stop the sink worker exactly once."""
        if self._ended_at is not None:
            return self._snapshot(self._ended_at)
        if self._started_at is None:
            await self.start()
        self._closed = True
        if self._buffer:
            self._health.malformed_events += 1
            if self._health.status == "healthy":
                self._health.status = "degraded"
            self._buffer = ""
        active = list(self._flows.values())
        self._flows.clear()
        for flow in active:
            self._health.cancelled_flows += 1
            self._offer(self._event(flow, terminal=False))
        await self._drain_bounded()
        ended_at = self._clock()
        self._ended_at = ended_at
        health = self._snapshot(ended_at)
        try:
            await asyncio.wait_for(
                self.telemetry.sink.record_oci_flow_health(health),
                timeout=self.telemetry.sink_timeout_s,
            )
        except (TimeoutError, OSError, RuntimeError, ValueError):
            # A failed health sink cannot recursively report itself. The
            # returned snapshot still exposes the failure to the backend.
            self._health.sink_failures += 1
            if self._health.status == "healthy":
                self._health.status = "degraded"
            health = self._snapshot(ended_at)
        return health

    async def _drain_bounded(self) -> None:
        task = self._sink_task
        if task is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(self._queue.join()), timeout=self.telemetry.drain_timeout_s)
        except TimeoutError:
            remaining = self._queue.qsize()
            self._health.dropped_events += remaining
            self._health.sink_failures += 1
            if self._health.status == "healthy":
                self._health.status = "degraded"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            while True:
                try:
                    self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                else:
                    self._queue.task_done()
        else:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    def _snapshot(self, ended_at: datetime) -> OciFlowHealth:
        if self._started_at is None:
            raise RuntimeError("OCI flow snapshot requested before the ledger started")
        return OciFlowHealth(
            sandbox_run_id=self.sandbox_run_id,
            campaign_id=self.telemetry.context.campaign_id,
            action_id=self.telemetry.context.action_id,
            status=self._health.status,
            fault=self._health.fault,
            started_at=self._started_at,
            ended_at=ended_at,
            received_events=self._health.received_events,
            emitted_events=self._health.emitted_events,
            dropped_events=self._health.dropped_events,
            malformed_events=self._health.malformed_events,
            out_of_order_events=self._health.out_of_order_events,
            dropped_flows=self._health.dropped_flows,
            cancelled_flows=self._health.cancelled_flows,
            sink_failures=self._health.sink_failures,
            queue_high_watermark=self._health.queue_high_watermark,
        )
