from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from aila.platform.services.sandbox.backends.oci_egress import (
    build_nft_script,
    scoped_conntrack_collector,
)
from aila.platform.services.sandbox.backends.oci_flow import (
    ConntrackFlowLedger,
    OciFlowContext,
    OciFlowEvent,
    OciFlowTelemetry,
    OciFlowTerminalResult,
    OciTelemetryMode,
    conntrack_mark_for_run,
    parse_conntrack_event,
)
from aila.platform.services.sandbox.contracts import (
    SandboxEgressDestination,
    SandboxEgressPolicy,
    SandboxExecutionError,
)

_RUN = "run-one"
_OTHER_RUN = "run-two"
_MARK = conntrack_mark_for_run(_RUN)
_OTHER_MARK = conntrack_mark_for_run(_OTHER_RUN)
_NOW = datetime(2025, 1, 1, tzinfo=UTC)
_CONTEXT = OciFlowContext(
    fingerprint="fp-0123456789",
    campaign_id="camp-1",
    action_id="act-1",
    request_id="req-1",
    destination_asset_id="asset-1",
    sandbox_identity="sbx-1",
)
_START_TS = "1700000000.000000"
_END_TS = "1700000005.000000"


def _tcp(
    kind: str,
    cid: int,
    *,
    state: str = "ESTABLISHED",
    ob: int | str = 0,
    rb: int | str = 0,
    mark: int = _MARK,
    sport: int = 40000,
    dport: int = 443,
    ts: str = _START_TS,
) -> str:
    return (
        f"[{ts}] [{kind}] tcp      6 120 {state} src=10.0.0.2 dst=192.0.2.10 "
        f"sport={sport} dport={dport} packets=1 bytes={ob} "
        f"src=192.0.2.10 dst=10.0.0.2 sport={dport} dport={sport} packets=1 bytes={rb} "
        f"mark={mark} id={cid}"
    )


def _udp(
    kind: str,
    cid: int,
    *,
    rb: int = 0,
    assured: bool = False,
    mark: int = _MARK,
    ts: str = _START_TS,
) -> str:
    flag = " [ASSURED]" if assured else ""
    return (
        f"[{ts}] [{kind}] udp      17 30 src=10.0.0.2 dst=192.0.2.10 "
        f"sport=50000 dport=53 packets=1 bytes=60 "
        f"src=192.0.2.10 dst=10.0.0.2 sport=53 dport=50000 packets=1 bytes={rb}{flag} "
        f"mark={mark} id={cid}"
    )


def _icmp(kind: str, cid: int, *, ident: int = 1234, mark: int = _MARK, ts: str = _START_TS) -> str:
    return (
        f"[{ts}] [{kind}] icmp     1 29 src=10.0.0.2 dst=192.0.2.10 type=8 code=0 id={ident} "
        f"packets=1 bytes=84 src=192.0.2.10 dst=10.0.0.2 type=0 code=0 id={ident} "
        f"packets=1 bytes=84 mark={mark} id={cid}"
    )


class _Sink:
    def __init__(self, *, delay: float = 0.0, fail: bool = False) -> None:
        self.events: list[OciFlowEvent] = []
        self.healths: list[Any] = []
        self.delay = delay
        self.fail = fail

    async def record_oci_flow(self, event: OciFlowEvent) -> None:
        if self.fail:
            raise RuntimeError("sink unavailable")
        if self.delay:
            await asyncio.sleep(self.delay)
        self.events.append(event)

    async def record_oci_flow_health(self, health: Any) -> None:
        self.healths.append(health)


def _telemetry(sink: _Sink, **overrides: Any) -> OciFlowTelemetry:
    return OciFlowTelemetry(context=_CONTEXT, sink=sink, **overrides)


def _ledger(telemetry: OciFlowTelemetry, *, run_id: str = _RUN, mark: int = _MARK) -> ConntrackFlowLedger:
    return ConntrackFlowLedger(
        telemetry,
        sandbox_run_id=run_id,
        conntrack_mark=mark,
        clock=lambda: _NOW,
    )


def _feed(ledger: ConntrackFlowLedger, *lines: str) -> None:
    for line in lines:
        ledger.feed_line(line)


def test_parse_tcp_udp_and_icmp_events() -> None:
    tcp = parse_conntrack_event(_tcp("NEW", 11, state="SYN_SENT", ob=60, rb=0))
    assert tcp.protocol == "tcp"
    assert (tcp.source_port, tcp.destination_port) == (40000, 443)
    assert (tcp.bytes_sent, tcp.bytes_received) == (60, 0)
    assert tcp.tcp_state == "SYN_SENT"
    assert tcp.conntrack_id == 11

    udp = parse_conntrack_event(_udp("DESTROY", 12, rb=90, assured=True))
    assert udp.protocol == "udp"
    assert (udp.destination_port, udp.bytes_received) == (53, 90)
    assert udp.assured is True
    assert udp.tcp_state is None

    icmp = parse_conntrack_event(_icmp("NEW", 13, ident=777))
    assert icmp.protocol == "icmp"
    assert (icmp.icmp_type, icmp.icmp_code, icmp.icmp_identifier) == (8, 0, 777)
    assert icmp.source_port is None and icmp.destination_port is None


def test_foreign_mark_is_ignored_and_chunk_boundaries_are_respected() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        foreign = _tcp("NEW", 21, mark=_OTHER_MARK)
        own_new = _tcp("NEW", 22)
        own_destroy = _tcp("DESTROY", 22, state="TIME_WAIT", ts=_END_TS)
        stream = foreign + "\n" + own_new + "\n" + own_destroy + "\n"
        # Split at arbitrary points to prove the buffer reassembles lines.
        for start in range(0, len(stream), 37):
            ledger.feed_chunk(stream[start : start + 37])
        health = await ledger.finish()
        assert health.received_events == 2
        assert health.malformed_events == 0
        assert health.emitted_events == 1
        assert [event.conntrack_id for event in sink.events] == [22]

    asyncio.run(run())


def test_interleaved_runs_each_receive_only_their_own_flows() -> None:
    sink = _Sink()
    first = _ledger(_telemetry(sink), run_id=_RUN, mark=_MARK)
    second = _ledger(_telemetry(sink), run_id=_OTHER_RUN, mark=_OTHER_MARK)
    stream = [
        _tcp("NEW", 31, mark=_MARK),
        _tcp("NEW", 32, mark=_OTHER_MARK, sport=40010),
        _tcp("DESTROY", 31, state="TIME_WAIT", ts=_END_TS, mark=_MARK),
        _tcp("DESTROY", 32, state="TIME_WAIT", ts=_END_TS, mark=_OTHER_MARK, sport=40010),
    ]

    async def run() -> None:
        await first.start()
        await second.start()
        for line in stream:
            half = len(line) // 2
            for ledger in (first, second):
                ledger.feed_chunk(line[:half])
                ledger.feed_chunk(line[half:] + "\n")
        await first.finish()
        await second.finish()
        by_run = {event.sandbox_run_id: event.conntrack_mark for event in sink.events}
        assert by_run == {_RUN: _MARK, _OTHER_RUN: _OTHER_MARK}
        assert len(sink.events) == 2

    asyncio.run(run())


def test_bytes_are_cumulative_not_double_counted() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        _feed(
            ledger,
            _tcp("NEW", 41, ob=0, rb=0),
            _tcp("UPDATES", 41, ob=100, rb=50),
            _tcp("UPDATES", 41, ob=80, rb=50),  # stale counter must not reduce the total
            _tcp("DESTROY", 41, state="TIME_WAIT", ob=250, rb=120, ts=_END_TS),
        )
        health = await ledger.finish()
        assert health.emitted_events == 1
        (event,) = sink.events
        assert (event.bytes_sent, event.bytes_received) == (250, 120)
        assert event.terminal_result is OciFlowTerminalResult.SUCCEEDED
        assert event.attribution_mode is OciTelemetryMode.ENFORCE
        assert event.ended_at > event.started_at

    asyncio.run(run())


def test_terminal_result_mapping() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        _feed(
            ledger,
            _tcp("NEW", 51, state="SYN_SENT", sport=41001),
            _tcp("DESTROY", 51, state="SYN_SENT", ts=_END_TS, sport=41001),
            _tcp("NEW", 52, sport=41002),
            _tcp("DESTROY", 52, state="CLOSE", rb=30, ts=_END_TS, sport=41002),
            _udp("NEW", 53),
            _udp("DESTROY", 53, ts=_END_TS),
            _udp("NEW", 54),
            _udp("DESTROY", 54, rb=40, assured=True, ts=_END_TS),
        )
        await ledger.finish()
        results = {event.conntrack_id: event.terminal_result for event in sink.events}
        assert results == {
            51: OciFlowTerminalResult.TIMED_OUT,
            52: OciFlowTerminalResult.RESET,
            53: OciFlowTerminalResult.TIMED_OUT,
            54: OciFlowTerminalResult.SUCCEEDED,
        }

    asyncio.run(run())


def test_malformed_lines_are_counted_and_never_emitted() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))
    no_reply_tuple = (
        f"[{_START_TS}] [NEW] tcp 6 120 ESTABLISHED src=10.0.0.2 dst=192.0.2.10 "
        f"sport=1 dport=2 packets=1 bytes=1 mark={_MARK} id=61"
    )
    bad_counter = _tcp("NEW", 62, ob="x")
    unknown_state = _tcp("NEW", 63, state="WEIRD")
    oversize = f"[{_START_TS}] [NEW] " + "x" * (70 * 1024)
    bad_timestamp = _tcp("NEW", 64).replace(f"[{_START_TS}]", "[notatime]", 1)

    async def run() -> None:
        await ledger.start()
        _feed(ledger, no_reply_tuple, bad_counter, unknown_state, oversize, bad_timestamp)
        health = await ledger.finish()
        assert health.malformed_events == 5
        assert health.received_events == 0
        assert health.emitted_events == 0
        assert sink.events == []
        assert health.status == "degraded"

    asyncio.run(run())


def test_update_or_destroy_without_new_is_out_of_order() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        _feed(ledger, _tcp("UPDATES", 71, ob=10), _tcp("DESTROY", 71, state="TIME_WAIT", ts=_END_TS))
        health = await ledger.finish()
        assert health.out_of_order_events == 2
        assert health.emitted_events == 0
        assert sink.events == []
        assert health.status == "degraded"

    asyncio.run(run())


def test_conntrack_id_reuse_with_new_tuple_emits_old_flow_as_cancelled() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        _feed(
            ledger,
            _tcp("NEW", 81, sport=40000),
            _tcp("NEW", 81, sport=40001),
        )
        health = await ledger.finish()
        # One cancelled by ID reuse, one flushed by finish().
        assert health.cancelled_flows == 2
        assert [event.source_port for event in sink.events] == [40000, 40001]
        assert all(event.terminal_result is OciFlowTerminalResult.CANCELLED for event in sink.events)

    asyncio.run(run())


def test_backpressure_drops_are_counted_with_high_watermark() -> None:
    sink = _Sink(delay=0.05)
    ledger = _ledger(_telemetry(sink, queue_capacity=1))

    async def run() -> None:
        await ledger.start()
        # All three terminal events are offered before the sink worker gets a turn.
        for cid in (91, 92, 93):
            _feed(ledger, _tcp("NEW", cid), _tcp("DESTROY", cid, state="TIME_WAIT", ts=_END_TS))
        health = await ledger.finish()
        assert health.dropped_events == 2
        assert health.queue_high_watermark == 1
        assert health.emitted_events == 1
        assert len(sink.events) == 1
        assert health.status == "degraded"

    asyncio.run(run())


def test_sink_failure_and_timeout_are_counted() -> None:
    failing = _Sink(fail=True)
    failing_ledger = _ledger(_telemetry(failing))
    slow = _Sink(delay=1.0)
    slow_ledger = _ledger(_telemetry(slow, sink_timeout_s=0.01), run_id="run-slow")

    async def run() -> None:
        await failing_ledger.start()
        _feed(failing_ledger, _tcp("NEW", 101), _tcp("DESTROY", 101, state="TIME_WAIT", ts=_END_TS))
        failed = await failing_ledger.finish()
        assert failed.sink_failures == 1
        assert failed.emitted_events == 0
        assert failed.status == "degraded"

        await slow_ledger.start()
        _feed(slow_ledger, _tcp("NEW", 102), _tcp("DESTROY", 102, state="TIME_WAIT", ts=_END_TS))
        timed_out = await slow_ledger.finish()
        assert timed_out.sink_failures == 1
        assert timed_out.emitted_events == 0
        assert timed_out.status == "degraded"

    asyncio.run(run())


def test_finish_flushes_open_flows_as_cancelled() -> None:
    sink = _Sink()
    ledger = _ledger(_telemetry(sink))

    async def run() -> None:
        await ledger.start()
        _feed(ledger, _tcp("NEW", 111), _tcp("UPDATES", 111, ob=10, rb=5))
        health = await ledger.finish()
        assert health.emitted_events == 1
        (event,) = sink.events
        assert event.terminal_result is OciFlowTerminalResult.CANCELLED
        assert (event.bytes_sent, event.bytes_received) == (10, 5)
        assert health.status == "healthy"

    asyncio.run(run())


def test_nft_script_without_mark_has_no_conntrack_rules() -> None:
    policy = SandboxEgressPolicy(
        destinations=[SandboxEgressDestination(address="192.0.2.10", port=443, protocol="tcp")]
    )
    bridge = "ailaabcdef12345"
    default = build_nft_script("abcdef1234567890", policy, bridge)
    explicit_none = build_nft_script("abcdef1234567890", policy, bridge, conntrack_mark=None)
    assert default == explicit_none
    assert "ct mark set" not in default

    marked = build_nft_script("abcdef1234567890", policy, bridge, conntrack_mark=_MARK)
    assert f"ct mark set {_MARK}" in marked


def test_enforce_collector_unavailable_raises_before_body_runs() -> None:
    ssh = _CollectorSSH()
    ledger = _ledger(_telemetry(_Sink(), mode=OciTelemetryMode.ENFORCE))
    body_ran = False

    async def run() -> None:
        nonlocal body_ran
        async with scoped_conntrack_collector(
            ssh,  # type: ignore[arg-type]
            object(),
            sudo="/usr/bin/sudo",
            conntrack="/usr/sbin/conntrack",
            ledger=ledger,
            run_id=_RUN,
            conntrack_mark=_MARK,
            enforce=True,
            timeout_seconds=30.0,
        ):
            body_ran = True

    with pytest.raises(SandboxExecutionError, match="flow telemetry unavailable"):
        asyncio.run(run())
    assert body_ran is False


def test_audit_collector_unavailable_proceeds_with_unavailable_health() -> None:
    ssh = _CollectorSSH()
    ledger = _ledger(_telemetry(_Sink(), mode=OciTelemetryMode.AUDIT))
    body_ran = False

    async def run() -> None:
        nonlocal body_ran
        async with scoped_conntrack_collector(
            ssh,  # type: ignore[arg-type]
            object(),
            sudo="/usr/bin/sudo",
            conntrack="/usr/sbin/conntrack",
            ledger=ledger,
            run_id=_RUN,
            conntrack_mark=_MARK,
            enforce=False,
            timeout_seconds=30.0,
        ):
            body_ran = True
        health = await ledger.finish()
        assert health.status == "unavailable"
        assert health.fault == "collector_unavailable"

    asyncio.run(run())
    assert body_ran is True


class _CollectorSSH:
    """Collector stream that exits immediately without emitting the readiness sentinel."""

    async def run_command_streaming(
        self,
        integration: Any,
        command: str,
        *,
        timeout_seconds: float,
        on_stdout: Any,
        on_stderr: Any,
        cancel_command: str | None = None,
        **_: Any,
    ) -> None:
        del integration, command, timeout_seconds, on_stdout, on_stderr, cancel_command
