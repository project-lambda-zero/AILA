"""M3.T-4 -- Capability profile builder orchestrator (run_target_enrichment).

Covers the ``orchestrate_target_enrichment`` helper that sequences
``CapabilityProfileBuilder.build`` then ``FunctionRankingDispatcher.rank``
and folds their outcomes into an ``EnrichmentResult``. The pure
helper is exercised directly with fake builder / dispatcher doubles;
the ``@platform_task`` wrapper (``run_target_enrichment``) does no
additional logic worth testing beyond passing the recorded services in.

Pinned behaviours:
- Sequence: build is awaited BEFORE rank (regressing to parallel would
  drop the profile context ranking now sees).
- Success shape: EnrichmentResult carries the returned profile, the
  target_id, an ISO ``completed_at``, and zero errors.
- Isolation: an exception from one stage is captured as an
  ``EnrichmentError`` entry AND the other stage still runs -- neither
  a wedged profile-build nor a wedged ranker aborts the orchestrator.
"""
from __future__ import annotations

import asyncio

import pytest

from aila.modules.vr.contracts.enrichment import (
    EnrichmentResult,
    TargetCapabilityProfile,
)
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.enrichment.services.function_ranker import (
    FunctionRankerError,
)
from aila.modules.vr.enrichment.services.profile_builder import (
    ProfileBuilderError,
)
from aila.modules.vr.enrichment.workers.orchestrator_worker import (
    orchestrate_target_enrichment,
)


def _profile() -> TargetCapabilityProfile:
    return TargetCapabilityProfile(
        target_kind=TargetKind.NATIVE_BINARY,
        primary_language="c",
    )


class _FakeBuilder:
    def __init__(
        self,
        *,
        returns: TargetCapabilityProfile | None = None,
        raises: BaseException | None = None,
        call_log: list[str] | None = None,
    ) -> None:
        self._returns = returns
        self._raises = raises
        self._call_log = call_log
        self.calls: list[str] = []

    async def build(self, target_id: str) -> TargetCapabilityProfile | None:
        self.calls.append(target_id)
        if self._call_log is not None:
            self._call_log.append("build")
        if self._raises is not None:
            raise self._raises
        return self._returns


class _FakeDispatcher:
    def __init__(
        self,
        *,
        raises: BaseException | None = None,
        call_log: list[str] | None = None,
    ) -> None:
        self._raises = raises
        self._call_log = call_log
        self.calls: list[str] = []

    async def rank(self, target_id: str) -> None:
        self.calls.append(target_id)
        if self._call_log is not None:
            self._call_log.append("rank")
        if self._raises is not None:
            raise self._raises
        return None


@pytest.mark.asyncio
async def test_sequences_build_then_rank_and_returns_result() -> None:
    call_log: list[str] = []
    profile = _profile()
    builder = _FakeBuilder(returns=profile, call_log=call_log)
    dispatcher = _FakeDispatcher(call_log=call_log)

    result = await orchestrate_target_enrichment(
        "tgt-1", builder=builder, dispatcher=dispatcher,
    )

    assert isinstance(result, EnrichmentResult)
    assert result.target_id == "tgt-1"
    assert result.capability_profile == profile
    assert result.errors == []
    assert result.completed_at is not None
    # Build MUST precede rank -- ranking observes the profile persisted
    # by build; regressing to parallel or reversed order would break the
    # observable contract this orchestrator exists for.
    assert call_log == ["build", "rank"]
    assert builder.calls == ["tgt-1"]
    assert dispatcher.calls == ["tgt-1"]


@pytest.mark.asyncio
async def test_profile_error_captured_and_rank_still_runs() -> None:
    call_log: list[str] = []
    builder = _FakeBuilder(
        raises=ProfileBuilderError("audit-mcp wedged"), call_log=call_log,
    )
    dispatcher = _FakeDispatcher(call_log=call_log)

    result = await orchestrate_target_enrichment(
        "tgt-2", builder=builder, dispatcher=dispatcher,
    )

    assert result.capability_profile is None
    # rank was invoked despite build blowing up -- one dead stage MUST
    # NOT abort the other.
    assert dispatcher.calls == ["tgt-2"]
    assert call_log == ["build", "rank"]
    assert len(result.errors) == 1
    (err,) = result.errors
    assert err.step == "capability_profile"
    assert "ProfileBuilderError" in err.message
    assert "audit-mcp wedged" in err.message


@pytest.mark.asyncio
async def test_rank_error_captured_without_masking_profile() -> None:
    profile = _profile()
    builder = _FakeBuilder(returns=profile)
    dispatcher = _FakeDispatcher(
        raises=FunctionRankerError("ida disconnected"),
    )

    result = await orchestrate_target_enrichment(
        "tgt-3", builder=builder, dispatcher=dispatcher,
    )

    # Profile still lands in the result even though ranking failed.
    assert result.capability_profile == profile
    assert len(result.errors) == 1
    (err,) = result.errors
    assert err.step == "function_ranking"
    assert "FunctionRankerError" in err.message
    assert "ida disconnected" in err.message


@pytest.mark.asyncio
async def test_infra_error_captured_as_stage_error() -> None:
    builder = _FakeBuilder(raises=TimeoutError("mcp poll timed out"))
    dispatcher = _FakeDispatcher()

    result = await orchestrate_target_enrichment(
        "tgt-4", builder=builder, dispatcher=dispatcher,
    )

    assert result.capability_profile is None
    assert dispatcher.calls == ["tgt-4"]
    (err,) = result.errors
    assert err.step == "capability_profile"
    assert "TimeoutError" in err.message


@pytest.mark.asyncio
async def test_cancelled_error_propagates() -> None:
    """CancelledError MUST bubble past the orchestrator so ARQ / the
    platform-task wrapper can honour a worker shutdown or timeout kill.
    Capturing it as a stage error would let the orchestrator survive
    its own cancellation and produce a bogus 'success' result."""
    builder = _FakeBuilder(raises=asyncio.CancelledError())
    dispatcher = _FakeDispatcher()

    with pytest.raises(asyncio.CancelledError):
        await orchestrate_target_enrichment(
            "tgt-5", builder=builder, dispatcher=dispatcher,
        )

    # Rank must NOT run once we've been cancelled mid-build.
    assert dispatcher.calls == []
