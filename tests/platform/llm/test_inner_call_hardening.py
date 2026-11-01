"""#287 / #288 / #289: module attribution, per-investigation cost and sealed nested calls.

* #287 -- ``module_id`` is stamped on the ``LLMCostRecord`` row, the ``gen_ai``
  span and the ``llm.call.completed`` event; a call outside any module runtime
  carries the ``_no_module`` sentinel instead of failing.
* #288 -- a call made inside an investigation's correlation scope carries that
  investigation's id as ``run_id`` even when the caller omitted it, so the rows
  the ledger holds reconcile with ``compute_live_investigation_cost`` and the
  in-memory ``CostTracker``; ``_no_run`` stays for genuinely global calls.
* #289 -- ``AilaLLMClient._inner_call`` (gate consensus, verify second opinion)
  runs the nested pipeline: it writes an ``AuditSealRecord``, opens a span and
  feeds the drift tracker. An AST guard pins that no model call can bypass the
  pipeline again.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import select

import aila.platform.llm.client as client_module
from aila.platform.events.domain_events import LlmCallCompletedPayload
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.correlation import (
    NO_MODULE,
    correlation_scope,
    current_module_id,
    resolve_run_id,
)
from aila.platform.llm.cost import CostTracker
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.drift import DriftResult
from aila.platform.llm.pipeline import NESTED_SKIPPED_STEPS, PipelineRunner
from aila.platform.llm.run_memory import RunMemory
from aila.platform.llm.seal import make_seal_step
from aila.platform.observability import GEN_AI_OPERATION_CHAT, gen_ai_span
from aila.platform.services.investigation_cost import (
    compute_live_investigation_cost,
)
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import AuditSealRecord

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEAL_KEY = "9" * 64
_MESSAGES: list[dict[str, Any]] = [{"role": "user", "content": "test"}]
_ROUTING = LLMRouting(
    model_id="gpt-4o",
    base_url="https://test.example.com",
    api_key="sk-test",
    max_tokens=1000,
    temperature=0.0,
    max_tool_steps=0,
    task_type="scoring",
)


class _AsyncRegistry:
    """Async ConfigRegistry stub -- returns None (schema default) for every key."""

    async def get(self, namespace: str, key: str) -> Any:
        return None


def _make_client() -> AilaLLMClient:
    """Real client with a secret store that can serve the seal HMAC key."""
    secret_store = MagicMock()
    secret_store.resolve_provider_secret = AsyncMock(return_value="sk-test-key")
    secret_store.get_secret_by_key = AsyncMock(return_value=_SEAL_KEY)
    secret_store.upsert_secret = AsyncMock(return_value=None)
    client = AilaLLMClient(registry=_AsyncRegistry(), secret_store=secret_store)  # type: ignore[arg-type]
    client._config.is_disabled = AsyncMock(return_value=False)
    client._config.resolve_routing = AsyncMock(return_value=_ROUTING)
    return client


def _canned_completion(
    content: str = "test response",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Minimal OpenAI completion mock (same shape as test_cost_client_wiring)."""
    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    usage.total_tokens = prompt_tokens + completion_tokens

    message = MagicMock()
    message.content = content
    message.tool_calls = []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = "stop"

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage
    return completion


@contextmanager
def _provider_returning(*completions: MagicMock) -> Generator[AsyncMock]:
    """Patch the SDK client so each provider call pops the next completion."""
    with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
        instance = AsyncMock()
        instance.chat.completions.create = AsyncMock(side_effect=list(completions))
        mock_oai.return_value = instance
        yield instance


async def _price(
    model_id: str, prompt_tokens: int, completion_tokens: int, registry: Any,
) -> tuple[float, bool]:
    """Deterministic pricing: 0.001 per prompt token, 0.002 per completion token."""
    return (prompt_tokens * 0.001 + completion_tokens * 0.002, True)


class _FakeSpan:
    def __init__(self, name: str, attributes: dict[str, Any] | None) -> None:
        self.name = name
        self.attributes: dict[str, Any] = dict(attributes or {})

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        return None

    def set_status(self, status: Any) -> None:
        return None


class _FakeTracer:
    def __init__(self) -> None:
        self.spans: list[_FakeSpan] = []

    @contextmanager
    def start_as_current_span(
        self, name: str, attributes: dict[str, Any] | None = None,
    ) -> Generator[_FakeSpan]:
        span = _FakeSpan(name, attributes)
        self.spans.append(span)
        yield span


@pytest.fixture()
def tracer() -> Iterator[_FakeTracer]:
    """Turn otel on and capture every span ``gen_ai_span`` opens."""
    fake = _FakeTracer()
    with (
        patch("aila.platform.observability.otel.is_otel_enabled", return_value=True),
        patch("aila.platform.observability.otel._tracer", return_value=fake),
    ):
        yield fake


# ---------------------------------------------------------------------------
# #287 -- module attribution plumbing
# ---------------------------------------------------------------------------


def test_module_is_sentinel_outside_any_scope() -> None:
    assert current_module_id() == NO_MODULE == "_no_module"


def test_nested_scope_inherits_overrides_and_restores_module() -> None:
    with correlation_scope(investigation_id="i", module_id="mod-a"):
        assert current_module_id() == "mod-a"
        # A nested scope that restates only the join keys stays attributed.
        with correlation_scope(investigation_id="i", branch_id="b"):
            assert current_module_id() == "mod-a"
        with correlation_scope(investigation_id="i", module_id="mod-b"):
            assert current_module_id() == "mod-b"
        assert current_module_id() == "mod-a"
    assert current_module_id() == NO_MODULE


def test_llm_call_completed_payload_defaults_to_no_module() -> None:
    payload = LlmCallCompletedPayload(model="m", tokens=1, cost=0.0, duration=0.1)
    assert payload.module_id == NO_MODULE


def test_gen_ai_span_records_module_id(tracer: _FakeTracer) -> None:
    with gen_ai_span(
        GEN_AI_OPERATION_CHAT,
        model="m",
        task_type="scoring",
        run_id="r",
        module_id="mod-a",
    ):
        pass
    assert tracer.spans[0].attributes["aila.module_id"] == "mod-a"
    assert tracer.spans[0].attributes["aila.run_id"] == "r"


@pytest.mark.parametrize(
    ("scope_module", "expected"),
    [("mod-x", "mod-x"), (None, NO_MODULE)],
)
async def test_chat_stamps_module_on_span_and_event(
    tracer: _FakeTracer, scope_module: str | None, expected: str,
) -> None:
    client = _make_client()
    client.bus = MagicMock()
    with (
        _provider_returning(_canned_completion()),
        patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()),
        patch("aila.platform.llm.cost.calculate_cost_usd", _price),
        correlation_scope(investigation_id="inv-ev", module_id=scope_module),
    ):
        await client.chat("scoring", _MESSAGES)

    assert tracer.spans[0].attributes["aila.module_id"] == expected
    client.bus.publish.assert_called_once()
    event = client.bus.publish.call_args.args[0]
    assert event.payload.module_id == expected


# ---------------------------------------------------------------------------
# #288 -- every in-investigation call reconciles across the ledgers
# ---------------------------------------------------------------------------


def test_resolve_run_id_prefers_explicit_then_ambient_investigation() -> None:
    assert resolve_run_id("explicit") == "explicit"
    assert resolve_run_id(None) is None
    with correlation_scope(investigation_id="inv-1"):
        assert resolve_run_id(None) == "inv-1"
        assert resolve_run_id("") == "inv-1"
        assert resolve_run_id("explicit") == "explicit"


@pytest.mark.usefixtures("test_db")
async def test_investigation_ledgers_reconcile_across_every_call_path() -> None:
    """Summed cost rows == live investigation cost == CostTracker; global == _no_run."""
    inv = f"inv-{uuid4().hex}"
    client = _make_client()
    client.cost_tracker = CostTracker(RunMemory(), _AsyncRegistry())  # type: ignore[arg-type]

    in_investigation = [(100, 50), (40, 10), (7, 3)]
    global_call = (11, 5)
    completions = [
        _canned_completion(prompt_tokens=p, completion_tokens=c)
        for p, c in [*in_investigation, global_call]
    ]

    with _provider_returning(*completions), patch(
        "aila.platform.llm.cost.calculate_cost_usd", _price,
    ):
        with correlation_scope(
            investigation_id=inv, branch_id="b1", turn_number=1, module_id="mod-x",
        ):
            # Explicit run_id, then the same call with run_id omitted, then a
            # nested pipeline-step call (gate consensus / verify) with it omitted.
            await client.chat("scoring", _MESSAGES, run_id=inv)
            await client.chat("scoring", _MESSAGES)
            await client._inner_call(routing=_ROUTING, messages=_MESSAGES)
        # Genuinely global: no investigation scope, no run_id.
        await client.chat("scoring", _MESSAGES)

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(select(LLMCostRecord))).all()
        live_cost = await compute_live_investigation_cost(uow, inv)

    in_inv = [r for r in rows if r.run_id == inv]
    no_run = [r for r in rows if r.run_id == "_no_run"]
    assert len(rows) == 4, "every call, nested included, writes exactly one cost row"
    assert len(in_inv) == 3
    assert len(no_run) == 1

    expected_inv_cost = sum(p * 0.001 + c * 0.002 for p, c in in_investigation)
    expected_global_cost = global_call[0] * 0.001 + global_call[1] * 0.002
    assert sum(r.cost_usd for r in in_inv) == pytest.approx(expected_inv_cost)
    assert live_cost == pytest.approx(expected_inv_cost)
    assert sum(r.cost_usd for r in no_run) == pytest.approx(expected_global_cost)
    assert live_cost + sum(r.cost_usd for r in no_run) == pytest.approx(
        sum(r.cost_usd for r in rows),
    )

    tracker = client.cost_tracker
    assert sum(r.prompt_tokens + r.completion_tokens for r in in_inv) == (
        tracker.get_usage(inv)["total_tokens"]
    )
    assert sum(r.prompt_tokens + r.completion_tokens for r in no_run) == (
        tracker.get_usage(None)["total_tokens"]
    )

    assert {r.module_id for r in in_inv} == {"mod-x"}
    assert {r.investigation_id for r in in_inv} == {inv}
    assert [r.module_id for r in no_run] == [NO_MODULE]
    assert no_run[0].investigation_id is None


# ---------------------------------------------------------------------------
# #289 -- a nested call is sealed, spanned and drift-scored
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_inner_call_writes_seal_span_and_drift(tracer: _FakeTracer) -> None:
    inv = f"inv-{uuid4().hex}"
    client = _make_client()
    client.pipeline.register(
        "seal", make_seal_step(config_provider=client._config, emitter=None),
    )
    record_and_check = AsyncMock(
        return_value=DriftResult(
            status="stable", mean=0.8, std_dev=0.0, sample_count=5, alert_fired=False,
        ),
    )
    router = MagicMock()

    with (
        _provider_returning(_canned_completion(content='{"confidence_score": 0.8}')),
        patch(
            "aila.platform.llm.drift.ConfidenceDriftTracker.record_and_check",
            record_and_check,
        ),
        patch(
            "aila.platform.llm.health_router.get_default_health_router",
            return_value=router,
        ),
        patch("aila.platform.llm.cost.calculate_cost_usd", _price),
        correlation_scope(investigation_id=inv, module_id="mod-x"),
    ):
        # run_id omitted: a nested call still carries the investigation id.
        response = await client._inner_call(routing=_ROUTING, messages=_MESSAGES)

    async with UnitOfWork() as uow:
        seals = (
            await uow.session.exec(
                select(AuditSealRecord).where(AuditSealRecord.run_id == inv),
            )
        ).all()
        costs = (
            await uow.session.exec(
                select(LLMCostRecord).where(LLMCostRecord.run_id == inv),
            )
        ).all()
    assert len(seals) == 1
    assert (seals[0].task_type, seals[0].model_id) == ("scoring", "gpt-4o")
    assert response.seal_id == seals[0].seal_hash
    assert [c.module_id for c in costs] == ["mod-x"]

    span = tracer.spans[0]
    assert span.attributes["aila.llm.nested"] is True
    assert span.attributes["aila.module_id"] == "mod-x"
    assert span.attributes["aila.run_id"] == inv

    record_and_check.assert_awaited_once_with(
        target_name=inv, task_type="scoring", confidence_score=0.8,
    )
    router.record_drift.assert_called_once_with("gpt-4o", "scoring", "stable")


class _StepConfig:
    """Config provider stub for a bare PipelineRunner: every step enabled, fail closed."""

    _registry = None

    async def is_step_enabled(self, step: str, task_type: str) -> bool:
        return True

    async def resolve_fail_mode(self, step: str, task_type: str) -> str:
        return "closed"


async def test_nested_run_skips_only_gate_and_verify() -> None:
    ran: list[str] = []

    def _spy(name: str) -> Callable[..., Any]:
        async def _step(ctx: dict[str, Any], messages: Any, routing: Any) -> None:
            ran.append(name)

        return _step

    runner = PipelineRunner(_StepConfig())  # type: ignore[arg-type]
    for name in ("classify", "validate", "gate", "verify", "seal"):
        runner.register(name, _spy(name))

    async def call_fn(**_kwargs: Any) -> Any:
        return SimpleNamespace(content="x", finish_reason="stop", usage={})

    kwargs: dict[str, Any] = {
        "task_type": "scoring",
        "messages": _MESSAGES,
        "routing": _ROUTING,
        "call_fn": call_fn,
        "call_kwargs": {},
    }
    _, primary_ctx = await runner.run(**kwargs)
    assert ran == ["classify", "validate", "gate", "verify", "seal"]
    assert "nested_call" not in primary_ctx

    ran.clear()
    _, nested_ctx = await runner.run(nested=True, **kwargs)
    assert ran == ["classify", "validate", "seal"]
    assert nested_ctx["nested_call"] is True
    assert frozenset({"gate", "verify"}) == NESTED_SKIPPED_STEPS


# ---------------------------------------------------------------------------
# #289 -- no seal-less model-call path remains in the client
# ---------------------------------------------------------------------------


def _functions_containing(
    tree: ast.Module, predicate: Callable[[ast.AST], bool],
) -> set[str]:
    return {
        func.name
        for func in ast.walk(tree)
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(predicate(node) for node in ast.walk(func))
    }


def _is_self_attr(node: ast.AST, attr: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attr
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _is_provider_call(node: ast.AST) -> bool:
    """``<anything>.chat.completions.create`` -- the raw SDK request."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "create"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "completions"
        and isinstance(node.value.value, ast.Attribute)
        and node.value.value.attr == "chat"
    )


def test_provider_is_reachable_only_through_the_pipeline() -> None:
    tree = ast.parse(Path(client_module.__file__).read_text(encoding="utf-8"))

    # Only _single_call (and the tool loop it enters) talk to the provider.
    assert _functions_containing(tree, _is_provider_call) == {"_single_call", "_tool_loop"}
    assert _functions_containing(
        tree, lambda n: _is_self_attr(n, "_tool_loop"),
    ) == {"_single_call"}

    # _single_call is never invoked directly: its only references are the
    # ``call_fn=`` argument of PipelineRunner.run in the two call paths.
    assert not [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _is_self_attr(n.func, "_single_call")
    ]
    pipeline_runs = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "run"
        and _is_self_attr(n.func.value, "_pipeline")
    ]
    handed_over = [
        kw for call in pipeline_runs for kw in call.keywords
        if kw.arg == "call_fn" and _is_self_attr(kw.value, "_single_call")
    ]
    references = [n for n in ast.walk(tree) if _is_self_attr(n, "_single_call")]
    assert len(handed_over) == len(references) == 2
    assert _functions_containing(
        tree, lambda n: _is_self_attr(n, "_single_call"),
    ) == {"_call_with_retry", "_inner_call"}

    # _inner_call takes the nested route; the turn's own call does not.
    def _nested_flags(func_name: str) -> list[ast.keyword]:
        func = next(
            f for f in ast.walk(tree)
            if isinstance(f, ast.AsyncFunctionDef) and f.name == func_name
        )
        return [
            kw for call in ast.walk(func) if isinstance(call, ast.Call)
            for kw in call.keywords if kw.arg == "nested"
        ]

    inner_flags = _nested_flags("_inner_call")
    assert len(inner_flags) == 1
    assert isinstance(inner_flags[0].value, ast.Constant)
    assert inner_flags[0].value.value is True
    assert _nested_flags("_call_with_retry") == []
