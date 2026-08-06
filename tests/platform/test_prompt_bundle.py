"""Tests for RFC-09 Amendment 2: the agent-config bundle.

Covers the five acceptance criteria:

(a) Registering the same body with roster / routing / exemplars produces
    a DIFFERENT content_hash than the same body prompt-only, and the same
    bundle re-registered dedups to the same version via bundle-hash
    uniqueness.
(b) Resolve returns the bundle fields via the store record's
    ``roster_json`` / ``routing_json`` / ``exemplars_json``.
(c) A prompt-only register (empty extras) yields a STABLE, reproducible
    hash and byte-identical body -- the safety invariant that every
    pre-amendment register keeps its current behaviour.
(d) Non-empty exemplars fold into the resolved body when the store path
    is used (via the pinning helper).
(e) The pinned bundle resolves roster / routing from the PINNED version,
    not the live alias, so a live bundle flip does not rewrite the
    routing of an already-running investigation.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.investigation import InvestigationKind
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.llm.config import LLMConfigProvider
from aila.platform.prompts.bundle_ctx import (
    PinnedBundle,
    clear_pinned_bundle,
    current_pinned_bundle,
    set_pinned_bundle,
)
from aila.platform.prompts.pinning import (
    ResolvedBundle,
    resolve_pinned_bundle,
    resolve_pinned_prompt,
)
from aila.platform.prompts.version_models import PromptVersionRecord
from aila.platform.prompts.version_store import (
    PromptVersionStore,
    _canonical_bundle_json,
    _content_hash,
)
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


def _key() -> str:
    return f"platform/bundle-{uuid4().hex[:8]}"


# --- (a) bundle-hash isolation + dedup -------------------------------------


@pytest.mark.asyncio
async def test_bundle_hash_differs_from_prompt_only_hash() -> None:
    """Same body + different extras => different content_hash.

    A prompt-only register and a bundle register on the same body must
    yield DIFFERENT hashes so they are distinct versions -- the extras
    are load-bearing.
    """
    body = "SHARED BODY"
    prompt_only = _content_hash(body)
    with_roster = _content_hash(body, roster={"halvar": {"weight": 1}})
    with_routing = _content_hash(body, routing={"scoring": "openai/gpt-4"})
    with_exemplars = _content_hash(body, exemplars=["ex1"])
    full = _content_hash(
        body,
        roster={"halvar": {"weight": 1}},
        routing={"scoring": "openai/gpt-4"},
        exemplars=["ex1"],
    )
    assert len({prompt_only, with_roster, with_routing, with_exemplars, full}) == 5


@pytest.mark.asyncio
async def test_register_bundle_dedups_on_bundle_hash() -> None:
    """Re-registering an identical bundle returns the SAME version.

    Bundle-hash uniqueness on (key, content_hash) means that
    ``register`` on the same body + roster + routing + exemplars twice
    is a no-op after the first -- no duplicate row is created.
    """
    store = PromptVersionStore()
    key = _key()
    roster = {"halvar": {"weight": 1.0}}
    routing = {"scoring": "openai/gpt-4"}
    exemplars = ["one-shot example"]
    v1 = await store.register(
        key, "BODY", roster=roster, routing=routing, exemplars=exemplars,
    )
    v1_again = await store.register(
        key, "BODY", roster=roster, routing=routing, exemplars=exemplars,
    )
    assert v1 == v1_again
    # A different body OR different extras => new version.
    v2 = await store.register(
        key, "BODY", roster=roster, routing={"scoring": "anthropic/claude-opus-4-7"},
        exemplars=exemplars,
    )
    assert v2 != v1


# --- (c) prompt-only safety invariant --------------------------------------


def test_prompt_only_hash_is_stable_and_reproducible() -> None:
    """Empty extras produce a stable canonical json => stable hash.

    Two invocations on the same body must return the same hash, and the
    canonical json is sorted / separator-normalised so the hash is
    reproducible across processes.
    """
    h1 = _content_hash("HELLO")
    h2 = _content_hash("HELLO", roster=None, routing=None, exemplars=None)
    h3 = _content_hash("HELLO", roster={}, routing={}, exemplars=[])
    assert h1 == h2 == h3
    canonical = _canonical_bundle_json("HELLO", None, None, None)
    assert canonical == json.dumps(
        {"body": "HELLO", "exemplars": [], "roster": {}, "routing": {}},
        sort_keys=True, separators=(",", ":"),
    )


@pytest.mark.asyncio
async def test_prompt_only_register_persists_empty_extras() -> None:
    """A prompt-only register writes ``{}`` / ``{}`` / ``[]`` verbatim.

    The row must be byte-identical to every prior prompt-only register
    (safety invariant) and the resolve path must decode the empties as
    \"no bundle extras\".
    """
    store = PromptVersionStore()
    key = _key()
    v = await store.register(key, "BODY BYTES", author="op")
    async with async_session_scope() as session:
        row = (await session.exec(
            select(PromptVersionRecord).where(
                PromptVersionRecord.key == key,
                PromptVersionRecord.version == v,
            )
        )).first()
    assert row is not None
    assert row.body == "BODY BYTES"
    assert row.roster_json == "{}"
    assert row.routing_json == "{}"
    assert row.exemplars_json == "[]"


# --- (b) resolve returns the bundle fields ---------------------------------


@pytest.mark.asyncio
async def test_resolve_returns_bundle_fields_on_record() -> None:
    """The row read back from the store carries the persisted extras."""
    store = PromptVersionStore()
    key = _key()
    roster = {"halvar": {"weight": 1.0}, "renzo": {"weight": 0.6}}
    routing = {"scoring": "openai/gpt-4", "synthesis": "anthropic/claude-opus-4-7"}
    exemplars = ["exemplar one", {"kind": "structured", "text": "exemplar two"}]
    v = await store.register(
        key, "BODY", author="op",
        roster=roster, routing=routing, exemplars=exemplars,
    )
    row = await store.resolve(key, version=v)
    assert row is not None
    assert json.loads(row.roster_json) == roster
    assert json.loads(row.routing_json) == routing
    assert json.loads(row.exemplars_json) == exemplars


# --- (d) exemplars fold into resolved body ---------------------------------


async def _make_investigation() -> str:
    """Seed workspace + target + investigation, return the investigation id."""
    suffix = uuid4().hex[:8]
    ws_id = f"ws-{suffix}"
    tgt_id = f"tgt-{suffix}"
    inv_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        session.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        await session.flush()
        session.add(VRTargetRecord(
            id=tgt_id, workspace_id=ws_id,
            display_name="tgt", kind="native_binary",
        ))
        await session.flush()
        session.add(VRInvestigationRecord(
            id=inv_id,
            target_id=tgt_id,
            kind=InvestigationKind.AUDIT.value,
            title="test",
            initial_question="",
            status=InvestigationStatus.CREATED.value,
            strategy_family="vulnerability_research.audit",
            prompt_pins_json="{}",
        ))
        await session.commit()
    return inv_id


@pytest.mark.asyncio
async def test_exemplars_fold_into_resolved_body() -> None:
    """When a pinned bundle carries exemplars, they fold into the body.

    The body returned by :func:`resolve_pinned_prompt` must contain the
    original body plus an ``## Exemplars`` section rendering each
    exemplar. Prompt-only bundles keep the body byte-identical.
    """
    clear_pinned_bundle()
    store = PromptVersionStore()
    key = _key()
    exemplars = ["first exemplar", "second exemplar"]
    v = await store.register(key, "BASE BODY", exemplars=exemplars)
    await store.set_alias(key, "production", v)
    inv_id = await _make_investigation()

    body, version = await resolve_pinned_prompt(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert version == v
    assert body is not None
    assert body.startswith("BASE BODY")
    assert "## Exemplars" in body
    assert "first exemplar" in body
    assert "second exemplar" in body


@pytest.mark.asyncio
async def test_prompt_only_bundle_leaves_body_byte_identical() -> None:
    """A prompt-only bundle resolves to the exact base body -- no fold."""
    clear_pinned_bundle()
    store = PromptVersionStore()
    key = _key()
    v = await store.register(key, "BASE BODY ONLY")
    await store.set_alias(key, "production", v)
    inv_id = await _make_investigation()

    body, _version = await resolve_pinned_prompt(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert body == "BASE BODY ONLY"


# --- (e) pin binds bundle -- live alias flip does not reroute --------------


@pytest.mark.asyncio
async def test_pin_binds_bundle_across_live_alias_flip() -> None:
    """A running investigation keeps its pinned bundle's routing / roster
    across a live production-alias flip to a bundle with different extras.

    The pin is per-investigation, per-key: once the investigation resolved
    v1's bundle, a flip to v2 must NOT change the roster / routing this
    investigation resolves on its next turn. A brand-new investigation
    would pick up v2's bundle -- but that path is already covered by
    ``test_second_investigation_gets_the_new_production_version``.
    """
    clear_pinned_bundle()
    store = PromptVersionStore()
    key = _key()
    v1_roster = {"halvar": {"weight": 1.0}}
    v1_routing = {"scoring": "openai/gpt-4"}
    v1 = await store.register(
        key, "BODY V1", roster=v1_roster, routing=v1_routing,
    )
    await store.set_alias(key, "production", v1)

    inv_id = await _make_investigation()
    first = await resolve_pinned_bundle(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert first.version == v1
    assert first.roster == v1_roster
    assert first.routing == v1_routing

    # Operator flips production to v2 with entirely different extras.
    v2_roster = {"renzo": {"weight": 0.9}}
    v2_routing = {"scoring": "anthropic/claude-opus-4-7"}
    v2 = await store.register(
        key, "BODY V2", roster=v2_roster, routing=v2_routing,
    )
    await store.set_alias(
        key, "production", v2, actor="op", reason="cutover",
    )

    # Second turn on the same investigation: still v1's bundle.
    second = await resolve_pinned_bundle(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert second.version == v1
    assert second.roster == v1_roster
    assert second.routing == v1_routing


# --- routing consumption in resolve_model ---------------------------------


class _StubRegistry:
    """Minimal ConfigRegistry stub -- returns None for every get, so the
    resolve_model path lands on its configured default unless the
    bundle-routing override fires first.
    """

    async def get(self, _namespace: str, _key: str) -> None:
        return None


class _StubSecretStore:
    async def resolve_provider_secret(self, _name: str) -> None:
        return None


@pytest.mark.asyncio
async def test_resolve_model_honours_pinned_bundle_routing() -> None:
    """When a pinned bundle carries ``routing[task_type]``, that model wins.

    The registry stub returns None for every lookup so the fallback path
    would ordinarily land on the ultimate default; the bundle-routing
    override must short-circuit before the registry read.
    """
    clear_pinned_bundle()
    provider = LLMConfigProvider(
        registry=_StubRegistry(),  # type: ignore[arg-type]
        secret_store=_StubSecretStore(),  # type: ignore[arg-type]
    )
    # No pinned bundle -> configured default (capture it rather than
    # naming the provider, so the assertion is provider-agnostic).
    default_model = await provider.resolve_model("scoring")
    assert default_model and "/" in default_model

    # Non-empty bundle routing wins for the matching task_type.
    set_pinned_bundle(PinnedBundle(
        routing={"scoring": "openai/gpt-4-turbo"},
    ))
    try:
        assert await provider.resolve_model("scoring") == "openai/gpt-4-turbo"
        # A task_type NOT in the bundle routing falls through to the
        # normal resolution (stub returns None everywhere, so the same
        # configured default, never the override).
        fell_through = await provider.resolve_model("synthesis")
        assert fell_through == default_model
        assert fell_through != "openai/gpt-4-turbo"
    finally:
        clear_pinned_bundle()


@pytest.mark.asyncio
async def test_empty_bundle_routing_leaves_resolve_model_unchanged() -> None:
    """The safety invariant on the LLM hot path: empty routing => byte-
    identical resolve_model behaviour compared to no bundle at all."""
    clear_pinned_bundle()
    provider = LLMConfigProvider(
        registry=_StubRegistry(),  # type: ignore[arg-type]
        secret_store=_StubSecretStore(),  # type: ignore[arg-type]
    )
    baseline = await provider.resolve_model("scoring")
    set_pinned_bundle(PinnedBundle())  # empty routing
    try:
        assert await provider.resolve_model("scoring") == baseline
    finally:
        clear_pinned_bundle()


# --- resolve_pinned_prompt publishes the bundle to the ContextVar ----------


@pytest.mark.asyncio
async def test_resolve_publishes_bundle_to_contextvar() -> None:
    """The pin resolve side-publishes the bundle so the LLM routing
    hot path and persona-spawn can see it without a second query."""
    clear_pinned_bundle()
    store = PromptVersionStore()
    key = _key()
    routing = {"scoring": "openai/gpt-4"}
    roster = {"halvar": {"weight": 1.0}}
    v = await store.register(key, "BODY", roster=roster, routing=routing)
    await store.set_alias(key, "production", v)
    inv_id = await _make_investigation()

    await resolve_pinned_prompt(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    bundle = current_pinned_bundle()
    assert bundle.routing == routing
    assert bundle.roster == roster


@pytest.mark.asyncio
async def test_file_fallback_resets_bundle_to_empty() -> None:
    """When the store has no version, the ContextVar publishes an EMPTY
    bundle -- a routing/roster from an earlier resolve must not leak
    into a turn that fell back to the file registry."""
    # Prime a stale bundle from an earlier call.
    set_pinned_bundle(PinnedBundle(routing={"scoring": "stale"}))
    assert current_pinned_bundle().routing == {"scoring": "stale"}

    store = PromptVersionStore()
    key = _key()
    inv_id = await _make_investigation()
    body, version = await resolve_pinned_prompt(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert body is None
    assert version is None
    bundle = current_pinned_bundle()
    assert bundle.routing == {}
    assert bundle.roster == {}
    assert bundle.exemplars == []


# --- resolve_pinned_bundle returns full bundle shape ----------------------


@pytest.mark.asyncio
async def test_resolve_pinned_bundle_returns_full_shape() -> None:
    """The sibling resolver returns a :class:`ResolvedBundle` with body,
    version, and every populated extra."""
    clear_pinned_bundle()
    store = PromptVersionStore()
    key = _key()
    roster = {"halvar": {"weight": 1.0}}
    routing = {"scoring": "openai/gpt-4"}
    exemplars = ["only one"]
    v = await store.register(
        key, "BODY", roster=roster, routing=routing, exemplars=exemplars,
    )
    await store.set_alias(key, "production", v)
    inv_id = await _make_investigation()

    resolved = await resolve_pinned_bundle(
        investigation_id=inv_id,
        key=key,
        investigation_model=VRInvestigationRecord,
        store=store,
    )
    assert isinstance(resolved, ResolvedBundle)
    assert resolved.version == v
    assert resolved.roster == roster
    assert resolved.routing == routing
    assert resolved.exemplars == exemplars
    assert resolved.body is not None
    assert resolved.body.startswith("BODY")
    assert "only one" in resolved.body
