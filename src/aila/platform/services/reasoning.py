from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningDomainProfile,
    ReasoningEvidenceGraph,
    ReasoningGraphEdge,
    ReasoningGraphNode,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    ReasoningStrategyDeclaration,
    ReasoningStrategyFamily,
    ReasoningTurnDecision,
)
from aila.platform.exceptions import ValidationError
from aila.platform.llm.client import AilaLLMClient
from aila.platform.services.context_assembler import (
    ContextAssembler,
    ContextSection,
    ContextTier,
    PinnedOverflowError,
)

# fix §132 -- imports first, then module-level statements (PEP 8 / E402).
_log = logging.getLogger(__name__)

__all__ = [
    "CyberReasoningEngine",
    "DomainProfileRegistry",
    "StrategyRegistry",
    "UnknownStrategyError",
    "register_reasoning_domain_profile",
    "register_reasoning_strategy",
    "reset_reasoning_registries",
]


# Namespace prefixes the agent must not write to. Tool / directive /
# recall keys carry external-source metadata (tool bodies, directive
# lifts, engine-pinned recall list) that the agent must not overwrite,
# rename, or shadow via self-set observables. ``_recall.pinned`` is
# written exclusively by :meth:`absorb` when the agent emits
# ``action="recall"``; blocking the ``_recall.`` prefix here also
# exempts the pinned-key list from the agent-key eviction cap in the
# same absorb() pass.
_TOOL_PREFIXES: tuple[str, ...] = (
    "audit_mcp:", "audit_mcp.",
    "ida_headless:", "ida_headless.",
    "_directive.",
    "_recall.",
)

# Fallback hard cap on agent-self-set observable keys across all turns
# when no ConfigRegistry is wired (constructed without one, e.g. narrow
# unit tests). Production paths resolve the live value via
# ``self._config_registry.get_sync("platform", "reasoning_max_agent_keys_total")``
# (schema default matches this literal so byte-for-byte behaviour is
# preserved). Anything past the resolved cap is LRU-evicted by insertion
# order; tool / directive / _recall.pinned keys are preserved by the
# partition in render_case_model and live separately from this cap.
# Bumped 50 -> 150 alongside the recall-action redesign: the 262K-context
# runtime no longer needs the old overflow-defense cap, and scratchpad
# now renders whole up to a 150-key ceiling so the eviction threshold
# matches the render ceiling.
_DEFAULT_MAX_AGENT_KEYS_TOTAL: int = 150

# Fallback recall pin working-set cap. ``absorb`` keeps the most-recent
# N recall pins so an agent can re-recall any turn without letting the
# pin list grow unbounded. Same config-registry-with-fallback pattern as
# ``_DEFAULT_MAX_AGENT_KEYS_TOTAL`` above.
_DEFAULT_RECALL_PINNED_MAX: int = 8

# Fallback per-turn user-prompt token budget applied by
# ``build_user_prompt`` when the caller passes 0/None and no
# ConfigRegistry is wired (narrow unit tests that construct the engine
# without a registry). Production paths resolve the live value via
# ``self._resolve_platform_int("reasoning_context_budget_tokens", ...)``
# and the schema default matches this literal so byte-for-byte behaviour
# is preserved for callers that never override. Sized against a
# 200K-context model with generous headroom (system prompt + tool
# payload + completion); see the schema field
# ``PlatformConfigSchema.reasoning_context_budget_tokens`` docstring
# NEVER unbounded on production callers -- the entire
# reason this constant exists is that removing the render_case_model
# display caps cannot regress into an unbounded prompt.
_DEFAULT_CONTEXT_BUDGET_TOKENS: int = 180_000

# Fallback staleness threshold (in turns) at which absorb writes the
# ``_directive.stale_hypotheses`` observable naming a live hypothesis
# so the agent resolves it, rejects it, or explicitly defers with a
# reason on this turn. Production paths resolve the live value via
# ``self._resolve_platform_int("reasoning_hyp_stale_turns", ...)``; the
# schema default matches this literal so behavior is preserved for
# callers that never override. A value <= 0 disables the directive.
_DEFAULT_HYP_STALE_TURNS: int = 8

# Marker body injected under a recalled key when the durable message
# history cannot supply the body (no fetcher wired, or the fetcher
# returned None). Keeps the render pipeline consistent -- the agent
# always sees SOMETHING under a pinned key rather than a silent drop.
_RECALL_MISSING_MARKER: str = (
    "[recall: body not available in message history -- "
    "try a fresh tool_run to re-derive]"
)

# Reasoning strategy families and domain profiles are module-owned: each
# module publishes them through ModuleProtocol.reasoning_strategies() and
# reasoning_domain_profiles(), and the platform builder registers them here
# at load. The platform itself owns only the ``generic`` strategy. Operators
# can still override a profile without a code deploy by writing the profile
# JSON to ConfigRegistry under ``reasoning_domain_profile_{domain_id}``; the
# engine loads that override lazily on first resolve.


class UnknownStrategyError(ValueError):
    """Raised when a reasoning strategy family is not registered."""


class StrategyRegistry:
    """Registry of reasoning strategy families, keyed by family name.

    Seeded with the platform-owned ``generic`` family; module families are
    added at load through :func:`register_reasoning_strategy`.
    """

    def __init__(self) -> None:
        self._by_family: dict[str, ReasoningStrategyDeclaration] = {}
        self.register(
            ReasoningStrategyDeclaration(
                family="generic",
                task_type="generic",
                description="Fallback for unclassified reasoning tasks.",
            ),
        )

    def register(self, declaration: ReasoningStrategyDeclaration) -> None:
        self._by_family[declaration.family] = declaration

    def resolve(self, family: str) -> ReasoningStrategyDeclaration:
        declaration = self._by_family.get(family)
        if declaration is None:
            raise UnknownStrategyError(family)
        return declaration

    def is_registered(self, family: str) -> bool:
        return family in self._by_family

    def clear(self) -> None:
        """Reset to the platform baseline (``generic`` only)."""
        self._by_family.clear()
        self.register(
            ReasoningStrategyDeclaration(
                family="generic",
                task_type="generic",
                description="Fallback for unclassified reasoning tasks.",
            ),
        )


class DomainProfileRegistry:
    """Registry of reasoning domain profiles, keyed by domain_id."""

    def __init__(self) -> None:
        self._by_id: dict[str, ReasoningDomainProfile] = {}

    def register(self, profile: ReasoningDomainProfile) -> None:
        self._by_id[profile.domain_id] = profile

    def resolve(self, domain_id: str) -> ReasoningDomainProfile | None:
        if domain_id not in self._by_id:
            return None
        return self._by_id[domain_id]

    def clear(self) -> None:
        self._by_id.clear()


# Process-wide registries populated by the platform builder at load. The
# platform seeds only ``generic``; domains and families arrive from modules.
_STRATEGY_REGISTRY = StrategyRegistry()
_DOMAIN_PROFILE_REGISTRY = DomainProfileRegistry()

# The strategy families the platform recognises without a module
# registration. These are exactly the families ``select_strategy_family``
# can return; keep the two in sync. ``resolve_domain_profile`` uses this
# set to adapt a domain_id that names a built-in family into a
# single-family profile, while a domain_id that names neither a
# registered profile nor a built-in family falls back to ``generic``.
_BUILTIN_STRATEGY_FAMILIES: frozenset[str] = frozenset({
    "generic",
    "mobile_reverse",
    "vulnerability_research",
    "network_forensics",
    "memory_forensics",
    "persistence_hunt",
    "web_pentest",
    "malware_static",
    "filesystem_triage",
})


def register_reasoning_strategy(declaration: ReasoningStrategyDeclaration) -> None:
    """Register a module-declared strategy family into the platform registry."""
    _STRATEGY_REGISTRY.register(declaration)


def register_reasoning_domain_profile(profile: ReasoningDomainProfile) -> None:
    """Register a module-declared domain profile into the platform registry."""
    _DOMAIN_PROFILE_REGISTRY.register(profile)


def reset_reasoning_registries() -> None:
    """Reset both registries to their platform-seeded baseline (tests)."""
    _STRATEGY_REGISTRY.clear()
    _DOMAIN_PROFILE_REGISTRY.clear()


class CyberReasoningEngine:
    """Platform-owned closed-loop reasoning adapter for cyber workflows.

    The engine owns the protocol-level interaction with the LLM:
    - prompt/response round-trip
    - strict JSON extraction
    - turn-decision validation
    - case-state merging semantics

    Domain modules still decide which tools to execute and how to interpret the
    results, but they no longer own the reasoning protocol itself.
    """

    def __init__(
        self,
        llm_client: AilaLLMClient,
        *,
        config_registry: Any | None = None,
    ) -> None:
        self._llm_client = llm_client
        # fix §131 -- optional registry lets operators add a domain profile
        # by writing JSON to ConfigRegistry without a code deploy. Cached
        # on first lookup to avoid repeated registry round-trips.
        self._config_registry = config_registry
        self._profile_override_cache: dict[str, ReasoningDomainProfile | None] = {}
        # RFC-24 assembler: reused across every build_user_prompt call.
        # Instances are stateless between assemble() calls so one per
        # engine (rather than one per turn) is fine.
        self._prompt_assembler = ContextAssembler()

    def resolve_domain_profile(self, domain_id: str) -> ReasoningDomainProfile:
        """Return the reasoning profile for ``domain_id``.

        Lookup order (fix §131):

        1. Operator-supplied override from ConfigRegistry under
           ``reasoning_domain_profile_{domain_id}`` (cached).
        2. Module-registered profile from the DomainProfileRegistry.
        3. Single-strategy self-adapter when ``domain_id`` names a
           built-in strategy family (``_BUILTIN_STRATEGY_FAMILIES``).
        4. Generic single-strategy profile (final fallback for a
           domain_id that names neither a registered profile nor a
           built-in family).
        """
        override = self._load_profile_override(domain_id)
        if override is not None:
            return override
        profile = _DOMAIN_PROFILE_REGISTRY.resolve(domain_id)
        if profile is not None:
            return profile
        if domain_id in _BUILTIN_STRATEGY_FAMILIES and domain_id != "generic":
            return ReasoningDomainProfile(
                domain_id=domain_id,
                task_type=domain_id,
                description="Cross-domain adapter for a built-in strategy family.",
                allowed_strategies=[domain_id],
                default_strategy=domain_id,
            )
        return ReasoningDomainProfile(
            domain_id=domain_id,
            task_type=domain_id,
            description="Custom reasoning domain.",
            allowed_strategies=["generic"],
            default_strategy="generic",
        )

    def _load_profile_override(
        self, domain_id: str,
    ) -> ReasoningDomainProfile | None:
        """Read + parse a profile override from ConfigRegistry, cached.

        Returns ``None`` when no registry is wired, the key is absent, or
        the JSON shape doesn't match. Failures log at DEBUG and fall back
        to the module-registered profile so a malformed override cannot crash the
        reasoning loop.
        """
        if self._config_registry is None:
            return None
        if domain_id in self._profile_override_cache:
            return self._profile_override_cache[domain_id]
        cached: ReasoningDomainProfile | None = None
        try:
            # get_sync is the sync read path (C3): the async .get() returned a
            # coroutine this sync helper could never await, so an operator's
            # profile override was always discarded in favor of the hardcoded
            # fallback. Async callers can still warm the cache via
            # set_profile_override().
            raw = self._config_registry.get_sync(
                "platform", f"reasoning_domain_profile_{domain_id}",
            )
            if raw:
                payload = raw if isinstance(raw, dict) else json.loads(str(raw))
                cached = ReasoningDomainProfile(**payload)
        except (ValueError, TypeError, ValidationError) as exc:
            _log.debug(
                "reasoning: profile override for %s ignored -- %s",
                domain_id, exc,
            )
        self._profile_override_cache[domain_id] = cached
        return cached

    def set_profile_override(
        self, domain_id: str, profile: ReasoningDomainProfile | None,
    ) -> None:
        """Pre-populate the override cache (used by async warmers + tests)."""
        self._profile_override_cache[domain_id] = profile

    async def decide_next_turn(
        self,
        *,
        task_type: str,
        system_prompt: str,
        user_prompt: str,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> ReasoningTurnDecision:
        """Return the next reasoning turn as a validated decision model.

        Uses ``chat_structured`` so the OpenAI-compatible gateway enforces
        the ReasoningTurnDecision JSON schema upstream when the routed
        model supports strict mode. Falls back to client-side parsing
        when the model emits something close-but-not-exact (handled
        below by the normalizer + extractor).

        ``run_id`` is forwarded to the LLM client so per-run cost records,
        budget checks, and cost aggregation attribute this turn's spend to
        the caller's run. Investigation callers pass their investigation_id;
        this is what makes the forensics freeflow cost ceiling and the
        per-investigation cost display functional (#59/#39). A None run_id
        keeps the old behaviour: the call is recorded under the standalone
        sentinel and never budget-checked.
        """
        response = await self._llm_client.chat_structured(
            task_type=task_type,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model_class=ReasoningTurnDecision,
            run_id=run_id,
            team_id=team_id,
        )
        if response.disabled:
            raise RuntimeError("LLM kill-switch active")
        raw = self._extract_json_object(response.content)
        # LLMs sometimes return null for required string fields.
        # Patch the raw dict so validation doesn't crash the turn,
        # but log a warning -- the model should be producing these.
        for str_field in ('expected_observation', 'reasoning'):
            if str_field in raw and raw[str_field] is None:
                _log.warning(
                    'LLM returned null for required field %s -- defaulting to empty string. '
                    'This indicates the model is not reasoning properly.',
                    str_field,
                )
                raw[str_field] = ''
        # Some LLMs (Claude in particular when asked for a tool_run)
        # ignore the documented ``command: "<json string>"`` shape and
        # place the dispatch elsewhere. Three observed variants:
        #   1. ``tool`` + ``args`` at top level (next to ``action``)
        #   2. nested under a key matching the action name:
        #      ``{"action":"tool_run","tool_run":{"command":"..."}}``
        #   3. nested under ``tool_run`` with ``tool``+``args`` instead
        #      of a pre-stringified ``command``
        # Normalize all three into the documented top-level ``command``
        # string so the executor gets a dispatchable payload.
        if raw.get('action') == 'tool_run' and not raw.get('command'):
            nested = raw.get('tool_run') if isinstance(raw.get('tool_run'), dict) else None
            nested_cmd = nested.get('command') if nested else None
            if isinstance(nested_cmd, str) and nested_cmd:
                raw['command'] = nested_cmd
                _log.info('LLM nested command under tool_run key -- lifted to top level')
            elif nested and isinstance(nested.get('tool'), str):
                raw['command'] = json.dumps({
                    'tool': nested['tool'],
                    'args': nested.get('args') or {},
                })
                _log.info(
                    'LLM nested tool/args under tool_run key -- synthesized '
                    'command for tool=%s', nested['tool'],
                )
            elif isinstance(raw.get('tool'), str):
                raw['command'] = json.dumps({
                    'tool': raw['tool'],
                    'args': raw.get('args') or {},
                })
                _log.info(
                    'LLM emitted top-level tool/args instead of nested command -- '
                    'synthesized command for tool=%s', raw['tool'],
                )
        return ReasoningTurnDecision.model_validate(raw)

    def _resolve_platform_int(
        self, key: str, default: int,
    ) -> int:
        """Read a platform-namespace int cap via ConfigRegistry.

        Reads under the ``platform`` namespace (the platform layer
        owns only this namespace per RFC-05); a missing registry, a
        DB / cache failure, or a non-numeric value all fall back to
        ``default`` so absorb never crashes on config drift. Cached
        transparently by ConfigRegistry itself; a fresh call per turn
        is cheap.
        """
        if self._config_registry is None:
            return default
        try:
            raw = self._config_registry.get_sync("platform", key)
        except (OSError, RuntimeError, ValueError, TypeError, SQLAlchemyError):
            return default
        if raw is None:
            return default
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    def absorb(
        self,
        case_state: ReasoningCaseState,
        decision: ReasoningTurnDecision,
        *,
        turn_number: int = 0,
        fetch_observable_body: Callable[[str], str | None] | None = None,
    ) -> ReasoningCaseState:
        """Merge a turn decision into cumulative reasoning state.

        ``fetch_observable_body`` is a module-supplied sync callable that
        returns the durable body for an observable key that is no longer
        in the live ``case_state.observables`` (evicted by the storage
        cap). The recall branch calls it for every pinned key that is
        absent and re-injects the returned body so a stale pin
        rehydrates from the DB message history instead of silently
        dropping. When the callable returns ``None`` -- or when no
        callable is wired (malware / forensics today) -- a short
        \"not available\" marker is injected under the pinned key so
        the render layer still surfaces the recall attempt to the agent
        rather than swallowing it.

        The platform layer names no module here: the callable is opaque
        (module can preload from its own message table, or wrap any
        other store) and the injected marker is a plain string with no
        module-specific vocabulary.
        """
        contract = case_state.contract
        if decision.contract is not None and not self._has_contract(case_state.contract):
            contract = decision.contract

        # Merge live hypotheses across turns instead of replacing.
        # The LLM emits its CURRENT view each turn, but it may forget
        # to repeat earlier ones -- that previously caused live
        # hypotheses to vanish silently. We:
        #   1. Start with the existing live list
        #   2. Drop any whose id is in the new rejected set
        #   3. Upsert each new hypothesis: replace existing by id,
        #      append unknown ones
        # Result: nothing the agent ever proposed disappears; the
        # only way to remove a hypothesis is to explicitly reject it.
        # Rejection dedup by id only (last-claim wins). The previous
        # (id, claim) tuple dedup let duplicates accumulate whenever
        # the agent rephrased a rejection's claim text turn-to-turn --
        # observed live on investigation <inv-uuid>: r1, r_gc_layout,
        # r_obj_moved_missing_from_source all appeared twice in
        # maddie's rejected list with slightly different wording.
        rejected_by_id: dict[str, Any] = {}
        for item in case_state.rejected:
            if item.id:
                rejected_by_id[item.id] = item
        for item in decision.rejected:
            if item.id:
                rejected_by_id[item.id] = item
        # Preserve insertion order (id-less keep their position)
        rejected = [item for item in case_state.rejected if not item.id]
        rejected.extend(item for item in decision.rejected if not item.id)
        rejected.extend(rejected_by_id.values())
        newly_rejected_ids = {item.id for item in decision.rejected if item.id}

        merged_live = [
            h for h in case_state.hypotheses if h.id not in newly_rejected_ids
        ]
        for new_h in decision.hypotheses or []:
            if not new_h.id:
                # No id: append; stamp current turn if not already set.
                if new_h.opened_at_turn == 0 and turn_number > 0:
                    new_h = new_h.model_copy(update={"opened_at_turn": turn_number})
                merged_live.append(new_h)
                continue
            for i, existing in enumerate(merged_live):
                if existing.id == new_h.id:
                    # Update in place but preserve the original opened_at_turn
                    # so age keeps counting from when the hypothesis FIRST
                    # appeared, not from each refinement the agent posts.
                    merged_live[i] = new_h.model_copy(update={
                        "opened_at_turn": existing.opened_at_turn or new_h.opened_at_turn,
                    })
                    break
            else:
                # Truly new id: stamp opened_at_turn.
                if new_h.opened_at_turn == 0 and turn_number > 0:
                    new_h = new_h.model_copy(update={"opened_at_turn": turn_number})
                merged_live.append(new_h)

        observables = dict(case_state.observables)
        # Engine-written pin list for the ``recall`` action. When the
        # agent emits ``action="recall"`` with ``recall_keys=[...]``,
        # merge those keys into the existing ``_recall.pinned`` list --
        # dedup while preserving order and keep the most-recent 8 if
        # over cap. render_case_model reads this list to render the
        # named tool bodies FULL + UNCAPPED in the next turn's prompt.
        # ``recall_keys`` is a first-class decision field; it is NOT
        # absorbed as normal observables (the ``_recall.`` prefix on
        # ``_TOOL_PREFIXES`` also blocks any agent attempt to write
        # ``_recall.pinned`` directly through ``decision.observables``,
        # so this branch is the only writer).
        if decision.action == "recall" and decision.recall_keys:
            pinned_raw = observables.get("_recall.pinned") or []
            if not isinstance(pinned_raw, list):
                pinned_raw = []
            merged_pinned: list[str] = []
            seen: set[str] = set()
            for candidate in list(pinned_raw) + list(decision.recall_keys):
                if not isinstance(candidate, str):
                    continue
                key = candidate.strip()
                if not key or key in seen:
                    continue
                seen.add(key)
                merged_pinned.append(key)
            # Keep the most-recent N pins (newest arrivals stay; agent
            # can re-recall an evicted key any turn). Cap is
            # config-resolved via the platform namespace so an operator
            # can widen or narrow the working set without a redeploy.
            recall_pinned_max = self._resolve_platform_int(
                "reasoning_recall_pinned_max", _DEFAULT_RECALL_PINNED_MAX,
            )
            if recall_pinned_max > 0 and len(merged_pinned) > recall_pinned_max:
                merged_pinned = merged_pinned[-recall_pinned_max:]
            observables["_recall.pinned"] = merged_pinned
            # Recall durable-history backing: for every pinned key not in
            # the live observables (evicted by the storage cap, or newly
            # recalled by an agent that never saw it live), try to
            # rehydrate the body from the module-supplied fetcher. Missing
            # bodies get a short marker so the render layer still shows
            # the recall attempt instead of dropping the pin silently.
            for key in merged_pinned:
                if key in observables:
                    continue
                fetched: str | None = None
                if fetch_observable_body is not None:
                    try:
                        fetched = fetch_observable_body(key)
                    except (OSError, RuntimeError, ValueError, TypeError) as exc:
                        # A misbehaving fetcher must not crash the turn;
                        # log at INFO with the exception class so the
                        # operator can correlate and fall back to the
                        # not-available marker.
                        _log.info(
                            "absorb: recall fetcher raised for key=%r "
                            "(%s: %s); injecting not-available marker",
                            key, type(exc).__name__, exc,
                        )
                        fetched = None
                if isinstance(fetched, str) and fetched:
                    observables[key] = fetched
                else:
                    observables[key] = _RECALL_MISSING_MARKER
        # Cap agent-self-set observables to keep case_state bounded:
        #   (1) max 10 NEW keys per turn (anti-spam)
        #   (2) block writes to tool / directive / _recall namespaces
        #   (3) max _MAX_AGENT_KEYS_TOTAL agent-set keys across all
        #       turns -- LRU evict oldest by dict-insertion order;
        #       tool / directive / _recall.pinned keys are NEVER
        #       evicted (they're preserved by the partition in
        #       render_case_model and live separately from the cap).
        accepted = 0
        for k, v in decision.observables.items():
            key = str(k).strip()
            if not key:
                continue
            if any(key.startswith(p) for p in _TOOL_PREFIXES):
                # Don't let the agent overwrite or shadow tool/directive keys.
                continue
            if accepted >= 10:
                break
            observables[key] = v
            accepted += 1
        # Enforce total-cap on agent-set keys. Cap is config-resolved via
        # the platform namespace so an operator can widen or narrow the
        # working set without a redeploy; the schema default matches the
        # pre-config-ification literal so behaviour is preserved.
        max_agent_keys_total = self._resolve_platform_int(
            "reasoning_max_agent_keys_total", _DEFAULT_MAX_AGENT_KEYS_TOTAL,
        )
        agent_keys = [
            k for k in observables
            if not any(k.startswith(p) for p in _TOOL_PREFIXES)
        ]
        if max_agent_keys_total > 0 and len(agent_keys) > max_agent_keys_total:
            evict_n = len(agent_keys) - max_agent_keys_total
            for k in agent_keys[:evict_n]:
                observables.pop(k, None)

        # Staleness directive: any live hypothesis whose age
        # (current_turn - opened_at_turn) has crossed the platform
        # threshold gets called out under ``_directive.stale_hypotheses``
        # so the agent resolves it, rejects it, or explicitly defers
        # this turn instead of letting it linger and block convergence.
        # Directive-only nudge (never auto-rejects) so a genuinely slow
        # lead is not dropped by a timer. Cleared on the same call when
        # no stale live hypotheses remain, so a resolved directive never
        # persists into a later turn.
        effective_turn = turn_number or case_state.current_turn
        stale_threshold = self._resolve_platform_int(
            "reasoning_hyp_stale_turns", _DEFAULT_HYP_STALE_TURNS,
        )
        stale: list[tuple[str, str, int]] = []
        if stale_threshold > 0 and effective_turn > 0:
            for h in merged_live:
                if not h.opened_at_turn:
                    continue
                age = effective_turn - h.opened_at_turn
                if age >= stale_threshold:
                    stale.append((h.id or "?", h.claim, age))
        if stale:
            lines = [
                "*** STALE LIVE HYPOTHESES ***",
                (
                    f"{len(stale)} live hypothesis(es) have been open for "
                    f">= {stale_threshold} turns without a resolution:"
                ),
                "",
            ]
            for hid, claim, age in stale:
                lines.append(f"  - {hid}: {claim[:200]} [alive {age} turns]")
            lines.extend([
                "",
                "This turn you MUST for EACH id above pick one:",
                "  (a) resolve it: add it to `decision.rejected[]` with a",
                "      concrete evidence-citing reason (file:line, tool",
                "      output, or a sibling's rejection you concur with),",
                "      OR fold it into a submit whose answer names the id",
                "      and shows the settling evidence.",
                "  (b) explicitly defer: keep it live and post a",
                "      one-sentence reason in `reasoning` naming the",
                "      concrete blocker (e.g. \"waiting on read_function",
                "      body from audit_mcp\"). Silent aging keeps the",
                "      panel from converging.",
            ])
            observables["_directive.stale_hypotheses"] = "\n".join(lines)
        else:
            # Clear on the same call so a resolved directive never
            # persists into a later turn (would otherwise scold the
            # agent for a stale id it already closed).
            observables.pop("_directive.stale_hypotheses", None)

        return ReasoningCaseState(
            contract=contract,
            hypotheses=merged_live,
            rejected=rejected,
            resolved=case_state.resolved,
            observables=observables,
            current_turn=turn_number or case_state.current_turn,
        )

    def render_case_model(self, case_state: ReasoningCaseState) -> str:
        """Render a compact textual case model for the next turn prompt.

        ``_directive.*`` and ``_recall.*`` observables are intentionally
        NOT rendered here as normal observables.

        * ``_directive.*``: the top-level prompt section
          ``_render_active_directives_section`` (in vuln_researcher)
          lifts those to PROMPT POSITION 2 so the agent sees them
          before any framing. Rendering them here too would duplicate
          the block lower in the prompt, splitting the agent's
          attention.
        * ``_recall.*``: engine-internal bookkeeping (``_recall.pinned``
          is the list of tool-reading keys currently pinned for
          full-body rendering). It steers which tool_obs values render
          uncapped below; surfacing it as a raw observable would just
          confuse the agent.
        * ``_ledger.*``: the shared investigation ledger digest
          (``_ledger.board``) rides its own dedicated section near the
          top and is skipped from the scratchpad partition so it is not
          rendered twice.

        Retrieval model:

        * Tool readings INDEX renders every tool key -- one compact
          line per key with size + first-line preview.
        * Tool readings shown IN FULL = every tool_obs key by insertion
          order UNION every key in ``_recall.pinned``. Recalled keys
          are flagged as such; a key in both renders once, in the
          recalled form. Bodies render verbatim so file:line anchors
          survive.
        * Agent scratchpad renders every agent-set key with its full
          value.

        The historical render-time truncation ceilings (hypotheses,
        scratchpad, tool index, tool full-body preview) are gone: the
        RFC-24 ``ContextAssembler`` now sizes the LIVE section against
        a real token budget resolved from
        ``platform.reasoning_context_budget_tokens``, and the recall
        action rehydrates evicted keys from the durable message history
        (see ``absorb``), so lossy display caps at this layer would only
        drop content the assembler already knows how to fit or the
        recall path already knows how to bring back.
        """
        parts: list[str] = []
        if self._has_contract(case_state.contract):
            parts.append("Contract:")
            parts.append(f"  answer_type   = {case_state.contract.answer_type}")
            parts.append(f"  answer_format = {case_state.contract.answer_format}")
            parts.append(f"  evidence      = {case_state.contract.evidence_domain}")
            if case_state.contract.depends_on:
                parts.append(f"  depends_on    = {case_state.contract.depends_on}")
        else:
            parts.append("Contract: (not parsed yet -- derive it this turn)")

        if case_state.hypotheses:
            live_count = len(case_state.hypotheses)
            header_suffix = ""
            if live_count >= 6:
                header_suffix = "  !! CLOSURE PRESSURE - close at least one this turn before adding new ones"
            elif live_count >= 4:
                header_suffix = "  (aging - prefer closing over adding)"
            parts.append(f"Live hypotheses ({live_count}):{header_suffix}")
            current_turn = case_state.current_turn or 0
            for hypothesis in case_state.hypotheses:
                age_marker = ""
                if hypothesis.opened_at_turn and current_turn:
                    age = current_turn - hypothesis.opened_at_turn
                    if age >= 10:
                        age_marker = f" [alive {age} turns - STALE, RESOLVE OR REJECT]"
                    elif age >= 5:
                        age_marker = f" [alive {age} turns - aging]"
                    elif age > 0:
                        age_marker = f" [alive {age} turns]"
                parts.append(f"  - {hypothesis.id or '?'}: {hypothesis.claim}{age_marker}")
                if hypothesis.why_plausible:
                    parts.append(f"      why: {hypothesis.why_plausible}")
                if hypothesis.kill_criterion:
                    parts.append(f"      kill: {hypothesis.kill_criterion}")
        else:
            parts.append("Live hypotheses: (propose 2-3 this turn)")

        if case_state.rejected:
            parts.append(f"Rejected (do not re-propose, {len(case_state.rejected)} total):")
            for rejected in case_state.rejected[:10]:
                parts.append(f"  - {rejected.id or '?'}: {rejected.claim} ({rejected.reason})")

        # RFC-13 (#68): the shared investigation ledger digest, written by
        # the turn runner before this render (reserved observable, one line
        # per recent entry). Surfaces cross-branch discoveries, notes, and
        # requests so a branch extends the shared board instead of
        # re-deriving what a sibling already posted.
        ledger_board = case_state.observables.get("_ledger.board")
        if isinstance(ledger_board, str) and ledger_board.strip():
            parts.append(ledger_board)

        # Partition observables so tool-generated readings (read_function
        # bodies, taint_paths_to results, callers_of edges, semantic
        # search hits) always survive prompt rendering. Without this,
        # agents bloat their own case_state with self-invented scratchpad
        # keys (sibling_*, mandatory_*, turns_without_*) and the render
        # eviction drops the actual source bodies, so the agent re-calls
        # read_function on names it already read.
        #
        # Tool keys are prefix-anchored: ``audit_mcp:*`` / ``audit_mcp.*``
        # / ``ida_headless:*`` / ``ida_headless.*`` / ``android_mcp:*``
        # / ``android_mcp.*``. ``_directive.*`` is already lifted to its
        # own top-of-prompt section so we drop them. ``_recall.*`` is
        # engine bookkeeping (drives the pinned-full section below) so
        # we drop those too. Everything else is agent-set scratchpad.
        tool_prefixes = (
            "audit_mcp:", "audit_mcp.",
            "ida_headless:", "ida_headless.",
            "android_mcp:", "android_mcp.",
        )
        tool_obs: list[tuple[str, Any]] = []
        agent_obs: list[tuple[str, Any]] = []
        for k, v in case_state.observables.items():
            if (
                k.startswith("_directive.")
                or k.startswith("_recall.")
                or k.startswith("_ledger.")
            ):
                continue
            if any(k.startswith(p) for p in tool_prefixes):
                tool_obs.append((k, v))
            else:
                agent_obs.append((k, v))

        # Read the engine-written pin list; only entries that actually
        # exist in tool_obs pin -- a stale key (evicted by storage cap)
        # is silently dropped from the pin set so the render stays
        # consistent with the observed state.
        pinned_raw = case_state.observables.get("_recall.pinned") or []
        if not isinstance(pinned_raw, list):
            pinned_raw = []
        tool_obs_map = dict(tool_obs)
        pinned_keys: list[str] = []
        seen_pinned: set[str] = set()
        for candidate in pinned_raw:
            if not isinstance(candidate, str):
                continue
            key = candidate.strip()
            if not key or key in seen_pinned:
                continue
            if key not in tool_obs_map:
                # Stale pin (storage evicted the body). Drop silently;
                # the agent can re-recall if the key reappears.
                continue
            seen_pinned.add(key)
            pinned_keys.append(key)

        if tool_obs:
            index_total = len(tool_obs)
            parts.append(
                f"Observables -- tool readings INDEX ({index_total} total -- "
                f"emit action=\"recall\" with recall_keys=[...] to pull full bodies):"
            )
            for key, value in tool_obs:
                body = str(value)
                nlines = body.count("\n") + 1
                ntok = len(body) // 4
                first_line = ""
                for candidate_line in body.split("\n"):
                    stripped = candidate_line.strip()
                    if stripped:
                        first_line = stripped
                        break
                parts.append(
                    f"  - {key}  ({nlines} lines / ~{ntok} tok)  {first_line}"
                )

            # Full-body section: every tool_obs key by insertion order
            # UNION the pinned set. A key in both renders once in the
            # recalled form so the agent sees the recall lineage. Bodies
            # render VERBATIM -- file:line anchors survive, and the
            # RFC-24 assembler decides whether the whole LIVE section
            # fits the token budget; a recalled key evicted by the
            # storage cap still rehydrates from the durable message
            # history via ``absorb``'s recall path.
            pinned_set = set(pinned_keys)
            full_render_order: list[tuple[str, bool]] = [
                (k, True) for k in pinned_keys
            ]
            for k, _ in tool_obs:
                if k not in pinned_set:
                    full_render_order.append((k, False))
            if full_render_order:
                parts.append(
                    "Observables -- tool readings shown in full:"
                )
                for key, is_recalled in full_render_order:
                    body = str(tool_obs_map.get(key, ""))
                    marker = " [recalled]" if is_recalled else ""
                    parts.append(f"  - {key}{marker} =")
                    parts.append(body)

        if agent_obs:
            scratchpad_total = len(agent_obs)
            parts.append(
                f"Observables -- agent scratchpad ({scratchpad_total} total):"
            )
            for key, value in agent_obs:
                parts.append(f"  - {key} = {value}")

        if not tool_obs and not agent_obs:
            parts.append("Observables: (none yet)")

        return "\n".join(parts)

    def resolve_context_budget_tokens(self) -> int:
        """Return the platform-configured per-turn user-prompt budget.

        Reads ``platform.reasoning_context_budget_tokens`` through
        :meth:`_resolve_platform_int` -- a missing registry, missing
        key, or non-numeric value falls back to
        :data:`_DEFAULT_CONTEXT_BUDGET_TOKENS` (matches the schema
        default so byte-for-byte behaviour is preserved).

        A non-positive resolved value (operator explicitly wrote 0 or a
        negative number, e.g. to disable the safety net during a local
        test) is coerced back to :data:`_DEFAULT_CONTEXT_BUDGET_TOKENS`
        so ``build_user_prompt`` never routes a caller through the
        assembler with an unbounded budget. The assembler itself
        interprets ``budget_tokens <= 0`` as unlimited; the whole
        reason this helper exists is that removing
        ``render_case_model``'s display caps cannot regress into an
        unbounded prompt on production callers.

        Callers can thread the resolved value into
        ``ReasoningPromptContext.context_budget_tokens`` so the budget
        applied is explicit at the caller boundary; the engine itself
        uses this helper as the fallback when a caller passes ``0``.
        """
        raw = self._resolve_platform_int(
            "reasoning_context_budget_tokens", _DEFAULT_CONTEXT_BUDGET_TOKENS,
        )
        if raw <= 0:
            return _DEFAULT_CONTEXT_BUDGET_TOKENS
        return raw

    def build_user_prompt(self, context: ReasoningPromptContext) -> str:
        """Build the user-prompt payload for one reasoning turn.

        Routes the prompt through the RFC-24 tiered assembler so the
        assembled body fits a real token budget while preserving the
        pinned tier (system framing, operator steering, kill directives).

        Budget resolution:

        * ``context.context_budget_tokens > 0`` -- honoured verbatim.
          Callers that already resolved a budget (VR threads the
          platform-configured value; tests pin a specific size) pass
          it explicitly.
        * ``context.context_budget_tokens <= 0`` -- the engine falls
          back to :meth:`resolve_context_budget_tokens`. This is the
          safety net for forensics and any other caller still passing
          the default. After ``render_case_model``'s hardcoded display
          caps were removed, an unbounded budget would let a busy
          case_state produce an arbitrarily large prompt; the fallback
          keeps every caller bounded by the same platform config.

        Section source:

        * ``context.prebuilt_sections`` set -- VR / malware pass their
          own tiered section list; the engine's built-in
          ``_prompt_sections`` (the forensics-style header + evidence
          + case_model + transcript layout) is skipped.
        * ``context.prebuilt_sections is None`` -- forensics and other
          domain-generic callers use the built-in section generator.

        Raises :class:`PinnedOverflowError` when the PINNED tier alone
        exceeds the resolved budget. That is a real operational signal
        -- either operator-authoritative content grew past the model
        window or the configured budget is too small for the deployment.
        The engine logs at ERROR before re-raising so an operator sees
        the exact numbers in the worker log; silently truncating
        operator steering would violate the RFC-24 guardrail.
        """
        if context.prebuilt_sections is not None:
            sections = list(context.prebuilt_sections)
        else:
            sections = self._prompt_sections(context)
        if context.context_budget_tokens > 0:
            budget_tokens = context.context_budget_tokens
        else:
            budget_tokens = self.resolve_context_budget_tokens()
        try:
            assembled = self._prompt_assembler.assemble(
                sections,
                budget_tokens=budget_tokens,
                reserved_tokens=context.system_prompt_tokens,
            )
        except PinnedOverflowError:
            _log.exception(
                "reasoning: pinned tier overflowed context budget "
                "(budget=%d, reserved=%d); operator-authoritative sections "
                "cannot be dropped -- widen platform.reasoning_context_"
                "budget_tokens or shrink pinned inputs (operator steering / "
                "active directives / target snapshot / tool catalog)",
                budget_tokens, context.system_prompt_tokens,
            )
            raise
        return assembled.text

    def _prompt_sections(
        self, context: ReasoningPromptContext,
    ) -> list[ContextSection]:
        """Break the per-turn prompt into RFC-24 tier-tagged sections.

        Tier assignments:

        * ``PINNED`` -- turn/question header, domain + strategy pin,
          operator steering, project-kind directive, and the trailing
          response contract instruction. These are the operator- and
          engine-authoritative pieces RFC-24 marks as never-evicted.
        * ``LIVE`` -- the case model (live hypotheses + retained tool
          readings; already capped by ``absorb`` / ``render_case_model``).
        * ``RECENT`` -- evidence directory listing, on-project
          artifacts, and the last-turns transcript. These fall away
          (summary first, then drop) when the budget is tight;
          each one carries a short ``summary`` so a budget-pressured
          turn keeps a cue rather than a hole.
        """
        n_evidence = (
            context.evidence_listing.count("\n") + 1
            if context.evidence_listing.strip()
            else 0
        )
        n_artifacts = (
            context.artifacts.count("\n== ")
            if context.artifacts
            else 0
        )

        sections: list[ContextSection] = []

        header_lines = [
            f"Turn {context.turn}/{context.max_turns}. User question:",
            context.question,
            "",
            f"Reasoning domain profile: {context.domain_profile}",
            f"Preferred strategy family: {context.strategy_family}",
        ]
        sections.append(
            ContextSection(
                tier=ContextTier.PINNED,
                label="header",
                body="\n".join(header_lines),
                droppable=False,
            )
        )

        steering = context.operator_steering
        if (
            steering.confirmed_facts
            or steering.disproved_hypotheses
            or steering.guidance
            or steering.required_artifacts
            or steering.pinned_strategy_family is not None
        ):
            steering_lines: list[str] = ["OPERATOR STEERING:"]
            if steering.pinned_strategy_family is not None:
                steering_lines.append(
                    f"  pinned_strategy_family = {steering.pinned_strategy_family}"
                )
            for fact in steering.confirmed_facts:
                steering_lines.append(f"  confirmed_fact = {fact}")
            for rejected in steering.disproved_hypotheses:
                steering_lines.append(f"  disproved_hypothesis = {rejected}")
            for artifact in steering.required_artifacts:
                steering_lines.append(f"  required_artifact = {artifact}")
            for item in steering.guidance:
                steering_lines.append(f"  guidance = {item}")
            sections.append(
                ContextSection(
                    tier=ContextTier.PINNED,
                    label="operator_steering",
                    body="\n".join(steering_lines),
                    droppable=False,
                )
            )

        if context.project_kind == "raw_directory":
            sections.append(
                ContextSection(
                    tier=ContextTier.PINNED,
                    label="project_kind_directive",
                    body=(
                        "PROJECT KIND: raw_directory\n"
                        "The evidence directory is a real filesystem on the analyzer (rootfs "
                        "/ loose-files). There is no disk image. Do NOT call dissect.target, "
                        "volatility3, or tshark. Read files directly by absolute path using "
                        "cat / Get-Content / Python open(). Treat every file in the listing as "
                        "already accessible on the analyzer filesystem."
                    ),
                    droppable=False,
                )
            )

        evidence_body = (
            f"Evidence directory: {context.evidence_dir}\n"
            f"Evidence files on disk ({n_evidence}):\n"
            + (context.evidence_listing or "(no evidence catalogued)")
        )
        sections.append(
            ContextSection(
                tier=ContextTier.RECENT,
                label="evidence",
                body=evidence_body,
                summary=(
                    f"Evidence directory: {context.evidence_dir} "
                    f"({n_evidence} files -- listing elided for budget)"
                ),
            )
        )

        case_body = "Case model so far:\n" + (context.case_model or "")
        sections.append(
            ContextSection(
                tier=ContextTier.LIVE,
                label="case_model",
                body=case_body,
                # Summarisation of the case model would paraphrase
                # observables and violate the RFC-24 file:line-anchor
                # guardrail. Under extreme pressure we drop the case
                # model rather than paraphrase it -- but that only
                # happens after every RECENT section is already dropped.
            )
        )

        artifacts_body = (
            f"Artefacts already collected on this project ({n_artifacts} records):\n"
            + (context.artifacts or "(no artefacts collected yet)")
        )
        sections.append(
            ContextSection(
                tier=ContextTier.RECENT,
                label="artifacts",
                body=artifacts_body,
                summary=(
                    f"Artefacts on project: {n_artifacts} records "
                    "(listing elided for budget)"
                ),
            )
        )

        transcript_body = "Transcript (last turns):\n" + (
            context.previous or "(no previous turns)"
        )
        sections.append(
            ContextSection(
                tier=ContextTier.RECENT,
                label="transcript",
                body=transcript_body,
                summary="Transcript (last turns): elided for budget",
            )
        )

        sections.append(
            ContextSection(
                tier=ContextTier.PINNED,
                label="response_contract",
                body="Return a single JSON object matching the response contract.",
                droppable=False,
            )
        )

        return sections

    def select_strategy_family(
        self,
        *,
        question: str,
        case_state: ReasoningCaseState,
        evidence_listing: str = "",
        project_kind: str = "",
        steering: ReasoningOperatorSteering | None = None,
    ) -> ReasoningStrategyFamily:
        """Choose a reusable strategy family for the current turn.

        This is deliberately deterministic today: fast, inspectable routing
        gives modules a stable baseline and keeps later strategy learning/evals
        comparable.
        """
        if steering is not None and steering.pinned_strategy_family is not None:
            return steering.pinned_strategy_family

        joined = "\n".join(
            [
                question,
                evidence_listing,
                "\n".join(steering.guidance if steering is not None else []),
                case_state.contract.evidence_domain,
                "\n".join(f"{key}={value}" for key, value in case_state.observables.items()),
            ]
        ).lower()

        if any(token in joined for token in ("apk", "ipa", "android", "ios", "mobile", "dexclassloader", "manifest")):
            return "mobile_reverse"
        if any(token in joined for token in ("cve", "cvss", "advisory", "package version", "exploitability", "kev", "epss")):
            return "vulnerability_research"
        if any(token in joined for token in ("pcap", "dns", "http", "tls", "sni", "beacon", "network traffic")):
            return "network_forensics"
        if any(token in joined for token in ("memory", "volatility", "lsass", "dll injection", "process tree", "memdump")):
            return "memory_forensics"
        if any(token in joined for token in ("run key", "autorun", "scheduled task", "service persistence", "launchagent", "startup folder", "registry")):
            return "persistence_hunt"
        if any(token in joined for token in ("xss", "sqli", "idor", "csrf", "jwt", "token", "auth bypass", "request", "response", "endpoint", "burp")):
            return "web_pentest"
        if any(token in joined for token in ("malware", "dropper", "loader", "payload", "packed", "shellcode")):
            return "malware_static"
        if project_kind == "raw_directory" or any(token in joined for token in ("filesystem", "archive", ".zip", ".7z", ".rar", ".tar")):
            return "filesystem_triage"
        return "generic"

    def validate_submission(
        self,
        *,
        answer: object,
        primary_artifact: str,
        previous_turns: list[dict[str, object]],
        observables: dict[str, object] | None = None,
        required_artifacts: list[str] | None = None,
        corroboration: list[str] | None = None,
    ) -> str | None:
        """Return an error string when a submission lacks sufficient evidence."""
        if answer is None or not str(answer).strip():
            return "answer is empty"
        if not primary_artifact:
            return "provenance.primary_artifact is empty -- need a concrete citation"
        if required_artifacts:
            cited = {primary_artifact, *(corroboration or [])}
            required = {artifact.split("] ", 1)[-1] for artifact in required_artifacts}
            if required.isdisjoint(cited):
                return "submission does not cite any operator-required artifact"
        for prev in previous_turns:
            for field in ("stdout", "stderr", "command", "script_content"):
                if primary_artifact and primary_artifact in str(prev.get(field) or ""):
                    return None
        if observables is not None:
            for value in observables.values():
                if primary_artifact and primary_artifact in str(value):
                    return None
        if any(token in primary_artifact for token in ("/", "\\", "-", ":")):
            return None
        return "primary_artifact not found in prior tool output, observables, or recognizable artefact id/path"

    def build_evidence_graph(
        self,
        *,
        case_state: ReasoningCaseState,
        decision: ReasoningTurnDecision | None = None,
    ) -> ReasoningEvidenceGraph:
        """Build a graph snapshot from cumulative reasoning state and one decision."""
        nodes: list[ReasoningGraphNode] = []
        edges: list[ReasoningGraphEdge] = []

        if self._has_contract(case_state.contract):
            nodes.append(
                ReasoningGraphNode(
                    id="contract",
                    kind="contract",
                    label=case_state.contract.answer_format or case_state.contract.answer_type or "contract",
                    attributes=case_state.contract.model_dump(mode="json"),
                )
            )

        for hypothesis in case_state.hypotheses:
            node_id = f"hyp:{hypothesis.id}"
            nodes.append(
                ReasoningGraphNode(
                    id=node_id,
                    kind="hypothesis",
                    label=hypothesis.claim,
                    attributes=hypothesis.model_dump(mode="json"),
                )
            )
            if hypothesis.id in case_state.contract.depends_on:
                edges.append(
                    ReasoningGraphEdge(
                        source=node_id,
                        target="contract",
                        kind="depends_on",
                    )
                )

        for rejected in case_state.rejected:
            nodes.append(
                ReasoningGraphNode(
                    id=f"rej:{rejected.id}",
                    kind="rejected_hypothesis",
                    label=rejected.claim,
                    attributes=rejected.model_dump(mode="json"),
                )
            )

        for key, value in case_state.observables.items():
            nodes.append(
                ReasoningGraphNode(
                    id=f"obs:{key}",
                    kind="observable",
                    label=key,
                    attributes={"value": value},
                )
            )

        if decision is not None:
            provenance = decision.provenance.model_dump(mode="json")
            primary_artifact = str(provenance.get("primary_artifact") or "").strip()
            if primary_artifact:
                nodes.append(
                    ReasoningGraphNode(
                        id=f"evidence:{primary_artifact}",
                        kind="evidence",
                        label=primary_artifact,
                    )
                )
            for artifact in decision.provenance.corroboration:
                artifact_id = str(artifact).strip()
                if not artifact_id:
                    continue
                nodes.append(
                    ReasoningGraphNode(
                        id=f"evidence:{artifact_id}",
                        kind="evidence",
                        label=artifact_id,
                    )
                )
                if primary_artifact:
                    edges.append(
                        ReasoningGraphEdge(
                            source=f"evidence:{artifact_id}",
                            target=f"evidence:{primary_artifact}",
                            kind="corroborates",
                        )
                    )
            if decision.answer:
                nodes.append(
                    ReasoningGraphNode(
                        id="answer",
                        kind="answer",
                        label=decision.answer,
                        attributes={
                            "confidence": decision.confidence,
                            "reasoning": decision.reasoning,
                        },
                    )
                )
                if primary_artifact:
                    edges.append(
                        ReasoningGraphEdge(
                            source=f"evidence:{primary_artifact}",
                            target="answer",
                            kind="answered_by",
                        )
                    )

        return ReasoningEvidenceGraph(nodes=nodes, edges=edges)

    @staticmethod
    def _has_contract(contract: ReasoningContract) -> bool:
        return any(
            [
                contract.answer_type.strip(),
                contract.answer_format.strip(),
                contract.evidence_domain.strip(),
                contract.depends_on,
            ]
        )

    @staticmethod
    def _extract_json_object(text: str) -> dict[str, object]:
        """Pull the first complete JSON object out of an LLM reply.

        The naive ``text[find('{'):rfind('}')+1]`` slice breaks when the
        model emits prose then a second JSON-looking block (e.g. an
        example follow-up), because the slice spans BOTH objects plus
        the prose between them. ``json.JSONDecoder.raw_decode`` walks
        one value starting at the given offset and returns where it
        stopped -- so we can ignore everything past the first object.
        """
        start = text.find("{")
        if start < 0:
            raise ValidationError(
                "Reasoning engine did not receive a JSON object from the LLM",
            )
        try:
            parsed, _ = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"Reasoning engine received invalid JSON: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise ValidationError("Reasoning engine expected a top-level JSON object")
        return parsed
