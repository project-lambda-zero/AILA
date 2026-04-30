from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..llm import AilaLLMClient

from ...storage.memory import PermanentMemoryStore
from ..contracts.platform import (
    RouteCandidate,
    RouteDecision,
    RoutingCandidateProfile,
    RoutingSelection,
)
from ..exceptions import UpstreamError
from ..modules.protocol import UNROUTABLE_ACTION_ID, ModuleCapabilityProfile
from .cache import DecisionCache, decision_cache_key


class ModuleRouter:
    """Two-tier router that maps user queries to module.action pairs.

    Tier 1 -- cache: checks DecisionCache for a matching unexpired routing
    decision keyed on the query + module profiles hash.

    Tier 2 -- model: sends a structured JSON prompt to AilaLLMClient listing
    all registered module capability profiles as candidates. The model returns
    the best module_id + action_id with a confidence score.

    Decisions below minimum_confidence are treated as unroutable.
    """

    def __init__(
        self,
        module_registry: Any,
        minimum_confidence: float = 0.2,
        model: AilaLLMClient | None = None,
        memory_store: PermanentMemoryStore | None = None,
        decision_cache_ttl_hours: int = 0,
    ):
        self.module_registry = module_registry
        self.minimum_confidence = minimum_confidence
        self.model = model
        self.decision_cache = (
            DecisionCache(
                memory_store=memory_store,
                namespace="platform.routing_decisions",
                ttl_hours=decision_cache_ttl_hours,
            )
            if memory_store is not None and decision_cache_ttl_hours > 0
            else None
        )

    async def route(self, session: Any, query: str) -> RouteDecision:
        """Route the user query to the best module action."""
        profiles = list(self.module_registry.capability_profiles())
        if not profiles:
            return RouteDecision(
                action_id=UNROUTABLE_ACTION_ID,
                selected_module=None,
                decision_source="unavailable",
                candidates=[],
            )
        selection, candidates, decision_source = await self._route_selection(session=session, query=query, profiles=profiles)
        if not candidates:
            return RouteDecision(
                action_id=UNROUTABLE_ACTION_ID,
                selected_module=None,
                confidence=selection.confidence,
                rationale=selection.rationale,
                decision_source=decision_source,
                candidates=candidates,
            )
        best = candidates[0]
        if selection.confidence < self.minimum_confidence:
            return RouteDecision(
                action_id=UNROUTABLE_ACTION_ID,
                selected_module=None,
                confidence=selection.confidence,
                rationale=selection.rationale,
                decision_source=decision_source,
                candidates=candidates,
            )
        return RouteDecision(
            action_id=best.action_id,
            selected_module=best.module_id,
            confidence=selection.confidence,
            rationale=selection.rationale,
            decision_source=decision_source,
            candidates=candidates,
        )

    async def _route_selection(
        self,
        *,
        session: Any,
        query: str,
        profiles: list[ModuleCapabilityProfile],
    ) -> tuple[RoutingSelection, list[RouteCandidate], str]:
        """Run the two-tier cache -> model routing logic."""
        cache_key = self._cache_key(query=query, profiles=profiles)
        if self.decision_cache is not None:
            cached = await self.decision_cache.load(session, key=cache_key)
            if cached is not None:
                try:
                    return (
                        self._selection_from_payload(cached.payload, profiles),
                        self._candidates_from_payload(cached.payload),
                        cached.source,
                    )
                except Exception:
                    pass
        selection, candidates = await self._route_with_model(query, profiles)
        if self.decision_cache is not None:
            await self.decision_cache.store(
                session,
                key=cache_key,
                payload={
                    "selection": selection.model_dump(mode="json"),
                    "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
                },
                commit=False,
            )
        return selection, candidates, "model"

    async def _route_with_model(
        self,
        query: str,
        profiles: list[ModuleCapabilityProfile],
    ) -> tuple[RoutingSelection, list[RouteCandidate]]:
        """Send the query and profiles to AilaLLMClient and parse the selection."""
        if self.model is None:
            raise RuntimeError("Platform routing requires an active model.")
        profile_index = {
            (profile.module_id, profile.action_id): profile
            for profile in profiles
        }
        serialized_profiles = [RoutingCandidateProfile.from_profile(profile) for profile in profiles]
        prompt = (
            "Choose the best module action for the user's request.\n"
            "Return JSON only with fields: module_id, action_id, confidence, rationale, alternates.\n"
            "Confidence must be 0..1.\n"
            "Alternates must contain zero to three other provided candidates with scores.\n"
            "Never invent a module_id or action_id.\n"
            f"User query: {query}\n"
            f"Candidates: {json.dumps([item.model_dump(mode='json') for item in serialized_profiles], separators=(',', ':'))}"
        )
        schema = RoutingSelection.model_json_schema()
        try:
            response = await self.model.chat_json(
                "routing",
                [{"role": "user", "content": prompt}],
                schema,
            )
            content = response.content or "{}"
            selection = RoutingSelection.model_validate(json.loads(content))
        except Exception as exc:
            # Surface raw content + upstream exception for operator diagnosis.
            import logging as _log_mod
            _log_mod.getLogger(__name__).warning(
                "router.parse_failed exc_type=%s exc=%r content=%r",
                type(exc).__name__, exc, locals().get("content", "<no response>"),
            )
            raise UpstreamError(
                f"Router model did not return a valid routing selection. "
                f"upstream_error={type(exc).__name__}: {str(exc)[:200]}"
            ) from exc

        selected_key = (selection.module_id, selection.action_id)
        if selected_key not in profile_index:
            raise RuntimeError(
                f"Router selected unknown action '{selection.action_id}' for module '{selection.module_id}'."
            )

        ordered_candidates: list[RouteCandidate] = [
            RouteCandidate(
                module_id=selection.module_id,
                action_id=selection.action_id,
                score=round(selection.confidence, 4),
                tools=list(profile_index[selected_key].tools),
            )
        ]
        seen = {selected_key}
        for alternate in selection.alternates:
            alternate_key = (alternate.module_id, alternate.action_id)
            if alternate_key in seen or alternate_key not in profile_index:
                continue
            seen.add(alternate_key)
            ordered_candidates.append(
                RouteCandidate(
                    module_id=alternate.module_id,
                    action_id=alternate.action_id,
                    score=round(alternate.confidence, 4),
                    tools=list(profile_index[alternate_key].tools),
                )
            )
        return selection, ordered_candidates

    def _cache_key(self, *, query: str, profiles: list[ModuleCapabilityProfile]) -> str:
        return decision_cache_key(
            scope="route",
            payload={
                "query": str(query or "").strip(),
                "minimum_confidence": self.minimum_confidence,
                "profiles": [
                    RoutingCandidateProfile.from_profile(profile).model_dump(mode="json")
                    for profile in profiles
                ],
            },
        ) if self.decision_cache is not None else ""

    @staticmethod
    def _selection_from_payload(payload: dict, profiles: list[ModuleCapabilityProfile]) -> RoutingSelection:
        selection_payload = payload.get("selection")
        if not isinstance(selection_payload, dict):
            raise RuntimeError("Cached routing decision is missing selection payload.")
        selection = RoutingSelection.model_validate(selection_payload)
        valid_pairs = {(profile.module_id, profile.action_id) for profile in profiles}
        if (selection.module_id, selection.action_id) not in valid_pairs:
            raise RuntimeError("Cached routing decision references an unavailable module action.")
        return selection

    @staticmethod
    def _candidates_from_payload(payload: dict) -> list[RouteCandidate]:
        candidates_payload = payload.get("candidates")
        if not isinstance(candidates_payload, list):
            raise RuntimeError("Cached routing decision is missing candidates payload.")
        return [RouteCandidate.model_validate(candidate) for candidate in candidates_payload]
