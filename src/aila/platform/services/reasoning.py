from __future__ import annotations

import json
import logging

_log = logging.getLogger(__name__)

from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningDomainProfile,
    ReasoningEvidenceGraph,
    ReasoningGraphEdge,
    ReasoningGraphNode,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    ReasoningStrategyFamily,
    ReasoningTurnDecision,
 )
from aila.platform.exceptions import ValidationError
from aila.platform.llm.client import AilaLLMClient

__all__ = ["CyberReasoningEngine"]


_DOMAIN_PROFILES: dict[str, ReasoningDomainProfile] = {
    "forensics": ReasoningDomainProfile(
        domain_id="forensics",
        task_type="forensics_freeflow",
        description="Evidence-driven static forensic investigation.",
        allowed_strategies=[
            "filesystem_triage",
            "persistence_hunt",
            "memory_forensics",
            "network_forensics",
            "malware_static",
            "generic",
        ],
        default_strategy="filesystem_triage",
    ),
    "vulnerability_research": ReasoningDomainProfile(
        domain_id="vulnerability_research",
        task_type="vulnerability_research",
        description="Exploitability, advisories, versions, and remediation reasoning.",
        allowed_strategies=["vulnerability_research", "generic"],
        default_strategy="vulnerability_research",
    ),
    "web_pentest": ReasoningDomainProfile(
        domain_id="web_pentest",
        task_type="web_pentest",
        description="Attack-path and web application security reasoning.",
        allowed_strategies=["web_pentest", "network_forensics", "generic"],
        default_strategy="web_pentest",
    ),
    "mobile_reverse": ReasoningDomainProfile(
        domain_id="mobile_reverse",
        task_type="mobile_reverse",
        description="APK/IPA reverse engineering and mobile app threat analysis.",
        allowed_strategies=["mobile_reverse", "malware_static", "generic"],
        default_strategy="mobile_reverse",
    ),
}


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

    def __init__(self, llm_client: AilaLLMClient) -> None:
        self._llm_client = llm_client

    def resolve_domain_profile(self, domain_id: str) -> ReasoningDomainProfile:
        """Return the built-in reasoning profile for the requested domain.

        Falls back to a generic single-strategy profile when the domain is not
        registered in ``_DOMAIN_PROFILES``.
        """
        profile = _DOMAIN_PROFILES.get(domain_id)
        if profile is not None:
            return profile
        return ReasoningDomainProfile(
            domain_id=domain_id,
            task_type=domain_id,
            description="Custom reasoning domain.",
            allowed_strategies=["generic"],
            default_strategy="generic",
        )

    async def decide_next_turn(
        self,
        *,
        task_type: str,
        system_prompt: str,
        user_prompt: str,
    ) -> ReasoningTurnDecision:
        """Return the next reasoning turn as a validated decision model.

        Uses ``chat_structured`` so the OpenAI-compatible gateway enforces
        the ReasoningTurnDecision JSON schema upstream when the routed
        model supports strict mode. Falls back to client-side parsing
        when the model emits something close-but-not-exact (handled
        below by the normalizer + extractor).
        """
        response = await self._llm_client.chat_structured(
            task_type=task_type,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model_class=ReasoningTurnDecision,
        )
        if response.disabled:
            raise RuntimeError("LLM kill-switch active")
        raw = self._extract_json_object(response.content)
        # LLMs sometimes return null for required string fields.
        # Patch the raw dict so validation doesn't crash the turn,
        # but log a warning — the model should be producing these.
        for str_field in ('expected_observation', 'reasoning'):
            if str_field in raw and raw[str_field] is None:
                _log.warning(
                    'LLM returned null for required field %s — defaulting to empty string. '
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
                _log.info('LLM nested command under tool_run key — lifted to top level')
            elif nested and isinstance(nested.get('tool'), str):
                raw['command'] = json.dumps({
                    'tool': nested['tool'],
                    'args': nested.get('args') or {},
                })
                _log.info(
                    'LLM nested tool/args under tool_run key — synthesized '
                    'command for tool=%s', nested['tool'],
                )
            elif isinstance(raw.get('tool'), str):
                raw['command'] = json.dumps({
                    'tool': raw['tool'],
                    'args': raw.get('args') or {},
                })
                _log.info(
                    'LLM emitted top-level tool/args instead of nested command — '
                    'synthesized command for tool=%s', raw['tool'],
                )
        return ReasoningTurnDecision.model_validate(raw)

    def absorb(
        self,
        case_state: ReasoningCaseState,
        decision: ReasoningTurnDecision,
    ) -> ReasoningCaseState:
        """Merge a turn decision into cumulative reasoning state."""
        contract = case_state.contract
        if decision.contract is not None and not self._has_contract(case_state.contract):
            contract = decision.contract

        # Merge live hypotheses across turns instead of replacing.
        # The LLM emits its CURRENT view each turn, but it may forget
        # to repeat earlier ones — that previously caused live
        # hypotheses to vanish silently. We:
        #   1. Start with the existing live list
        #   2. Drop any whose id is in the new rejected set
        #   3. Upsert each new hypothesis: replace existing by id,
        #      append unknown ones
        # Result: nothing the agent ever proposed disappears; the
        # only way to remove a hypothesis is to explicitly reject it.
        rejected = list(case_state.rejected)
        seen_rejected = {(item.id, item.claim) for item in rejected}
        for item in decision.rejected:
            key = (item.id, item.claim)
            if key in seen_rejected:
                continue
            seen_rejected.add(key)
            rejected.append(item)
        newly_rejected_ids = {item.id for item in decision.rejected if item.id}

        merged_live = [
            h for h in case_state.hypotheses if h.id not in newly_rejected_ids
        ]
        for new_h in decision.hypotheses or []:
            if not new_h.id:
                merged_live.append(new_h)
                continue
            for i, existing in enumerate(merged_live):
                if existing.id == new_h.id:
                    merged_live[i] = new_h
                    break
            else:
                merged_live.append(new_h)

        observables = dict(case_state.observables)
        observables.update({k: v for k, v in decision.observables.items() if str(k).strip()})

        return ReasoningCaseState(
            contract=contract,
            hypotheses=merged_live,
            rejected=rejected,
            observables=observables,
        )

    def render_case_model(self, case_state: ReasoningCaseState) -> str:
        """Render a compact textual case model for the next turn prompt."""
        parts: list[str] = []
        if self._has_contract(case_state.contract):
            parts.append("Contract:")
            parts.append(f"  answer_type   = {case_state.contract.answer_type}")
            parts.append(f"  answer_format = {case_state.contract.answer_format}")
            parts.append(f"  evidence      = {case_state.contract.evidence_domain}")
            if case_state.contract.depends_on:
                parts.append(f"  depends_on    = {case_state.contract.depends_on}")
        else:
            parts.append("Contract: (not parsed yet — derive it this turn)")

        if case_state.observables:
            parts.append("Observables:")
            for key, value in list(case_state.observables.items())[:40]:
                parts.append(f"  - {key} = {value}")
        else:
            parts.append("Observables: (none yet)")

        if case_state.hypotheses:
            parts.append("Live hypotheses:")
            for hypothesis in case_state.hypotheses[:6]:
                parts.append(f"  - {hypothesis.id or '?'}: {hypothesis.claim}")
                if hypothesis.kill_criterion:
                    parts.append(f"      kill: {hypothesis.kill_criterion}")
        else:
            parts.append("Live hypotheses: (propose 2-3 this turn)")

        if case_state.rejected:
            parts.append(f"Rejected (do not re-propose, {len(case_state.rejected)} total):")
            for rejected in case_state.rejected[:10]:
                parts.append(f"  - {rejected.id or '?'}: {rejected.claim} ({rejected.reason})")

        return "\n".join(parts)

    def build_user_prompt(self, context: ReasoningPromptContext) -> str:
        """Build the user-prompt payload for one reasoning turn.

        This moves prompt framing out of individual modules so every future
        cyber domain shares one turn contract and one operator-facing context
        layout, while still allowing modules to provide domain evidence and
        artifacts.
        """
        n_evidence = context.evidence_listing.count("\n") + 1 if context.evidence_listing.strip() else 0
        n_artifacts = context.artifacts.count("\n== ") if context.artifacts else 0
        parts: list[str] = [
            f"Turn {context.turn}/{context.max_turns}. User question:",
            context.question,
            "",
            f"Reasoning domain profile: {context.domain_profile}",
            f"Preferred strategy family: {context.strategy_family}",
            "",
        ]
        steering = context.operator_steering
        if (
            steering.confirmed_facts
            or steering.disproved_hypotheses
            or steering.guidance
            or steering.required_artifacts
            or steering.pinned_strategy_family is not None
        ):
            parts.append("OPERATOR STEERING:")
            if steering.pinned_strategy_family is not None:
                parts.append(f"  pinned_strategy_family = {steering.pinned_strategy_family}")
            for fact in steering.confirmed_facts:
                parts.append(f"  confirmed_fact = {fact}")
            for rejected in steering.disproved_hypotheses:
                parts.append(f"  disproved_hypothesis = {rejected}")
            for artifact in steering.required_artifacts:
                parts.append(f"  required_artifact = {artifact}")
            for item in steering.guidance:
                parts.append(f"  guidance = {item}")
            parts.append("")
        if context.project_kind == "raw_directory":
            parts.extend([
                "PROJECT KIND: raw_directory",
                (
                    "The evidence directory is a real filesystem on the analyzer (rootfs "
                    "/ loose-files). There is no disk image. Do NOT call dissect.target, "
                    "volatility3, or tshark. Read files directly by absolute path using "
                    "cat / Get-Content / Python open(). Treat every file in the listing as "
                    "already accessible on the analyzer filesystem."
                ),
                "",
            ])
        parts.extend([
            f"Evidence directory: {context.evidence_dir}",
            f"Evidence files on disk ({n_evidence}):",
            context.evidence_listing or "(no evidence catalogued)",
            "",
            "Case model so far:",
            context.case_model,
            "",
            f"Artefacts already collected on this project ({n_artifacts} records):",
            context.artifacts or "(no artefacts collected yet)",
            "",
            "Transcript (last turns):",
            context.previous or "(no previous turns)",
            "",
            "Return a single JSON object matching the response contract.",
        ])
        return "\n".join(parts)

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
            return "provenance.primary_artifact is empty — need a concrete citation"
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
        stopped — so we can ignore everything past the first object.
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
