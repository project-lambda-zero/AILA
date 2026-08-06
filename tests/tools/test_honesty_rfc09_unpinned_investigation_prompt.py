"""RFC-09 rule 74 (unpinned_investigation_prompt) honesty guardrail.

Rule 74 is the RFC-09 fourth guardrail (design doc
``.run/designs/DESIGN_reasoning_platform.md`` sec 3.6 + threat T6): a
long-running audited investigation must resolve its prompt through the
per-investigation pin, not through the live production alias, so an
operator alias flip mid-run never rewrites the prompt of an already-
running investigation.

The rule fires on an agent-runtime file (``platform/agents/**`` or
``modules/*/agents/**``) whose turn function calls a raw
``.resolve(alias=...)`` on the prompt store or the prompt registry
without :func:`aila.platform.prompts.pinning.resolve_pinned_prompt`
in the same body. Exempt: seed / registration functions
(``seed_prompt_versions``), the platform prompts package
(``platform/prompts/**``, outside the agent-runtime scope), and any
function that goes through ``resolve_pinned_prompt``.

Sibling of rules 58 / 59 / 60 on the pin surface; mirrors rule 66
(``retrieval_without_gate``) as the agent-runtime template of "call
the gated wrapper, not the raw path".
"""
from __future__ import annotations

from pathlib import Path

from aila.tools.honesty_audit import HonestyAuditor

# ---------------------------------------------------------------------------
# Helpers (kept local so this file can move without touching siblings).
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, source: str) -> Path:
    """Write *source* to *base/rel*, creating parent directories."""
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _audit(path: Path) -> list[str]:
    """Return the rule names of findings emitted for *path*."""
    return [f.rule for f in HonestyAuditor().audit_file(path)]


_RULE = "unpinned_investigation_prompt"


# ---------------------------------------------------------------------------
# POSITIVE (rule fires)
# ---------------------------------------------------------------------------


class TestUnpinnedInvestigationPromptFires:
    """A turn in an agent-runtime file resolving by live alias fires."""

    def test_store_resolve_with_alias_kwarg_in_agent_turn(
        self, tmp_path: Path,
    ) -> None:
        """The canonical bad shape: ``store.resolve(key, alias='production')``
        inside a turn function of a module agent-runtime file. No
        ``resolve_pinned_prompt`` in the body -- the pin is bypassed."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/rogue_turn.py",
            "class Rogue:\n"
            "    async def run_turn(self, key):\n"
            "        row = await self._store.resolve(key, alias='production')\n"
            "        return row.body if row is not None else ''\n",
        )
        assert _RULE in _audit(src)

    def test_registry_resolve_with_alias_kwarg_in_platform_agent(
        self, tmp_path: Path,
    ) -> None:
        """The rule also covers ``platform/agents/**``: a raw
        ``registry.resolve(alias=...)`` bypass in a platform-agent
        turn function is caught by the same scope pattern."""
        src = _write(
            tmp_path,
            "aila/platform/agents/rogue_turn.py",
            "class Rogue:\n"
            "    def __init__(self, registry):\n"
            "        self._registry = registry\n"
            "    async def run_turn(self, family):\n"
            "        return await self._registry.resolve(family, alias='production')\n",
        )
        assert _RULE in _audit(src)

    def test_module_level_store_singleton_receiver(
        self, tmp_path: Path,
    ) -> None:
        """The receiver-token guard catches a ``.resolve(...)`` call
        without an explicit ``alias=`` kwarg when the receiver is one
        of the known prompt-store singletons -- the registry's default
        override still rides the live alias."""
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/rogue_turn.py",
            "_PROMPT_VERSION_STORE = None  # bound at import time\n"
            "\n"
            "async def run_turn(key):\n"
            "    return await _PROMPT_VERSION_STORE.resolve(key)\n",
        )
        assert _RULE in _audit(src)

    def test_prompt_registry_class_receiver(
        self, tmp_path: Path,
    ) -> None:
        """A ``PromptRegistry(...).resolve(alias=...)`` chain: the
        constructor-call receiver's callee terminal is ``PromptRegistry``
        which is in the receiver token set, so the shape is caught even
        without an explicit ``alias=`` kwarg on the outer call."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/rogue_turn.py",
            "class Rogue:\n"
            "    async def run_turn(self, family):\n"
            "        return await PromptRegistry(family).resolve(family)\n",
        )
        assert _RULE in _audit(src)


# ---------------------------------------------------------------------------
# NEGATIVE (rule does NOT fire)
# ---------------------------------------------------------------------------


class TestUnpinnedInvestigationPromptExempt:
    """Sanctioned paths that must NOT fire."""

    def test_seed_prompt_versions_function_exempt(
        self, tmp_path: Path,
    ) -> None:
        """Seed / bootstrap legitimately talks to the store directly.
        Mirrors the live ``seed_prompt_versions`` in
        ``vr/agents/vuln_researcher.py`` and
        ``malware/agents/malware_researcher.py``: a
        ``_PROMPT_VERSION_STORE.resolve(key, alias='production')`` call
        inside ``seed_prompt_versions`` must stay silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/vuln_researcher.py",
            "_PROMPT_VERSION_STORE = None\n"
            "\n"
            "async def seed_prompt_versions():\n"
            "    key = 'vr/foo/base'\n"
            "    if await _PROMPT_VERSION_STORE.resolve(key, alias='production') is not None:\n"
            "        return 0\n"
            "    return 1\n",
        )
        assert _RULE not in _audit(src)

    def test_seed_platform_prefix_function_exempt(
        self, tmp_path: Path,
    ) -> None:
        """``seed_platform_*_prompts`` (the shared claim-verifier seed
        pattern shipped under ``platform/agents/claim_verifier.py``)
        must also stay silent. The seed marker set matches by
        substring so a new platform-owned seed helper is exempt
        without a manual whitelist entry."""
        src = _write(
            tmp_path,
            "aila/platform/agents/claim_verifier.py",
            "async def seed_platform_claim_verifier_prompts(store):\n"
            "    key = 'platform/claim_verifier/extractor'\n"
            "    if await store.resolve(key, alias='production') is not None:\n"
            "        return 0\n"
            "    return 1\n",
        )
        assert _RULE not in _audit(src)

    def test_platform_prompts_package_out_of_scope(
        self, tmp_path: Path,
    ) -> None:
        """``platform/prompts/**`` owns the raw resolve and is outside
        the agent-runtime scope pattern; a ``store.resolve(alias=...)``
        there does not fire (the registry / store / pinning files call
        each other legitimately)."""
        src = _write(
            tmp_path,
            "aila/platform/prompts/registry.py",
            "class PromptRegistry:\n"
            "    def __init__(self, store):\n"
            "        self._store = store\n"
            "    async def resolve(self, key):\n"
            "        return await self._store.resolve(key, alias='production')\n",
        )
        assert _RULE not in _audit(src)

    def test_agent_turn_going_through_resolve_pinned_prompt(
        self, tmp_path: Path,
    ) -> None:
        """An agent turn that DOES go through ``resolve_pinned_prompt``
        is the canonical good shape. The pin marker in the body clears
        the rule even when the underlying store also appears (the
        wrapper itself internally calls ``store.resolve(...)`` inside
        the pinning module -- but the caller stays honest by delegating
        through the wrapper)."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/honest_turn.py",
            "async def run_turn(investigation_id, key):\n"
            "    body, version = await resolve_pinned_prompt(\n"
            "        investigation_id=investigation_id, key=key,\n"
            "    )\n"
            "    return body, version\n",
        )
        assert _RULE not in _audit(src)

    def test_non_agent_runtime_file_out_of_scope(
        self, tmp_path: Path,
    ) -> None:
        """A module ``services/**`` file is NOT agent-runtime and stays
        out of scope even when it calls ``.resolve(alias=...)`` on the
        store. The rule locks in the agent-turn resolve path only."""
        src = _write(
            tmp_path,
            "aila/modules/vr/services/some_service.py",
            "async def load(store, key):\n"
            "    return await store.resolve(key, alias='production')\n",
        )
        assert _RULE not in _audit(src)

    def test_unrelated_resolve_receiver_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A ``.resolve(...)`` call on an unrelated receiver (a domain
        profile registry, a task registry, ...) with no ``alias=``
        kwarg is NOT flagged: the receiver-token guard is precise to
        the prompt store / registry bindings."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/unrelated_call.py",
            "async def run_turn(profile_registry, domain_id):\n"
            "    return profile_registry.resolve(domain_id)\n",
        )
        assert _RULE not in _audit(src)
