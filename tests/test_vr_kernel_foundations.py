"""Unit tests for v0.5 phase 1 -- kernel + hypervisor foundations."""
from __future__ import annotations

import pytest

from aila.modules.vr.agents.vuln_researcher import _load_prompt
from aila.modules.vr.contracts import TargetKind
from aila.modules.vr.enrichment.services.profile_builder import (
    _APPLICABLE_FUZZING_ENGINES,
    _APPLICABLE_MCP_BY_KIND,
    _DEFAULT_COST_USD,
    _DEFAULT_DISCLOSURE_TRACKS,
    _DEFAULT_REASONING_STRATEGY,
)


class TestTargetKindEnum:
    @pytest.mark.parametrize("value,expected", [
        ("kernel_image", TargetKind.KERNEL_IMAGE),
        ("kernel_module", TargetKind.KERNEL_MODULE),
        ("hypervisor_image", TargetKind.HYPERVISOR_IMAGE),
    ])
    def test_new_v05_kinds_parse(self, value: str, expected: TargetKind) -> None:
        assert TargetKind(value) == expected

    def test_v05_kinds_dont_collide_with_v03(self) -> None:
        v05 = {
            TargetKind.KERNEL_IMAGE.value,
            TargetKind.KERNEL_MODULE.value,
            TargetKind.HYPERVISOR_IMAGE.value,
        }
        all_kinds = {k.value for k in TargetKind}
        # Sanity: total count = original 10 + 3 new
        assert len(all_kinds) == 13
        assert v05.issubset(all_kinds)


class TestProfileRules:
    def test_mcp_routing_kernel(self) -> None:
        assert (
            _APPLICABLE_MCP_BY_KIND[TargetKind.KERNEL_IMAGE.value]
            == ["ida_headless", "audit_mcp"]
        )
        assert (
            _APPLICABLE_MCP_BY_KIND[TargetKind.KERNEL_MODULE.value]
            == ["ida_headless"]
        )

    def test_mcp_routing_hypervisor(self) -> None:
        assert (
            _APPLICABLE_MCP_BY_KIND[TargetKind.HYPERVISOR_IMAGE.value]
            == ["ida_headless", "audit_mcp"]
        )

    def test_kernel_fuzzers_are_syzkaller_kafl(self) -> None:
        assert _APPLICABLE_FUZZING_ENGINES.get(
            (TargetKind.KERNEL_IMAGE.value, "c"),
        ) == ["syzkaller", "kafl"]
        assert _APPLICABLE_FUZZING_ENGINES.get(
            (TargetKind.KERNEL_MODULE.value, "c"),
        ) == ["syzkaller", "kafl"]

    def test_hypervisor_fuzzers_are_aflpp_qemu(self) -> None:
        for lang in ("c", "c++"):
            assert _APPLICABLE_FUZZING_ENGINES.get(
                (TargetKind.HYPERVISOR_IMAGE.value, lang),
            ) == ["afl++", "qemu-fuzz"]

    def test_kernel_reasoning_strategy_default(self) -> None:
        for kind in (TargetKind.KERNEL_IMAGE, TargetKind.KERNEL_MODULE):
            assert _DEFAULT_REASONING_STRATEGY.get(
                (kind.value, "*"),
            ) == "vulnerability_research.kernel_audit"

    def test_hypervisor_reasoning_strategy_default(self) -> None:
        assert _DEFAULT_REASONING_STRATEGY.get(
            (TargetKind.HYPERVISOR_IMAGE.value, "*"),
        ) == "vulnerability_research.hypervisor_audit"

    def test_kernel_default_disclosure(self) -> None:
        # v0.5 phase 3 -- kernel disclosures now point at real tracks.
        for kind in (TargetKind.KERNEL_IMAGE, TargetKind.KERNEL_MODULE):
            tracks = _DEFAULT_DISCLOSURE_TRACKS[kind.value]
            assert "kernel_org_security" in tracks
            assert "linux_distros" in tracks
            assert "oss_security" in tracks
            assert "blog_post" in tracks

    def test_hypervisor_default_disclosure_includes_cert_cc(self) -> None:
        # Hypervisor escapes typically span multiple vendors → cert_cc
        tracks = _DEFAULT_DISCLOSURE_TRACKS[TargetKind.HYPERVISOR_IMAGE.value]
        assert "cert_cc" in tracks
        assert "vendor_direct" in tracks

    def test_kernel_costs_higher_than_userspace(self) -> None:
        # Kernel audits run longer + need syzkaller campaign budget
        kernel_cost = _DEFAULT_COST_USD[TargetKind.KERNEL_IMAGE.value]
        userspace_cost = _DEFAULT_COST_USD[TargetKind.NATIVE_BINARY.value]
        assert kernel_cost > userspace_cost

    def test_hypervisor_is_highest_cost(self) -> None:
        all_costs = list(_DEFAULT_COST_USD.values())
        hv_cost = _DEFAULT_COST_USD[TargetKind.HYPERVISOR_IMAGE.value]
        assert hv_cost == max(all_costs)


class TestPromptLoading:
    async def test_kernel_audit_prompt_loads(self, test_db) -> None:
        text = await _load_prompt("vulnerability_research.kernel_audit")
        assert "kernel audit" in text.lower()
        assert "slab" in text.lower()
        assert "refcount" in text.lower() or "ref-count" in text.lower()

    async def test_hypervisor_audit_prompt_loads(self, test_db) -> None:
        text = await _load_prompt("vulnerability_research.hypervisor_audit")
        assert "hypervisor" in text.lower()
        assert "virtio" in text.lower()
        assert "guest" in text.lower() and "host" in text.lower()

    async def test_kernel_prompt_mentions_hardening(self, test_db) -> None:
        text = await _load_prompt("vulnerability_research.kernel_audit")
        # Prompt should call out the hardening features that invalidate findings
        for term in ("KASLR", "SMEP", "KPTI"):
            assert term in text, f"kernel prompt missing {term}"

    async def test_hypervisor_prompt_mentions_iommu(self, test_db) -> None:
        text = await _load_prompt("vulnerability_research.hypervisor_audit")
        assert "iommu" in text.lower()
        assert "dma" in text.lower()

    async def test_unknown_kernel_strategy_falls_back_to_audit(self, test_db) -> None:
        # Loader strips dotted prefix; an unmapped suffix falls back to
        # the original system_audit.md
        text = await _load_prompt("vulnerability_research.totally_unknown_kernel_thing")
        assert "audit-only investigation" in text
