"""Tests for the module-supplied knowledge hooks (issue #136).

Covers the three seams introduced when the FFmpeg / nginx / kernel /
persona vocabulary moved out of ``platform/agents/`` and onto module
subclass ClassVars:

* ``AgentTurnRunnerBase.known_allocators`` /
  ``AgentTurnRunnerBase.known_input_readers`` -- the defense-check
  submit gate vocabulary.
* ``ToolExecutorHelpersBase.lateral_patterns`` -- the auto-steering
  Rule 5 lateral-vulnerability scan vocabulary.
* ``PersonaRouter.persona_role_map`` -- the persona-to-role map used
  by role-based ``task_type`` resolution.

Behavior preservation: with VR's ClassVars populated the pre-refactor
outcomes match exactly. Graceful degradation: an empty ClassVar makes
each hook a no-op instead of a crash or a false rejection.
"""
from __future__ import annotations

import re

from aila.modules.vr.agents.tool_executor import ToolExecutor as VRToolExecutor
from aila.modules.vr.agents.vuln_researcher import HonestVulnResearcher
from aila.platform.agents.auto_steering import _detect_lateral_pattern
from aila.platform.agents.persona_router import PersonaRouter
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.agents.turn_runner import AgentTurnRunnerBase


class TestPlatformDefaultsAreEmpty:
    """No FFmpeg / nginx / persona vocabulary bleeds out of the platform."""

    def test_turn_runner_base_has_empty_allocator_vocab(self) -> None:
        assert AgentTurnRunnerBase.known_allocators == frozenset()
        assert AgentTurnRunnerBase.known_input_readers == frozenset()

    def test_tool_executor_base_has_empty_lateral_patterns(self) -> None:
        assert ToolExecutorHelpersBase.lateral_patterns == []

    def test_persona_router_base_has_empty_role_map(self) -> None:
        assert PersonaRouter.persona_role_map == {}


class TestVRSuppliesVocabulary:
    """VR's subclasses supply the migrated vocabulary."""

    def test_vr_researcher_populates_allocator_vocab(self) -> None:
        # Sampled entries from the FFmpeg / libc / nginx / kernel /
        # OpenSSL banks -- a silent deletion of any bank surfaces here.
        allocators = HonestVulnResearcher.known_allocators
        assert "av_calloc" in allocators                # FFmpeg
        assert "malloc" in allocators                   # libc
        assert "ngx_palloc" in allocators               # nginx
        assert "kmalloc" in allocators                  # Linux kernel
        assert "OPENSSL_malloc" in allocators           # OpenSSL
        assert "g_malloc" in allocators                 # GLib
        assert "apr_palloc" in allocators               # Apache httpd

    def test_vr_researcher_populates_input_reader_vocab(self) -> None:
        readers = HonestVulnResearcher.known_input_readers
        assert "avio_rb16" in readers                   # FFmpeg AVIO
        assert "get_bits" in readers                    # FFmpeg bitstream
        assert "bytestream2_get_le32" in readers        # FFmpeg bytestream
        assert "AV_RL16" in readers                     # FFmpeg macro
        assert "recv" in readers                        # POSIX

    def test_vr_tool_executor_populates_lateral_patterns(self) -> None:
        patterns = VRToolExecutor.lateral_patterns
        pattern_ids = {pid for _pat, pid in patterns}
        assert pattern_ids == {
            "protocol_passthrough_no_check",
            "unchecked_int_multiply",
            "memop_variable_length",
            "truncating_dimension_shift",
            "input_to_allocation",
        }
        for pat, _pid in patterns:
            assert isinstance(pat, re.Pattern)


class TestLateralPatternDetectionWithVRVocabulary:
    """Behavior preservation: VR's lateral patterns match the same
    FFmpeg-shaped source snippets they matched before the refactor."""

    def test_protocol_passthrough_matches(self) -> None:
        # ``else if (av_strstart(proto, "http", NULL)) ;`` -- pattern 1
        body = (
            "if (av_strstart(proto, \"tcp\", NULL)) return 0;\n"
            "else if (av_strstart(proto, \"http\", NULL)) ;\n"
        )
        findings = _detect_lateral_pattern(
            "audit_mcp", "read_function",
            {"file_path": "libavformat/protocol.c", "name": "url_open"},
            {"content": body},
            VRToolExecutor.lateral_patterns,
        )
        pids = {f["pattern"] for f in findings}
        assert "protocol_passthrough_no_check" in pids

    def test_unchecked_int_multiply_matches(self) -> None:
        # ``int size = w * h;`` -- pattern 2
        body = "void codec_probe(int w, int h) {\n    int size = w * h;\n}\n"
        findings = _detect_lateral_pattern(
            "audit_mcp", "read_function",
            {"file_path": "libavcodec/x.c", "name": "codec_probe"},
            {"content": body},
            VRToolExecutor.lateral_patterns,
        )
        pids = {f["pattern"] for f in findings}
        assert "unchecked_int_multiply" in pids

    def test_input_to_allocation_flow_matches(self) -> None:
        # ``avio_rb32(...); ... av_malloc(...)`` -- pattern 5
        body = (
            "static int decode(AVFormatContext *s) {\n"
            "    uint32_t len = avio_rb32(s->pb);\n"
            "    void *buf = av_malloc(len);\n"
            "    return 0;\n"
            "}\n"
        )
        findings = _detect_lateral_pattern(
            "audit_mcp", "read_function",
            {"file_path": "libavformat/x.c", "name": "decode"},
            {"content": body},
            VRToolExecutor.lateral_patterns,
        )
        pids = {f["pattern"] for f in findings}
        assert "input_to_allocation" in pids

    def test_clean_body_produces_no_findings(self) -> None:
        body = "static int is_prime(int n) {\n    return n > 1;\n}\n"
        findings = _detect_lateral_pattern(
            "audit_mcp", "read_function",
            {"file_path": "util/prime.c", "name": "is_prime"},
            {"content": body},
            VRToolExecutor.lateral_patterns,
        )
        assert findings == []


class TestLateralPatternGracefulNoOp:
    """Empty lateral_patterns (malware, forensics, hello_world today)
    turns the scan into a no-op -- no crash, no findings, no cost."""

    def test_empty_patterns_returns_empty(self) -> None:
        # A body that WOULD match VR's patterns is silently ignored
        # when the module publishes no lateral vocabulary.
        body = "int size = w * h;\n"
        findings = _detect_lateral_pattern(
            "audit_mcp", "read_function",
            {"file_path": "x.c", "name": "f"},
            {"content": body},
            [],  # empty -- the platform base default
        )
        assert findings == []

    def test_empty_patterns_ignores_non_audit_mcp_server(self) -> None:
        findings = _detect_lateral_pattern(
            "ida_headless", "read_function",
            {"name": "f"}, {"content": "int size = w * h;"},
            VRToolExecutor.lateral_patterns,
        )
        # audit_mcp restriction stays; not a scan-worthy server_id.
        assert findings == []

    def test_empty_patterns_ignores_non_source_surfacing_tool(self) -> None:
        findings = _detect_lateral_pattern(
            "audit_mcp", "callers_of",
            {"name": "f"}, {"content": "int size = w * h;"},
            VRToolExecutor.lateral_patterns,
        )
        # Only read_function / read_lines / semantic_search are scanned.
        assert findings == []


class TestPlatformBoundaryPreserved:
    """Guardrail: the platform files must NOT reference the FFmpeg /
    nginx / persona-name vocabulary any more. Grep-style check that
    keeps drift caught in tests instead of a manual audit."""

    def test_submit_gates_has_no_ffmpeg_names(self) -> None:
        import inspect
        from aila.platform.agents import submit_gates
        source = inspect.getsource(submit_gates)
        # Sample of migrated names; any of these leaking back into the
        # platform gate re-opens the boundary.
        for name in (
            "av_malloc", "av_calloc", "avio_rb16",
            "ngx_palloc", "kmalloc", "OPENSSL_malloc",
        ):
            assert name not in source, f"platform submit_gates still references {name!r}"

    def test_auto_steering_has_no_ffmpeg_regex_vocab(self) -> None:
        import inspect
        from aila.platform.agents import auto_steering
        source = inspect.getsource(auto_steering)
        # The migrated regex fragments named FFmpeg-specific primitives.
        for name in ("av_strstart", "bytestream2_get", "av_mallocz"):
            assert name not in source, f"platform auto_steering still references {name!r}"

    def test_persona_router_has_no_hardcoded_persona_names(self) -> None:
        import inspect
        from aila.platform.agents import persona_router
        source = inspect.getsource(persona_router)
        # The six voice names are the domain vocabulary -- platform
        # base must not carry them as data literals any more.
        for name in ("HALVAR", "NOOR", "RENZO", "WEI", "MADDIE", "YUKI"):
            assert (
                f"PersonaVoice.{name}" not in source
            ), f"platform persona_router still hardcodes PersonaVoice.{name}"
