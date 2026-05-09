"""Phase 7: VR CrashTriageTool unit tests.

Exercises ``parse_asan``, ``compute_signature``, and ``classify_exploitability``
directly (the methods are sync; the async ``forward`` wrapper is just dispatch).
The ASAN sample is a minimal but realistic heap-buffer-overflow report.
"""
from __future__ import annotations

from aila.modules.vr.tools.crash_triage import CrashTriageTool

__all__ = [
    "TestParseAsan",
    "TestComputeSignature",
    "TestClassifyExploitability",
]


_HEAP_OVERFLOW_ASAN = """=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000efb4
READ of size 4 at 0x60200000efb4
    #0 0x55a1234 in ParseHeader /src/parser.c:42
    #1 0x55a5678 in ProcessInput /src/main.c:100
    #2 0x7f0001 in __libc_start_main /lib/libc.so:234
0x60200000efb4 is located 4 bytes to the right of 32-byte region
"""

_UAF_ASAN = """=================================================================
==9999==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000001234
READ of size 8 at 0x602000001234
    #0 0x4001 in DoStuff /src/uaf.c:11
    #1 0x4002 in main /src/uaf.c:50
"""


class TestParseAsan:
    def test_heap_buffer_overflow(self) -> None:
        t = CrashTriageTool()
        r = t.parse_asan(_HEAP_OVERFLOW_ASAN)
        assert r["status"] == "ready"
        assert r["sanitizer"] == "AddressSanitizer"
        assert r["sanitizer_kind"] == "heap-buffer-overflow"
        assert r["crash_type"] == "overflow_heap"
        assert r["access_type"] == "read"
        assert r["access_size"] == 4
        assert r["crash_address"] == "0x60200000efb4"
        assert r["overflow_offset"] == 4
        assert r["overflow_direction"] == "right"
        assert r["region_size"] == 32
        frames = r["stack_frames"]
        assert len(frames) == 3
        assert frames[0]["function"] == "ParseHeader"
        assert frames[0]["depth"] == 0
        assert frames[1]["function"] == "ProcessInput"
        assert frames[2]["function"] == "__libc_start_main"

    def test_use_after_free(self) -> None:
        t = CrashTriageTool()
        r = t.parse_asan(_UAF_ASAN)
        assert r["status"] == "ready"
        assert r["crash_type"] == "uaf"
        assert r["sanitizer_kind"] == "heap-use-after-free"
        assert r["access_type"] == "read"
        assert r["access_size"] == 8

    def test_empty_input_returns_error(self) -> None:
        t = CrashTriageTool()
        r = t.parse_asan("")
        assert r["status"] == "error"
        assert "non-empty" in r["error"]

    def test_whitespace_input_returns_error(self) -> None:
        t = CrashTriageTool()
        r = t.parse_asan("   \n\t  ")
        assert r["status"] == "error"


class TestComputeSignature:
    def test_determinism(self) -> None:
        t = CrashTriageTool()
        frames = ["ParseHeader@/src/parser.c", "ProcessInput@/src/main.c"]
        r1 = t.compute_signature("overflow_heap", frames=frames)
        r2 = t.compute_signature("overflow_heap", frames=frames)
        assert r1["signature_hash"] == r2["signature_hash"]
        # SHA256 hex is 64 chars
        assert len(r1["signature_hash"]) == 64

    def test_aslr_normalization(self) -> None:
        """Hex addresses inside frame tokens collapse to 0x? so ASLR bases
        do not split otherwise-identical crashes."""
        t = CrashTriageTool()
        # Two crashes whose only difference is the leaked ASLR base address
        a = t.compute_signature("overflow_heap", frames=["Foo@0x1234", "Bar@0xabcd"])
        b = t.compute_signature("overflow_heap", frames=["Foo@0x9999", "Bar@0x5555"])
        assert a["signature_hash"] == b["signature_hash"]
        assert a["frames"] == ["Foo@0x?", "Bar@0x?"]

    def test_only_top_5_frames_used(self) -> None:
        t = CrashTriageTool()
        many = [f"frame{i}" for i in range(10)]
        r = t.compute_signature("overflow_heap", frames=many)
        assert r["frames"] == ["frame0", "frame1", "frame2", "frame3", "frame4"]
        # Adding extra frames beyond 5 must not change the hash
        more = many + ["extra1", "extra2"]
        r2 = t.compute_signature("overflow_heap", frames=more)
        assert r["signature_hash"] == r2["signature_hash"]

    def test_empty_crash_type_errors(self) -> None:
        t = CrashTriageTool()
        r = t.compute_signature("", frames=["a"])
        assert r["status"] == "error"
        assert "crash_type" in r["error"]

    def test_dict_frames_supported(self) -> None:
        t = CrashTriageTool()
        r = t.compute_signature(
            "uaf",
            frames=[
                {"depth": 0, "function": "DoStuff", "module": "/src/uaf.c"},
                {"depth": 1, "function": "main", "module": "/src/uaf.c"},
            ],
        )
        assert r["status"] == "ready"
        assert r["frames"] == ["DoStuff@/src/uaf.c", "main@/src/uaf.c"]


class TestClassifyExploitability:
    def test_overflow_heap_controllable(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("overflow_heap", controllable=True)
        assert r["status"] == "ready"
        assert r["verdict"] == "likely_exploitable"

    def test_overflow_heap_uncontrolled_is_possibly_exploitable(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("overflow_heap")
        assert r["verdict"] == "possibly_exploitable"

    def test_null_deref_is_unlikely(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("null_deref")
        assert r["verdict"] == "unlikely"

    def test_oob_read_is_info_disclosure(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("oob_read")
        assert r["verdict"] == "info_disclosure"

    def test_uaf_is_likely_exploitable(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("uaf")
        assert r["verdict"] == "likely_exploitable"

    def test_cmd_injection_is_likely_exploitable(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("cmd_injection")
        assert r["verdict"] == "likely_exploitable"

    def test_empty_crash_type_errors(self) -> None:
        t = CrashTriageTool()
        r = t.classify_exploitability("")
        assert r["status"] == "error"
