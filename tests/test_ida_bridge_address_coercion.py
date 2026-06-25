"""IDA bridge: coerce IDA auto-name strings on address kwargs.

The bridge's ``_coerce_ida_autoname_to_address`` classmethod rewrites
agent-supplied IDA-style auto-names (``sub_474FC0``, ``loc_4012A0``,
``unk_402100``, ...) into ``0x<hex>`` strings before dispatch. Without
this step, MCP tools that declare an integer-shaped address kwarg
(``build_call_tree.root_address`` is the lead case) reject the call
with ``ValueError: invalid literal for int() with base 16: 'sub_...'``
and the agent burns a turn re-asking with the address it could have
extracted from the name itself.

These tests pin the pattern matrix + the kwargs-name allowlist.
"""
from __future__ import annotations

from aila.platform.mcp.bridges.ida_headless import IDABridgeTool


class TestIDAAutonameCoercion:
    def test_sub_prefix(self) -> None:
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "build_call_tree",
            {"binary_id": "b", "root_address": "sub_474FC0"},
        )
        assert out["root_address"] == "0x474FC0"
        assert out["binary_id"] == "b"
        assert len(notes) == 1
        assert "sub_474FC0" in notes[0]
        assert "0x474FC0" in notes[0]

    def test_every_known_prefix(self) -> None:
        # All 13 IDA auto-name prefixes the bridge recognizes.
        prefixes = [
            "sub", "loc", "unk", "byte", "word", "dword", "qword",
            "off", "nullsub", "j", "asc", "stru", "flt", "dbl",
            "tbyte", "packreal", "locret",
        ]
        for p in prefixes:
            out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
                "xrefs_to", {"address": f"{p}_402100"},
            )
            assert out["address"] == "0x402100", f"prefix {p!r} not coerced"
            assert len(notes) == 1, f"prefix {p!r} produced wrong note count"

    def test_lowercase_hex_tail(self) -> None:
        out, _ = IDABridgeTool._coerce_ida_autoname_to_address(
            "build_call_tree",
            {"root_address": "sub_4abc12"},
        )
        assert out["root_address"] == "0x4abc12"

    def test_real_label_passes_through(self) -> None:
        # `_main` / `wmain` / `WinMain` / `main` -- the bridge doesn't
        # know the address, so it leaves the value untouched and lets
        # the MCP server surface the real \"address not hex\" error.
        for raw in ["_main", "wmain", "WinMain", "main", "DllEntryPoint"]:
            out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
                "build_call_tree",
                {"root_address": raw},
            )
            assert out["root_address"] == raw
            assert notes == []

    def test_already_hex_passes_through(self) -> None:
        # If the agent already passed a hex address, leave it alone.
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "build_call_tree",
            {"root_address": "0x474FC0"},
        )
        assert out["root_address"] == "0x474FC0"
        assert notes == []

    def test_every_address_kwarg_name_coerced(self) -> None:
        # All 15 address-shaped kwarg names in the bridge's allowlist.
        # Verifies the full sweep -- a single missing entry here is a
        # site where the agent's auto-name would fail with `invalid
        # literal for int() with base 16`.
        for kw in [
            "address", "ea",
            "function_address", "caller_address", "callee_address",
            "target_function", "decryptor_address",
            "root_address", "source_address", "sink_address",
            "target_address", "start_address", "end_address",
            "from_address", "to_address",
            "focus_address", "address_or_name",
        ]:
            out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
                "any_tool", {kw: "sub_402100"},
            )
            assert out[kw] == "0x402100", f"kwarg {kw!r} not coerced"
            assert notes, f"kwarg {kw!r} produced no note"

    def test_address_list_kwarg(self) -> None:
        # avoid_addresses is a list. Walk each elem; rewrite auto-names
        # in-place. Real labels and non-string entries pass through.
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "find_paths",
            {"avoid_addresses": ["sub_474FC0", "wmain", "0x401000", 42]},
        )
        assert out["avoid_addresses"] == ["0x474FC0", "wmain", "0x401000", 42]
        assert len(notes) == 1
        assert "coerced 1" in notes[0]

    def test_address_or_name_coerced(self) -> None:
        # ``address_or_name`` IS in the allowlist now -- the coercion
        # regex only matches IDA auto-names, so real labels still
        # pass through (covered by test_real_label_passes_through).
        # Tools like disassemble_function advertise "address_or_name"
        # but reject names at runtime; coercing the auto-name's
        # embedded address keeps those calls working.
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "disassemble_function",
            {"address_or_name": "sub_474FC0"},
        )
        assert out["address_or_name"] == "0x474FC0"
        assert len(notes) == 1

    def test_non_address_kwarg_untouched(self) -> None:
        # Kwargs NOT in ``_ADDRESS_KWARG_NAMES`` get no coercion,
        # even when the value looks like an IDA auto-name.
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "some_tool",
            {"function": "sub_474FC0"},
        )
        assert out["function"] == "sub_474FC0"
        assert notes == []

    def test_substring_match_rejected(self) -> None:
        # The pattern is anchored ^...$ so a label that happens to
        # contain `sub_<hex>` in the middle does not get rewritten.
        out, _ = IDABridgeTool._coerce_ida_autoname_to_address(
            "build_call_tree",
            {"root_address": "my_sub_474FC0_wrapper"},
        )
        assert out["root_address"] == "my_sub_474FC0_wrapper"

    def test_empty_kwargs(self) -> None:
        out, notes = IDABridgeTool._coerce_ida_autoname_to_address(
            "x", {},
        )
        assert out == {}
        assert notes == []

    def test_non_string_value_skipped(self) -> None:
        # An int address goes through untouched.
        out, _ = IDABridgeTool._coerce_ida_autoname_to_address(
            "build_call_tree",
            {"root_address": 0x474FC0},
        )
        assert out["root_address"] == 0x474FC0
