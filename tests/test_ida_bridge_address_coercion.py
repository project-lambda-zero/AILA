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


class TestEncodingValueCoercion:
    """``encoding`` value normalization on string-family tools.

    The MCP server's ``list_strings`` emits hits under ``by_encoding``
    with the label ``"utf16le"`` but the historical filter on the
    server only accepted ``"utf16"``. An agent reading ``count_only``
    output and passing the observed encoding label back as a filter
    got zero matches (false negative -- killed sibling-branch
    second-stage hunts on masson). The bridge now rewrites the alias
    forms to the canonical ``"utf16le"`` before dispatch.
    """

    def test_utf16_aliased_to_utf16le_on_list_strings(self) -> None:
        out, notes = IDABridgeTool._coerce_encoding_value(
            "list_strings",
            {"binary_id": "b", "encoding": "utf16"},
        )
        assert out["encoding"] == "utf16le"
        assert len(notes) == 1 and "utf16" in notes[0]

    def test_hyphen_variants_aliased(self) -> None:
        for variant in ("utf-16", "utf-16le", "utf16-le", "UTF-16LE"):
            out, _ = IDABridgeTool._coerce_encoding_value(
                "list_strings",
                {"encoding": variant},
            )
            assert out["encoding"] == "utf16le", f"variant {variant!r} not normalized"

    def test_canonical_utf16le_passes_through_silently(self) -> None:
        # Already canonical -- no rewrite, no note.
        out, notes = IDABridgeTool._coerce_encoding_value(
            "list_strings",
            {"encoding": "utf16le"},
        )
        assert out["encoding"] == "utf16le"
        assert notes == []

    def test_ascii_and_all_untouched(self) -> None:
        for value in ("ascii", "all"):
            out, notes = IDABridgeTool._coerce_encoding_value(
                "list_strings",
                {"encoding": value},
            )
            assert out["encoding"] == value
            assert notes == []

    def test_non_string_encoding_skipped(self) -> None:
        # Don't crash on an int or None passed as encoding -- just
        # let the MCP surface the real validation error.
        out, notes = IDABridgeTool._coerce_encoding_value(
            "list_strings",
            {"encoding": None},
        )
        assert out["encoding"] is None
        assert notes == []

    def test_get_string_at_also_normalized(self) -> None:
        out, notes = IDABridgeTool._coerce_encoding_value(
            "get_string_at",
            {"binary_id": "b", "address": "0x4c0608", "encoding": "utf16"},
        )
        assert out["encoding"] == "utf16le"
        assert out["address"] == "0x4c0608"
        assert len(notes) == 1

    def test_unrelated_tool_untouched(self) -> None:
        # Only list_strings + get_string_at are in _ENCODING_TOOLS.
        # decompile has no ``encoding`` kwarg, but if some other
        # tool happens to take ``encoding``, the bridge must not
        # rewrite it -- the alias map is scoped to string tools.
        out, notes = IDABridgeTool._coerce_encoding_value(
            "decompile",
            {"encoding": "utf16"},
        )
        assert out["encoding"] == "utf16"
        assert notes == []

    def test_full_pipeline_normalizes_through_normalize_kwargs(self) -> None:
        # End-to-end: _normalize_kwargs is what forward() actually
        # calls. Confirm the encoding-value step runs inside the
        # full pipeline (after alias renames, pagination drops,
        # and address coercion).
        bridge = IDABridgeTool.__new__(IDABridgeTool)
        bridge._auto_alias_map = {}  # type: ignore[attr-defined]
        bridge._known_params = {"list_strings": frozenset({"binary_id", "encoding", "section"})}  # type: ignore[attr-defined]
        out, notes = bridge._normalize_kwargs(
            "list_strings",
            {"binary_id": "b", "encoding": "utf16", "section": ".rsrc"},
        )
        assert out["encoding"] == "utf16le"
        assert any("encoding" in n for n in notes)
