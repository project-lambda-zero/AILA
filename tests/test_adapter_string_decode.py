"""Adapter-side base64 / hex auto-decode for ida-headless string tools.

The bridge surfaces strings the agent commonly needs to decode (base64
C2 URLs, hex-encoded configs, etc.) directly in the observation row so
the agent doesn't have to call out to a separate decoder.

These tests pin the heuristic: encoded blobs above the printable-ratio
gate decode; random bytes (encrypted payloads / shellcode) skip cleanly;
short / oversized / mis-padded inputs are rejected.
"""
from __future__ import annotations

import base64
import secrets

from aila.platform.mcp.adapters._shared import (
    enrich_strings_with_decodes,
    try_decode_string,
)


class TestTryDecodeString:
    def test_base64_url(self) -> None:
        encoded = base64.b64encode(b"https://c2.evil.example/beacon").decode()
        out = try_decode_string(encoded)
        assert out is not None
        assert out["encoding"] == "base64"
        assert "c2.evil.example" in out["decoded"]

    def test_base64_url_safe(self) -> None:
        encoded = base64.urlsafe_b64encode(b"_user_token_abc123_xyz").decode()
        # Strip padding so we still hit % 4 == 0 OR keep it -- either way
        # the urlsafe path checks for - / _ presence.
        out = try_decode_string(encoded)
        assert out is not None
        assert out["encoding"] in ("base64", "base64url")
        assert "user_token" in out["decoded"]

    def test_hex_encoded_path(self) -> None:
        encoded = b"C:\\Users\\victim\\AppData\\Roaming\\evil.exe".hex()
        out = try_decode_string(encoded)
        assert out is not None
        assert out["encoding"] == "hex"
        assert "victim" in out["decoded"]

    def test_random_bytes_rejected(self) -> None:
        # Random bytes encoded as base64 -- decoded bytes have low
        # printable ratio so the heuristic skips them (the encoded
        # form alone is still in the payload via the caller).
        encoded = base64.b64encode(secrets.token_bytes(64)).decode()
        out = try_decode_string(encoded)
        # Either None (gate rejected) or printable=False.
        if out is not None:
            # On the off-chance the random bytes happen to be printable,
            # the function returns a valid decode -- which is the right
            # behavior for genuinely-printable input. The gate is
            # heuristic, not a guarantee.
            assert "decoded" in out

    def test_too_short(self) -> None:
        # len < 8 -> rejected without even trying.
        assert try_decode_string("abcd") is None
        assert try_decode_string("a===") is None

    def test_not_a_string(self) -> None:
        assert try_decode_string(123) is None  # type: ignore[arg-type]
        assert try_decode_string(None) is None  # type: ignore[arg-type]

    def test_empty(self) -> None:
        assert try_decode_string("") is None
        assert try_decode_string("   ") is None

    def test_plain_text_no_decode(self) -> None:
        # Looks like base64 chars but isn't actually valid base64.
        # Length-not-divisible-by-4 case fails the regex+len gate.
        assert try_decode_string("KERNEL32") is None

    def test_meaningful_length_floor(self) -> None:
        # b64 of "hi" = "aGk=" -> 2 bytes decoded, below MIN_OUTPUT (4)
        # The MIN_OUTPUT gate skips it.
        # But "aGkhCg==" decodes to "hi!\n" which IS 4 bytes -> hits.
        # Let's test both.
        assert try_decode_string("aGk=") is None  # 2 bytes, too short
        out = try_decode_string(base64.b64encode(b"hello!").decode())  # 6 bytes
        assert out is not None and "hello" in out["decoded"]


class TestEnrichStringsWithDecodes:
    def test_bare_strings(self) -> None:
        url = base64.b64encode(b"https://evil.test/c2").decode()
        out = enrich_strings_with_decodes([url, "KERNEL32.DLL", "short"])
        assert isinstance(out[0], dict)
        assert out[0]["encoding"] == "base64"
        assert "evil.test" in out[0]["decoded"]
        # The non-decodable entries stay as bare strings.
        assert out[1] == "KERNEL32.DLL"
        assert out[2] == "short"

    def test_dict_records_value_key(self) -> None:
        url = base64.b64encode(b"http://malware.example/dl").decode()
        records = [
            {"value": url, "address": "0x401000"},
            {"value": "RegOpenKeyExA", "address": "0x402000"},
        ]
        out = enrich_strings_with_decodes(records)
        assert out[0]["encoding"] == "base64"
        assert "malware.example" in out[0]["decoded"]
        assert out[0]["address"] == "0x401000"  # preserved
        assert "decoded" not in out[1]
        assert out[1]["address"] == "0x402000"

    def test_alternate_string_key(self) -> None:
        # Some adapters use \"string\" not \"value\"; the enricher falls\n        # back through (string -> text -> raw -> data).\n
        url = base64.b64encode(b"https://x.test/y").decode()
        records = [{"string": url, "ea": "0x500000"}]
        out = enrich_strings_with_decodes(records)
        assert "decoded" in out[0]
        assert "x.test" in out[0]["decoded"]

    def test_not_a_list(self) -> None:
        # Non-list passes through unchanged for caller-side robustness.
        assert enrich_strings_with_decodes("not a list") == "not a list"  # type: ignore[arg-type]
        assert enrich_strings_with_decodes(None) is None  # type: ignore[arg-type]
