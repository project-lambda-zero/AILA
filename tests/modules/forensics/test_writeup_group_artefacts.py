"""Writeup artefact-grouping tests for #59.

The writeup builder grouped artefacts by phantom attribute names
(family/type/data), so every row fell into 'unknown' with empty data and
writeups rendered blank. _group_artefacts now reads the real ArtifactRecord
columns (artifact_family / artifact_type / data_json).
"""
from __future__ import annotations

from types import SimpleNamespace

from aila.modules.forensics.reporting.writeup_builder import _group_artefacts


def _row(family: str, type_: str, data_json: str, id_: str = "a1", tool: str = "dissect"):
    return SimpleNamespace(
        artifact_family=family,
        artifact_type=type_,
        data_json=data_json,
        id=id_,
        source_tool=tool,
    )


def test_groups_by_real_family_and_reads_data() -> None:
    rows = [_row("malware", "binary_summary", '{"sha256": "deadbeef"}')]
    grouped = _group_artefacts(rows)
    assert "malware" in grouped
    assert "unknown" not in grouped
    entry = grouped["malware"][0]
    assert entry["type"] == "binary_summary"
    assert entry["data"]["sha256"] == "deadbeef"
    assert entry["source_tool"] == "dissect"


def test_multiple_families() -> None:
    rows = [
        _row("malware", "bin", "{}", id_="1"),
        _row("network", "pcap", "{}", id_="2"),
        _row("malware", "bin", "{}", id_="3"),
    ]
    grouped = _group_artefacts(rows)
    assert len(grouped["malware"]) == 2
    assert len(grouped["network"]) == 1


def test_missing_family_falls_back_to_unknown() -> None:
    rows = [_row("", "bin", "{}")]
    grouped = _group_artefacts(rows)
    assert grouped["unknown"][0]["type"] == "bin"


def test_malformed_data_json_yields_empty_dict() -> None:
    rows = [_row("malware", "bin", "not json")]
    assert _group_artefacts(rows)["malware"][0]["data"] == {}


def test_empty_rows() -> None:
    assert _group_artefacts([]) == {}
