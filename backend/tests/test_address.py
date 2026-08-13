"""Address normalisation and node-id generation."""

from __future__ import annotations

import pytest

from app.utils.address import (
    api_node_id,
    block_node_id,
    format_address,
    function_node_id,
    parse_address,
    try_parse_address,
)


class TestFormatAddress:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0x401000, "0x401000"),
            (0, "0x0"),
            (0x140001300, "0x140001300"),
            (0xDEADBEEF, "0xdeadbeef"),
        ],
    )
    def test_lowercase_hex_with_prefix(self, value: int, expected: str) -> None:
        assert format_address(value) == expected


class TestParseAddress:
    @pytest.mark.parametrize(
        "text", ["0x401000", "401000", "0X401000", " 0x401000 ", "0x401000".upper()]
    )
    def test_accepts_common_forms(self, text: str) -> None:
        assert parse_address(text) == 0x401000

    def test_passthrough_int(self) -> None:
        assert parse_address(0x401000) == 0x401000

    @pytest.mark.parametrize("text", ["", "   ", "0x", "zzz", "0xGG", "not-an-address"])
    def test_rejects_garbage(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_address(text)

    def test_try_parse_returns_none_instead_of_raising(self) -> None:
        assert try_parse_address("nope") is None
        assert try_parse_address("0x401000") == 0x401000

    def test_round_trip(self) -> None:
        for value in (0, 0x1000, 0x401000, 0x140001300):
            assert parse_address(format_address(value)) == value


class TestNodeIds:
    def test_function_and_block_ids_are_distinct(self) -> None:
        assert function_node_id(0x401000) == "func_401000"
        assert block_node_id(0x401000) == "block_401000"
        assert function_node_id(0x401000) != block_node_id(0x401000)

    def test_api_id_is_case_and_extension_insensitive(self) -> None:
        # The PE import table is inconsistent about DLL casing/extension; the
        # same API must collapse to one node regardless.
        assert api_node_id("KERNEL32.dll", "CreateFileW") == api_node_id(
            "kernel32.DLL", "CreateFileW"
        )
        assert api_node_id("KERNEL32", "CreateFileW") == api_node_id(
            "KERNEL32.dll", "CreateFileW"
        )

    def test_same_export_from_different_dlls_stays_separate(self) -> None:
        assert api_node_id("kernel32.dll", "GetVersion") != api_node_id(
            "ntdll.dll", "GetVersion"
        )
