"""`_pseudocode_address_lines`: converts angr codegen's internal
`map_addr_to_pos` (address -> character position) into the per-line map the
UI uses to sync a disassembly row with its pseudocode line.

Uses a minimal fake standing in for `CStructuredCodeGenerator` rather than a
real decompile (the real thing is exercised end to end by
`test_integration_angr.py` and was verified live against a real PE during
development - see the module's own docstring) - this file only tests the
pure position-to-line arithmetic, which is what this project's own code is
actually responsible for.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.angr_analyzer import _pseudocode_address_lines


@dataclass
class _FakeElement:
    posmap_pos: int | None


class _FakeCodegen:
    def __init__(self, map_addr_to_pos: dict[int, _FakeElement]) -> None:
        self.map_addr_to_pos = map_addr_to_pos


class TestPseudocodeAddressLines:
    def test_maps_address_to_the_line_its_position_falls_on(self) -> None:
        text = "int main(void)\n{\n    int x = 1;\n    return x;\n}\n"
        #        line 1            line 2  line 3           line 4       line 5
        pos_of_x_assignment = text.index("int x = 1")
        pos_of_return = text.index("return x")
        codegen = _FakeCodegen(
            {
                0x401000: _FakeElement(pos_of_x_assignment),
                0x401005: _FakeElement(pos_of_return),
            }
        )

        result = _pseudocode_address_lines(codegen, text)

        assert result == {0x401000: 3, 0x401005: 4}

    def test_position_at_very_start_of_text_maps_to_line_1(self) -> None:
        text = "int main(void) {}\n"
        codegen = _FakeCodegen({0x401000: _FakeElement(0)})

        assert _pseudocode_address_lines(codegen, text) == {0x401000: 1}

    def test_entries_with_no_position_are_skipped_not_crashed_on(self) -> None:
        text = "int main(void) {}\n"
        codegen = _FakeCodegen(
            {
                0x401000: _FakeElement(None),
                0x401004: _FakeElement(0),
            }
        )

        assert _pseudocode_address_lines(codegen, text) == {0x401004: 1}

    def test_empty_map_produces_empty_result(self) -> None:
        assert _pseudocode_address_lines(_FakeCodegen({}), "int main(void) {}\n") == {}
