"""Runtime <-> static address translation - pure math, no pykd/VM needed."""

from __future__ import annotations

import pytest

from app.dynamic.debug_bridge.address_map import (
    rebase_delta,
    runtime_to_static,
    static_to_runtime,
)


class TestRebaseDelta:
    def test_zero_when_loaded_at_preferred_base(self) -> None:
        assert rebase_delta(0x400000, 0x400000) == 0

    def test_positive_when_shifted_up(self) -> None:
        assert rebase_delta(0x140000000, 0x400000) == 0x13FC00000

    def test_negative_when_shifted_down(self) -> None:
        assert rebase_delta(0x300000, 0x400000) == -0x100000


class TestRuntimeToStatic:
    def test_no_rebase_is_identity(self) -> None:
        assert runtime_to_static(0x401234, 0x400000, 0x400000) == 0x401234

    def test_aslr_shifted_module(self) -> None:
        # Preferred 0x400000, actually loaded at 0x7ff600000000 (typical x64
        # ASLR-style base) - an instruction at runtime 0x7ff600001234 must
        # map back to the same offset from the preferred base.
        actual_base = 0x7FF600000000
        preferred_base = 0x400000
        runtime_address = actual_base + 0x1234
        assert runtime_to_static(runtime_address, actual_base, preferred_base) == 0x401234


class TestStaticToRuntime:
    def test_inverse_of_runtime_to_static(self) -> None:
        actual_base = 0x7FF600000000
        preferred_base = 0x400000
        static_address = 0x401234
        runtime_address = static_to_runtime(static_address, actual_base, preferred_base)
        assert runtime_to_static(runtime_address, actual_base, preferred_base) == static_address

    def test_round_trip_many_values(self) -> None:
        actual_base = 0x10000000
        preferred_base = 0x400000
        for offset in (0, 0x10, 0x1000, 0xABCDE):
            static_address = preferred_base + offset
            runtime_address = static_to_runtime(static_address, actual_base, preferred_base)
            assert runtime_to_static(runtime_address, actual_base, preferred_base) == static_address

    @pytest.mark.parametrize(
        ("actual_base", "preferred_base"),
        [(0x400000, 0x400000), (0x500000, 0x400000), (0x300000, 0x400000)],
    )
    def test_various_rebases(self, actual_base: int, preferred_base: int) -> None:
        static_address = 0x401000
        runtime_address = static_to_runtime(static_address, actual_base, preferred_base)
        assert runtime_address == static_address + (actual_base - preferred_base)
