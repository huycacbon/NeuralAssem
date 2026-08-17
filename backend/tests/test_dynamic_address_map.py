"""Runtime <-> static address translation - pure math, no pykd/VM needed."""

from __future__ import annotations

import pytest

from app.dynamic.debug_bridge.address_map import (
    is_canonical_x64_address,
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


class TestIsCanonicalX64Address:
    @pytest.mark.parametrize(
        "address",
        [
            0x0,
            0x401000,
            0x140001690,
            0x7FF604A80000,
            0x00007FFFFFFFFFFF,  # max user-space address
            0xFFFF800000000000,  # min kernel-space address
            0xFFFFFFFFFFFFFFFF,  # max representable address
        ],
    )
    def test_canonical_addresses_accepted(self, address: int) -> None:
        assert is_canonical_x64_address(address) is True

    @pytest.mark.parametrize(
        "address",
        [
            0x0000800000000000,  # one past max user-space
            0xFFFF7FFFFFFFFFFF,  # one before min kernel-space
            0xFFEAC95016D0,  # the actual garbage address from a real bug report -
            # double-applying the rebase delta to an already-runtime address
        ],
    )
    def test_non_canonical_addresses_rejected(self, address: int) -> None:
        assert is_canonical_x64_address(address) is False

    def test_real_bug_report_reproduced(self) -> None:
        """The exact scenario that surfaced this check: a *runtime* address
        (`load_base + small offset`, as if copied from the "Runtime address"
        UI field) fed into `static_to_runtime` as if it were static - the
        delta gets applied twice, landing non-canonical."""
        load_base = 0x7FF604A80000
        preferred_image_base = 0x140000000
        already_runtime_address = load_base + 0x16D0

        double_rebased = static_to_runtime(already_runtime_address, load_base, preferred_image_base)
        assert is_canonical_x64_address(double_rebased) is False
