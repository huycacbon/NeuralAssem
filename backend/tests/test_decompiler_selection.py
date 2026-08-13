"""Priority logic for which functions get spent on best-effort decompilation.

This only tests the pure selection/ordering function - the actual angr
Decompiler call is exercised by the integration test (best-effort, opt-in,
requires a real PE) since it cannot run without a live `angr.Project`.
"""

from __future__ import annotations

from app.analyzers.angr_analyzer import (
    AnalysisArtifacts,
    AnalyzedBlock,
    _select_decompile_candidates,
)
from tests.conftest import make_function


def _with_blocks(function, count: int):
    """Give a synthetic function `count` dummy blocks so it counts as eligible
    (`_select_decompile_candidates` requires a non-empty body)."""
    function.blocks = {
        function.address + i * 0x10: AnalyzedBlock(address=function.address + i * 0x10, size=0x10)
        for i in range(count)
    }
    return function


def _artifacts(*functions, entry_point: int) -> AnalysisArtifacts:
    return AnalysisArtifacts(
        architecture="x86",
        bits=32,
        entry_point=entry_point,
        image_base=0x400000,
        binary_format="PE",
        functions={f.address: f for f in functions},
    )


class TestEligibility:
    def test_plt_functions_excluded(self) -> None:
        plt = _with_blocks(make_function(0x401000, "CreateFileW", is_plt=True), 3)
        real = _with_blocks(make_function(0x402000, "sub_402000"), 3)
        artifacts = _artifacts(plt, real, entry_point=0x402000)

        candidates = _select_decompile_candidates(artifacts)

        assert plt not in candidates
        assert real in candidates

    def test_functions_without_a_body_excluded(self) -> None:
        empty = make_function(0x401000, "sub_401000")  # blocks defaults to {}
        artifacts = _artifacts(empty, entry_point=0x401000)

        assert _select_decompile_candidates(artifacts) == []

    def test_simprocedure_and_syscall_excluded(self) -> None:
        simproc = _with_blocks(make_function(0x401000, "memcpy"), 2)
        simproc.is_simprocedure = True
        syscall = _with_blocks(make_function(0x402000, "NtCreateFile"), 2)
        syscall.is_syscall = True
        artifacts = _artifacts(simproc, syscall, entry_point=0x403000)

        assert _select_decompile_candidates(artifacts) == []


class TestPriorityOrder:
    def test_entry_point_sorts_first(self) -> None:
        entry = _with_blocks(make_function(0x401000, "sub_401000"), 50)
        named_risky = _with_blocks(make_function(0x402000, "CreateRemoteThread_wrapper", risk_score=50), 2)
        artifacts = _artifacts(entry, named_risky, entry_point=0x401000)

        ordered = _select_decompile_candidates(artifacts)

        assert ordered[0].address == 0x401000

    def test_named_function_beats_unnamed_at_equal_risk(self) -> None:
        named = _with_blocks(make_function(0x401000, "main"), 5)
        unnamed = _with_blocks(make_function(0x402000, "sub_402000"), 5)
        artifacts = _artifacts(named, unnamed, entry_point=0x900000)

        ordered = _select_decompile_candidates(artifacts)

        assert [f.address for f in ordered] == [0x401000, 0x402000]

    def test_higher_risk_beats_lower_risk_among_unnamed(self) -> None:
        low = _with_blocks(make_function(0x401000, "sub_401000", risk_score=2), 5)
        high = _with_blocks(make_function(0x402000, "sub_402000", risk_score=20), 5)
        artifacts = _artifacts(low, high, entry_point=0x900000)

        ordered = _select_decompile_candidates(artifacts)

        assert [f.address for f in ordered] == [0x402000, 0x401000]

    def test_fewer_blocks_wins_ties_so_budget_covers_more_functions(self) -> None:
        big = _with_blocks(make_function(0x401000, "sub_401000"), 100)
        small = _with_blocks(make_function(0x402000, "sub_402000"), 3)
        artifacts = _artifacts(big, small, entry_point=0x900000)

        ordered = _select_decompile_candidates(artifacts)

        assert [f.address for f in ordered] == [0x402000, 0x401000]

    def test_full_priority_chain(self) -> None:
        """entry point > named > risk score > fewer blocks, in that order."""
        entry = _with_blocks(make_function(0x401000, "sub_401000"), 80)  # worst on every
        # tiebreak but wins on being the entry point
        named_low_risk_big = _with_blocks(make_function(0x402000, "main", risk_score=0), 80)
        unnamed_high_risk_small = _with_blocks(
            make_function(0x403000, "sub_403000", risk_score=99), 2
        )
        unnamed_low_risk_small = _with_blocks(
            make_function(0x404000, "sub_404000", risk_score=0), 2
        )
        artifacts = _artifacts(
            unnamed_low_risk_small,
            unnamed_high_risk_small,
            named_low_risk_big,
            entry,
            entry_point=0x401000,
        )

        ordered = [f.address for f in _select_decompile_candidates(artifacts)]

        assert ordered == [0x401000, 0x402000, 0x403000, 0x404000]
