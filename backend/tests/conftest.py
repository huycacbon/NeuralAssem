"""Shared fixtures.

Most tests run against synthetic ``AnalysisArtifacts`` rather than a real PE, so
the suite stays fast and works on a machine without a C compiler. The one
angr-backed test is opt-in (see ``test_integration_angr.py``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow ``import app...`` when pytest is invoked from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analyzers.angr_analyzer import (  # noqa: E402
    AnalysisArtifacts,
    AnalyzedBlock,
    AnalyzedFunction,
    AnalyzedInstruction,
)
from app.analyzers.import_extractor import ImportEntry  # noqa: E402
from app.analyzers.string_extractor import ExtractedString  # noqa: E402


def make_function(
    address: int,
    name: str,
    *,
    risk_score: int = 0,
    callers: set[int] | None = None,
    callees: set[int] | None = None,
    api_calls: dict[str, list[int]] | None = None,
    api_names: list[str] | None = None,
    blocks: dict[int, AnalyzedBlock] | None = None,
    is_plt: bool = False,
) -> AnalyzedFunction:
    return AnalyzedFunction(
        address=address,
        name=name,
        size=0x40,
        is_plt=is_plt,
        is_imported=is_plt,
        callers=callers or set(),
        callees=callees or set(),
        api_calls=api_calls or {},
        api_names=api_names or [],
        blocks=blocks or {},
        risk_score=risk_score,
    )


@pytest.fixture
def sample_artifacts() -> AnalysisArtifacts:
    """A small hand-built call graph mirroring the C fixture's shape.

        main -> calculate -> {add, multiply}
        main -> printf (API)
        multiply -> CreateRemoteThread (API, high risk)
        orphan  (unreachable from main)
    """
    entry = 0x401000

    main = make_function(0x401000, "main", callees={0x401100})
    calculate = make_function(
        0x401100, "calculate", callers={0x401000}, callees={0x401200, 0x401300}
    )
    add = make_function(0x401200, "add", callers={0x401100})
    multiply = make_function(
        0x401300,
        "multiply",
        callers={0x401100},
        risk_score=10,
        api_calls={"api_kernel32!CreateRemoteThread": [0x401310]},
        api_names=["CreateRemoteThread"],
    )
    orphan = make_function(0x409000, "sub_409000")

    main.api_calls = {"api_msvcrt!printf": [0x401050]}
    main.api_names = ["printf"]

    # calculate gets a two-block conditional CFG so CFG tests have real data.
    calculate.blocks = {
        0x401100: AnalyzedBlock(
            address=0x401100,
            size=0x10,
            instructions=[
                AnalyzedInstruction(0x401100, "cmp", "eax, 0xa"),
                AnalyzedInstruction(0x40110C, "jle", "0x401130"),
            ],
            successors=[(0x401110, "TRUE"), (0x401130, "FALSE")],
        ),
        0x401110: AnalyzedBlock(
            address=0x401110,
            size=0x08,
            instructions=[AnalyzedInstruction(0x401110, "call", "0x401300")],
            successors=[(0x401130, "FALLTHROUGH")],
            call_targets=["api_kernel32!CreateRemoteThread"],
        ),
        0x401130: AnalyzedBlock(
            address=0x401130,
            size=0x04,
            instructions=[AnalyzedInstruction(0x401130, "ret", "")],
        ),
    }
    calculate.blocks[0x401110].predecessors = [0x401100]
    calculate.blocks[0x401130].predecessors = [0x401100, 0x401110]

    multiply.strings = [ExtractedString(0x40A000, "http://example.invalid/payload")]

    functions = {
        function.address: function
        for function in (main, calculate, add, multiply, orphan)
    }

    return AnalysisArtifacts(
        architecture="x86",
        bits=32,
        entry_point=entry,
        image_base=0x400000,
        binary_format="PE",
        functions=functions,
        call_edges={
            (0x401000, 0x401100): 1,
            (0x401100, 0x401200): 1,
            (0x401100, 0x401300): 3,
        },
        call_sites={
            (0x401000, 0x401100): 0x401010,
            (0x401100, 0x401200): 0x401120,
            (0x401100, 0x401300): 0x401110,
        },
        imports=[
            ImportEntry(module="msvcrt.dll", name="printf", iat_address=0x40B000),
            ImportEntry(
                module="KERNEL32.dll",
                name="CreateRemoteThread",
                iat_address=0x40B004,
            ),
        ],
        api_callers={
            "api_msvcrt!printf": {0x401000},
            "api_kernel32!CreateRemoteThread": {0x401300},
        },
        api_references={
            "api_msvcrt!printf": 1,
            "api_kernel32!CreateRemoteThread": 1,
        },
        strings=[ExtractedString(0x40A000, "http://example.invalid/payload")],
    )
