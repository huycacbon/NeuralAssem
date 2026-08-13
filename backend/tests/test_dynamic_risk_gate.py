"""Risk bucket derivation for the mandatory Debug warning modal."""

from __future__ import annotations

import pytest

from app.dynamic.risk_gate import derive_risk_bucket
from app.models.analysis import AnalysisSummary, FunctionSummary


def _summary(scores: list[int]) -> AnalysisSummary:
    functions = [
        FunctionSummary(address=f"0x{i:x}", name=f"fn_{i}", nodeId=f"func_{i:x}", riskScore=score)
        for i, score in enumerate(scores)
    ]
    # Mirror how AnalysisSummary.highest_risk_functions is actually built in
    # analysis_service._build_record: sorted descending by risk score.
    functions.sort(key=lambda item: item.risk_score, reverse=True)
    return AnalysisSummary(highestRiskFunctions=functions)


class TestDeriveRiskBucket:
    def test_no_functions_means_no_risk(self) -> None:
        assert derive_risk_bucket(_summary([])) == ("none", 0)

    @pytest.mark.parametrize(
        ("scores", "expected_bucket", "expected_score"),
        [
            ([0], "none", 0),
            ([1, 5], "low", 5),
            ([9], "low", 9),
            ([10], "medium", 10),
            ([19, 3], "medium", 19),
            ([20], "high", 20),
            ([99, 2, 1], "high", 99),
        ],
    )
    def test_thresholds_match_risk_scorer(
        self, scores: list[int], expected_bucket: str, expected_score: int
    ) -> None:
        assert derive_risk_bucket(_summary(scores)) == (expected_bucket, expected_score)
