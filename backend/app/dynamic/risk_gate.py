"""Derives the risk bucket shown in the mandatory Debug warning modal.

Reads ``app.analyzers.risk_scorer.risk_level`` - a pure function with no
side effects - which is explicitly allowed by the one-directional import
rule (this package may read the static analyzer's public surface; the
static analyzer must stay unaware of this package).

There is no aggregate risk score anywhere in the static analysis API today
(see ``app.models.analysis.AnalysisSummary``): only per-function scores. The
bucket used here is derived from the single highest-scoring function, since
``highest_risk_functions`` is already sorted descending.
"""

from __future__ import annotations

from app.analyzers.risk_scorer import risk_level
from app.models.analysis import AnalysisSummary


def derive_risk_bucket(summary: AnalysisSummary) -> tuple[str, int]:
    """Return ``(bucket, score)`` for the sample's single riskiest function.

    ``bucket`` is one of ``"high"``/``"medium"``/``"low"``/``"none"``
    (``app.analyzers.risk_scorer.risk_level``'s thresholds). ``score`` is 0
    when the sample has no functions with a non-zero risk score.
    """
    functions = summary.highest_risk_functions
    score = functions[0].risk_score if functions else 0
    return risk_level(score), score
