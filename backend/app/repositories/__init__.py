"""Storage for completed analyses.

Deliberately behind an interface: the MVP keeps results in process memory, but
swapping in SQLite later only means writing another ``AnalysisRepository``
implementation and changing one line in ``app.main``.
"""

from app.repositories.base import AnalysisRepository
from app.repositories.memory import InMemoryAnalysisRepository

__all__ = ["AnalysisRepository", "InMemoryAnalysisRepository"]
