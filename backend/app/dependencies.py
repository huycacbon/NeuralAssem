"""FastAPI dependency wiring.

The repository is instantiated once here. Swapping the in-memory store for a
SQLite-backed one later means changing this module only.
"""

from __future__ import annotations

from functools import lru_cache

from app.config import settings
from app.repositories import AnalysisRepository, InMemoryAnalysisRepository
from app.services.analysis_service import AnalysisService


@lru_cache(maxsize=1)
def get_repository() -> AnalysisRepository:
    return InMemoryAnalysisRepository(capacity=settings.max_stored_analyses)


@lru_cache(maxsize=1)
def get_analysis_service() -> AnalysisService:
    return AnalysisService(get_repository())
