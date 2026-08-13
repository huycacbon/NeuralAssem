"""Repository interface for stored analyses."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.analysis import AnalysisRecord


class AnalysisRepository(ABC):
    """Persistence boundary. Implementations must be safe for concurrent use."""

    @abstractmethod
    def save(self, record: AnalysisRecord) -> None:
        """Store (or replace) an analysis."""

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisRecord | None:
        """Return an analysis, or ``None`` when it is unknown or evicted."""

    @abstractmethod
    def delete(self, analysis_id: str) -> bool:
        """Remove an analysis. Returns whether anything was removed."""

    @abstractmethod
    def list_ids(self) -> list[str]:
        """Return the ids currently held, newest first."""
