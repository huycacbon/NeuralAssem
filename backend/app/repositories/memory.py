"""In-memory analysis store with LRU eviction.

No database in the MVP. Results are bounded so a long-running local session
cannot grow without limit; the oldest analysis is dropped when the cap is hit.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict

from app.models.analysis import AnalysisRecord
from app.repositories.base import AnalysisRepository

logger = logging.getLogger(__name__)

DEFAULT_CAPACITY = 16


class InMemoryAnalysisRepository(AnalysisRepository):
    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        self._capacity = max(1, capacity)
        self._items: OrderedDict[str, AnalysisRecord] = OrderedDict()
        self._lock = threading.Lock()

    def save(self, record: AnalysisRecord) -> None:
        with self._lock:
            self._items[record.analysis_id] = record
            self._items.move_to_end(record.analysis_id)
            while len(self._items) > self._capacity:
                evicted_id, _ = self._items.popitem(last=False)
                logger.info("Evict analysis %s (vượt capacity)", evicted_id)

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        with self._lock:
            record = self._items.get(analysis_id)
            if record is not None:
                self._items.move_to_end(analysis_id)
            return record

    def delete(self, analysis_id: str) -> bool:
        with self._lock:
            return self._items.pop(analysis_id, None) is not None

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(reversed(self._items.keys()))
