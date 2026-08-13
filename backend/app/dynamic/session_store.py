"""In-memory store of live debug sessions, with idle-timeout eviction.

Mirrors `InMemoryAnalysisRepository`'s `OrderedDict` + `threading.Lock`
shape (see `app.repositories.memory`), but a debug session is a live
connection rather than an immutable record, so this store additionally:

- takes an `AnalysisRepository` at construction (not a hardcoded singleton)
  so both the web deployment (its shared `app.dependencies.get_repository()`)
  and the desktop build (its own per-window repository instance, see
  `app.desktop_bridge.DesktopApi`) can each supply their own, keeping this
  module itself transport-agnostic;
- runs a background reaper thread that disconnects and evicts sessions idle
  past `idle_timeout_seconds` (the static side has nothing analogous - its
  records are immutable, nothing to time out).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from typing import BinaryIO

from app.dynamic.debug_bridge.client import ComtypesDebugBridge, DebugBridge
from app.dynamic.local_upload import stage_upload
from app.dynamic.session import DebugSession
from app.repositories.base import AnalysisRepository
from app.utils.security import safe_unlink

logger = logging.getLogger(__name__)


class DynamicAnalysisNotFound(LookupError):
    """The `analysis_id` given to `create()` has no static analysis on record."""


class DynamicSessionNotFound(LookupError):
    """No live debug session with this id (never connected, disconnected, or
    evicted by the idle-timeout reaper)."""


class SessionStore:
    def __init__(
        self,
        repository: AnalysisRepository,
        capacity: int,
        idle_timeout_seconds: int,
        # Default is ComtypesDebugBridge, not PykdDebugBridge: pykd has no
        # PyPI wheel for this project's Python version (see
        # debug_bridge/client.py's module docstring). ComtypesDebugBridge's
        # dbgeng-specific vtable slots still need filling in from a real
        # dbgeng.h before a connection actually succeeds - see its class
        # docstring - but it is at least importable/constructible here.
        bridge_factory: Callable[[], DebugBridge] = ComtypesDebugBridge,
        clock: Callable[[], float] = time.monotonic,
        reaper_interval_seconds: float = 30.0,
        start_reaper: bool = True,
    ) -> None:
        self._repository = repository
        self._capacity = max(1, capacity)
        self._idle_timeout_seconds = idle_timeout_seconds
        self._bridge_factory = bridge_factory
        self._clock = clock
        self._reaper_interval_seconds = reaper_interval_seconds

        self._items: OrderedDict[str, DebugSession] = OrderedDict()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._reaper_thread: threading.Thread | None = None
        if start_reaper:
            self._start_reaper()

    def _start_reaper(self) -> None:
        thread = threading.Thread(
            target=self._reap_loop, name="dynamic-session-reaper", daemon=True
        )
        self._reaper_thread = thread
        thread.start()

    def _reap_loop(self) -> None:  # pragma: no cover - exercised via reap_idle() in tests
        while not self._stop_event.wait(self._reaper_interval_seconds):
            self.reap_idle()

    def reap_idle(self) -> list[str]:
        """Disconnect and evict every session idle past the timeout.

        Public (not just invoked by the background thread) so tests can
        drive eviction deterministically with a fake clock instead of
        waiting on a real 30-minute timer.
        """
        with self._lock:
            idle_ids = [
                session_id
                for session_id, session in self._items.items()
                if session.is_idle(self._idle_timeout_seconds)
            ]
            idle_sessions = [(session_id, self._items.pop(session_id)) for session_id in idle_ids]

        for session_id, session in idle_sessions:
            logger.info("Ngắt kết nối debug session %s (idle timeout)", session_id)
            try:
                session.disconnect()
            except Exception:  # pragma: no cover - best-effort cleanup
                logger.exception("Lỗi khi ngắt kết nối session %s", session_id)
        return idle_ids

    def create(
        self,
        analysis_id: str,
        host: str,
        port: int,
        process_id: int | None,
        process_name: str | None,
        connect_timeout_seconds: float,
    ) -> DebugSession:
        record = self._repository.get(analysis_id)
        if record is None:
            raise DynamicAnalysisNotFound(analysis_id)

        preferred_image_base = int(record.raw["artifacts"].image_base)

        session = DebugSession(
            session_id=uuid.uuid4().hex,
            analysis_id=analysis_id,
            bridge=self._bridge_factory(),
            preferred_image_base=preferred_image_base,
            clock=self._clock,
        )

        # The real connect+attach happens outside this store's own lock -
        # it can block for a while (network + dbgeng), and callers (api.py)
        # already run this whole method via run_in_threadpool so it never
        # blocks the event loop either.
        session.connect_and_attach(
            host, port, process_id, process_name, connect_timeout_seconds
        )
        self._register(session)
        return session

    def create_local(
        self,
        analysis_id: str,
        command_line: str,
        connect_timeout_seconds: float,  # noqa: ARG002 - kept for signature symmetry with create(); DebugSession.launch_local doesn't take a timeout today (the underlying local dbgeng call has no timeout parameter), reserved for when that's added.
    ) -> DebugSession:
        """Local-launch path: the app itself executes `command_line` on this
        host, directly - see `DebugBridge.create_and_attach_local`'s
        docstring for the full rationale. Kept as a separate method from
        `create()` rather than a branch inside it, deliberately, so the two
        code paths (remote client-only vs. local-execute) stay visually and
        structurally distinct in this security-relevant file.
        """
        record = self._repository.get(analysis_id)
        if record is None:
            raise DynamicAnalysisNotFound(analysis_id)

        preferred_image_base = int(record.raw["artifacts"].image_base)

        session = DebugSession(
            session_id=uuid.uuid4().hex,
            analysis_id=analysis_id,
            bridge=self._bridge_factory(),
            preferred_image_base=preferred_image_base,
            clock=self._clock,
        )

        session.launch_local(command_line)
        self._register(session)
        return session

    def create_local_from_upload(
        self,
        analysis_id: str,
        stream: BinaryIO,
        filename: str | None,
        connect_timeout_seconds: float,  # noqa: ARG002 - see create_local()'s note on this param
        max_upload_bytes: int,
    ) -> DebugSession:
        """Local-launch-from-upload: stages `stream` to a fresh temp file
        (`local_upload.stage_upload` - the same validation the static
        analyzer's own upload uses, a different directory) and launches that
        copy. See `local_upload.py`'s module docstring for why this exists
        instead of reusing the static analyzer's already-deleted upload.

        Any failure - staging (bad extension/size/not-a-PE) or the launch
        itself - cleans up the staged file before propagating; `DebugSession`
        only owns cleanup for failures *after* it exists.
        """
        record = self._repository.get(analysis_id)
        if record is None:
            raise DynamicAnalysisNotFound(analysis_id)

        staged = stage_upload(stream, filename, max_upload_bytes)

        try:
            preferred_image_base = int(record.raw["artifacts"].image_base)

            session = DebugSession(
                session_id=uuid.uuid4().hex,
                analysis_id=analysis_id,
                bridge=self._bridge_factory(),
                preferred_image_base=preferred_image_base,
                clock=self._clock,
            )
            session.launch_local(str(staged.path), owned_temp_file=staged.path)
        except Exception:
            # session.launch_local already cleans up on its own failure path
            # (it knows about owned_temp_file once assigned inside the lock),
            # but a failure *before* that call ever runs (e.g. constructing
            # DebugSession) would otherwise leak the staged file - safe_unlink
            # is idempotent, so calling it again here even after
            # launch_local's own cleanup is harmless.
            safe_unlink(staged.path)
            raise

        self._register(session)
        return session

    def _register(self, session: DebugSession) -> None:
        """Shared tail of `create()`/`create_local()`: add the newly
        attached session to the store, evicting the oldest if over
        capacity."""
        with self._lock:
            self._items[session.session_id] = session
            self._items.move_to_end(session.session_id)
            overflow: list[DebugSession] = []
            while len(self._items) > self._capacity:
                evicted_id, evicted_session = self._items.popitem(last=False)
                logger.info("Evict debug session %s (vượt capacity)", evicted_id)
                overflow.append(evicted_session)

        for evicted_session in overflow:
            try:
                evicted_session.disconnect()
            except Exception:  # pragma: no cover - best-effort cleanup
                pass

    def get(self, session_id: str) -> DebugSession:
        with self._lock:
            session = self._items.get(session_id)
            if session is None:
                raise DynamicSessionNotFound(session_id)
            self._items.move_to_end(session_id)
        # Any lookup counts as activity (state reads, breakpoint edits, step,
        # continue - api.py calls store.get() before every one of them), so
        # touch() happens outside the store's own lock to avoid holding it
        # for longer than the OrderedDict bookkeeping needs.
        session.touch()
        return session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            session = self._items.pop(session_id, None)
        if session is None:
            return False
        session.disconnect()
        return True

    def shutdown(self) -> None:
        """Stop the reaper thread and disconnect every live session."""
        self._stop_event.set()
        if self._reaper_thread is not None:
            self._reaper_thread.join(timeout=self._reaper_interval_seconds + 1)
        with self._lock:
            sessions = list(self._items.values())
            self._items.clear()
        for session in sessions:
            try:
                session.disconnect()
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
