"""`ThreadPinnedDebugBridge` - every call must land on the same OS thread,
regardless of which thread the *caller* is on. See that module's docstring
for the live failure (`ReadVirtual` succeeding via one call path, failing
moments later via another at the exact same address) this exists to prevent.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.dynamic.debug_bridge.client import DebugBridge, ModuleInfo, StopReason
from app.dynamic.debug_bridge.thread_pinned import ThreadPinnedDebugBridge


class _ThreadRecordingBridge(DebugBridge):
    """Records which OS thread each method actually ran on - the whole
    point under test."""

    def __init__(self) -> None:
        self.thread_ids: list[int] = []

    def _record(self) -> None:
        self.thread_ids.append(threading.get_ident())

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        self._record()

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        self._record()
        return ModuleInfo(load_base=0x400000, module_name="sample.exe", size=0x1000)

    def set_breakpoint(self, runtime_address: int) -> int:
        self._record()
        return 1

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        self._record()

    def step_into(self) -> StopReason:
        self._record()
        return StopReason(kind="step")

    def step_over(self) -> StopReason:
        self._record()
        return StopReason(kind="step")

    def go(
        self, timeout_seconds: float, breakpoint_addresses: frozenset[int] = frozenset()
    ) -> StopReason:
        self._record()
        return StopReason(kind="breakpoint")

    def read_registers(self) -> dict[str, int]:
        self._record()
        return {}

    def read_stack(self, max_frames: int) -> list:
        self._record()
        return []

    def current_instruction_address(self) -> int:
        self._record()
        return 0x400000

    def disconnect(self) -> None:
        self._record()

    def read_memory(self, address: int, size: int) -> bytes:
        self._record()
        return b"\x90" * size


class TestThreadPinnedDebugBridge:
    def test_every_call_from_the_same_caller_thread_lands_on_one_worker_thread(self) -> None:
        recording = _ThreadRecordingBridge()
        bridge = ThreadPinnedDebugBridge(recording)

        bridge.attach(1, None)
        bridge.set_breakpoint(0x401000)
        bridge.read_memory(0x401000, 1)
        bridge.go(5.0, frozenset({0x401000}))
        bridge.step_into()
        bridge.disconnect()

        assert len(recording.thread_ids) == 6
        assert len(set(recording.thread_ids)) == 1, "every call must run on the same worker thread"
        # And that worker thread must not be the thread that made the calls
        # above - proving this is a real pin, not an accidental same-thread
        # coincidence.
        assert recording.thread_ids[0] != threading.get_ident()

    def test_calls_from_different_caller_threads_still_land_on_one_worker_thread(self) -> None:
        """The actual bug this wrapper fixes: two calls issued from two
        *different* OS threads (mirroring `run_in_threadpool`/pywebview's
        bridge potentially dispatching different calls to different worker
        threads) must still both execute on the bridge's own single pinned
        thread."""
        recording = _ThreadRecordingBridge()
        bridge = ThreadPinnedDebugBridge(recording)

        with ThreadPoolExecutor(max_workers=2) as caller_pool:
            caller_pool.submit(bridge.read_memory, 0x401000, 1).result()
            caller_pool.submit(bridge.go, 5.0, frozenset()).result()

        assert len(recording.thread_ids) == 2
        assert recording.thread_ids[0] == recording.thread_ids[1]
