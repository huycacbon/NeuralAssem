"""Pins every call to a wrapped `DebugBridge` onto one dedicated worker
thread for that bridge's entire lifetime.

Why this exists: dbgeng's own COM interfaces (`IDebugClient`/`IDebugControl`/
`IDebugRegisters`/`IDebugSymbols`/`IDebugDataSpaces`) are not free-threaded -
Microsoft's own dbgeng documentation expects every call for a given target to
come from the same thread that originally created the engine (`DebugCreate`)
and drives its event loop (`WaitForEvent`). Neither of this app's two call
paths gives that guarantee on its own:

- `api.py` (web/HTTP) dispatches blocking calls via
  `starlette.concurrency.run_in_threadpool`, which can hand different calls
  to different worker threads from its pool.
- `desktop_bridge.py` (pywebview's `js_api` bridge) has the same risk -
  pywebview does not document (and this project cannot assume) that
  consecutive JS -> Python calls always land on the same OS thread.

Confirmed live: `IDebugDataSpaces::ReadVirtual` succeeded reading the exact
same bytes at the exact same address twice via the synchronous "Dump Memory"
path (`session.dump_memory`), then failed with `ERROR_READ_FAULT` moments
later reading that same address from inside `go()`'s breakpoint-planting
step (`ComtypesDebugBridge._plant_breakpoint`) - the only difference between
the two calls was which path (and therefore, plausibly, which OS thread)
made them. Pinning every call for one session's bridge onto one dedicated
thread removes that variable entirely.

`ThreadPoolExecutor(max_workers=1)` is the whole mechanism: submitting work
to it always runs on the same one worker thread for the executor's entire
lifetime, and `.result()` blocks the caller until that call finishes -
preserving the exact synchronous call shape every `DebugBridge` method
already has. `session.py`'s own `_lock` still serializes *when* calls
happen (so two threads can never call this wrapper concurrently); this only
pins *where* the underlying dbgeng work actually executes.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from app.dynamic.debug_bridge.client import (
    DebugBridge,
    LiveInstruction,
    ModuleInfo,
    StackFrameInfo,
    StopReason,
)

T = TypeVar("T")


class ThreadPinnedDebugBridge(DebugBridge):
    """Delegates every `DebugBridge` method to `wrapped`, always on the same
    one dedicated thread - see module docstring for why."""

    def __init__(self, wrapped: DebugBridge) -> None:
        self._wrapped = wrapped
        # A single-worker pool *is* the pin - every `_run()` call below runs
        # on the same one thread, created lazily on first submission and
        # reused for this wrapper's entire lifetime (one per session, since
        # `session_store.py`'s `bridge_factory` creates a fresh instance per
        # `DebugSession`).
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dbgeng-session")

    def _run(self, func: Callable[..., T], *args: object) -> T:
        return self._executor.submit(func, *args).result()

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        self._run(self._wrapped.connect, host, port, timeout_seconds)

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        return self._run(self._wrapped.attach, process_id, process_name)

    def set_breakpoint(self, runtime_address: int) -> int:
        return self._run(self._wrapped.set_breakpoint, runtime_address)

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        self._run(self._wrapped.clear_breakpoint, breakpoint_id)

    def step_into(self) -> StopReason:
        return self._run(self._wrapped.step_into)

    def step_over(self) -> StopReason:
        return self._run(self._wrapped.step_over)

    def go(
        self, timeout_seconds: float, breakpoint_addresses: frozenset[int] = frozenset()
    ) -> StopReason:
        return self._run(self._wrapped.go, timeout_seconds, breakpoint_addresses)

    def read_registers(self) -> dict[str, int]:
        return self._run(self._wrapped.read_registers)

    def read_stack(self, max_frames: int) -> list[StackFrameInfo]:
        return self._run(self._wrapped.read_stack, max_frames)

    def current_instruction_address(self) -> int:
        return self._run(self._wrapped.current_instruction_address)

    def disconnect(self) -> None:
        try:
            self._run(self._wrapped.disconnect)
        finally:
            # Best-effort, non-blocking shutdown - never hang `disconnect`
            # (documented idempotent/best-effort, see `DebugBridge.disconnect`)
            # on a worker thread that is somehow already stuck.
            self._executor.shutdown(wait=False, cancel_futures=True)

    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        return self._run(self._wrapped.create_and_attach_local, command_line)

    def write_register(self, name: str, value: int) -> None:
        self._run(self._wrapped.write_register, name, value)

    def write_memory(self, address: int, data: bytes) -> None:
        self._run(self._wrapped.write_memory, address, data)

    def disassemble_range(self, address: int, instruction_count: int) -> list[LiveInstruction]:
        return self._run(self._wrapped.disassemble_range, address, instruction_count)

    def module_label_at(self, address: int) -> str | None:
        return self._run(self._wrapped.module_label_at, address)

    def read_memory(self, address: int, size: int) -> bytes:
        return self._run(self._wrapped.read_memory, address, size)
