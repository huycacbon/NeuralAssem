"""`DebugBridge` - the interface `session.py`/`session_store.py` program
against for all local-process debugging.

`Win32DebugBridge` (`win32_debug.py`) is the one real implementation, built
on the plain Win32 debug API (`kernel32.dll`) - see that module's own
docstring for the full rationale. This file used to also define
`ComtypesDebugBridge` (raw `dbgeng.dll`/COM vtable calls) and `PykdDebugBridge`
(`pykd`, a `dbgeng` wrapper) for *remote* debugging against a `dbgsrv`
process server running in an isolated VM - that whole remote-debug feature
(UI, API routes, `session_store.create()`) was removed at explicit user
request after a long, confirmed-live chain of dbgeng/COM-specific failures
(miscounted vtable slots, a native breakpoint object corrupting engine
state just from being registered, a wrong `SetExecutionStatus` continuation
value) that a genuinely different foundation (the Win32 debug API,
`Win32DebugBridge`) does not reproduce. `connect`/`attach` stay on this
interface only because `FakeDebugBridge` (the test suite's double) and a
good number of existing tests use them as convenient session-setup
scaffolding - nothing in the running app calls them anymore.

`ctypes` (stdlib, always available) is imported at module level; the rest
of this file is pure Python with no native/Windows-only dependency, so it
imports and runs cleanly on any platform, same as before.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModuleInfo:
    load_base: int
    module_name: str
    size: int


@dataclass(frozen=True)
class StackFrameInfo:
    index: int
    return_address: int


@dataclass(frozen=True)
class LiveInstruction:
    """One line from a live disassembly call - distinct from
    `app.models.graph.Instruction` (the static, angr-derived kind) because
    this one only ever exists for the *current* runtime address, is never
    persisted, and needs no rebasing (it is already in the live process's
    own address space)."""

    address: int
    mnemonic: str
    operands: str = ""


@dataclass(frozen=True)
class StopReason:
    kind: str  # "breakpoint" | "step" | "timeout" | "exited" | "exception"
    breakpoint_id: int | None = None


class DebugBridgeError(RuntimeError):
    """Raised by any `DebugBridge` method on connect/attach/protocol failure.

    `session.py`/`api.py` catch this and translate it into the structured
    DYNAMIC_CONNECT_FAILED/DYNAMIC_TIMEOUT error envelope - there is no
    fallback path of any kind on failure (safety constraint #8).
    """


class DebugBridge(ABC):
    """Debug operations against one attached process.

    One instance corresponds to one debug session's connection; instances
    are not reused across sessions.
    """

    @abstractmethod
    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        """Open the TCP connection to a `dbgsrv` already running at host:port.

        No production caller reaches this anymore (the remote-debug feature
        this backed was removed - see module docstring) - kept on the
        interface only because `FakeDebugBridge`/existing tests use it as
        session-setup scaffolding. `Win32DebugBridge` (the one real bridge)
        raises `NotImplementedError` here.
        """

    @abstractmethod
    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        """Attach to the target process and return its main module's real
        (runtime) load base, name and size. Same "no production caller"
        note as `connect` above applies here."""

    @abstractmethod
    def set_breakpoint(self, runtime_address: int) -> int:
        """Set a breakpoint at a *runtime* address; returns a bridge-assigned id."""

    @abstractmethod
    def clear_breakpoint(self, breakpoint_id: int) -> None: ...

    @abstractmethod
    def step_into(self) -> StopReason: ...

    @abstractmethod
    def step_over(self) -> StopReason: ...

    @abstractmethod
    def go(
        self, timeout_seconds: float, breakpoint_addresses: frozenset[int] = frozenset()
    ) -> StopReason:
        """Resume execution until a breakpoint, exit, or the timeout elapses.

        `breakpoint_addresses` (the session's currently-active breakpoints'
        *runtime* addresses - `session.py::DebugSession.go` is the only
        caller, and it always passes its own `_breakpoints` there) is an
        implementation detail some bridges need and others don't: see
        `Win32DebugBridge.go`'s docstring for how it's used there.
        """

    @abstractmethod
    def read_registers(self) -> dict[str, int]: ...

    @abstractmethod
    def read_stack(self, max_frames: int) -> list[StackFrameInfo]: ...

    @abstractmethod
    def current_instruction_address(self) -> int: ...

    @abstractmethod
    def disconnect(self) -> None:
        """Idempotent - both explicit disconnect and idle-timeout eviction
        call this, and it must not raise on a second call."""

    # --- Local-launch extension point -----------------------------------
    # NOT part of the Phase 1 MVP as originally scoped - added afterwards at
    # explicit, twice-confirmed user request. Unlike every other method on
    # this interface, a working override of this one method makes the app
    # itself execute an arbitrary binary directly - the "sample is never
    # executed" guarantee (README.md #10, `test_sample_is_never_executed`)
    # does not hold once a bridge overrides this. See
    # `docs/dynamic-analysis-spec.md`'s local-launch addendum and
    # `Win32DebugBridge.create_and_attach_local`'s own docstring for the
    # full rationale, scope, and the audit-logging this is paired with in
    # `session.py`. Concrete (not abstract) with a `NotImplementedError`
    # default so a bridge that doesn't support it doesn't have to opt in.
    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        raise NotImplementedError("Local launch chưa được cài đặt trên bridge này")

    # --- Phase 2 extension point ---------------------------------------
    # `write_register`/`write_memory` - patch-and-continue. `Win32DebugBridge`
    # overrides both; this default covers any bridge that doesn't.
    def write_register(self, name: str, value: int) -> None:
        raise NotImplementedError("Phase 2 (patch-and-continue) chưa được cài đặt")

    def write_memory(self, address: int, data: bytes) -> None:
        raise NotImplementedError("Phase 2 (patch-and-continue) chưa được cài đặt")

    # --- Live disassembly extension point --------------------------------
    # Added after Phase 1 shipped, at explicit user request: the static
    # graph (and therefore the assembly view built on top of it, see
    # `frontend/src/components/AssemblyView.tsx`) only ever covers the one
    # module angr analysed - the moment the debugger's PC is somewhere else
    # (ntdll/kernel32/any other loaded module, extremely common: API calls
    # into a system DLL are one of the most frequent places a malware
    # analyst actually wants to look), there is no static function to show
    # code from. This reads and disassembles the *live* process's own bytes
    # instead, address-space-agnostic - no static/runtime rebasing involved,
    # unlike everything else in this file. Concrete with a safe default
    # (matching the Phase 2 pattern above) so a bridge that doesn't support
    # it doesn't have to implement it.
    def disassemble_range(self, address: int, instruction_count: int) -> list[LiveInstruction]:
        raise NotImplementedError("Disassemble trực tiếp chưa được cài đặt trên bridge này")

    def module_label_at(self, address: int) -> str | None:
        """Best-effort ``module!symbol+offset``-style label for `address` -
        purely cosmetic (assembly view header), so a bridge that cannot
        resolve one returns ``None`` rather than raising."""
        return None

    # --- Memory dump extension point --------------------------------------
    # Added at explicit user request: view raw bytes at an arbitrary address
    # with a chosen size, the same "Dump"/`db` capability every other
    # debugger (x64dbg, WinDbg) has. Read-only, address-space-agnostic like
    # `disassemble_range` above (a runtime address, not the static graph's
    # coordinate space) - concrete with a safe default so a bridge that
    # doesn't support it doesn't have to implement it.
    def read_memory(self, address: int, size: int) -> bytes:
        raise NotImplementedError("Dump memory chưa được cài đặt trên bridge này")
