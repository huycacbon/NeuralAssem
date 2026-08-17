"""Per-session debug state machine.

One `DebugSession` wraps one `DebugBridge` connection to one attached
process in the user's VM, plus the bookkeeping needed to answer the API
layer's queries: the current address translated into the static graph's
coordinate space (`address_map`), a register/stack snapshot, the breakpoint
list, and the idle-tracking `session_store.py`'s reaper relies on.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from app.dynamic.debug_bridge.address_map import (
    is_canonical_x64_address,
    runtime_to_static,
    static_to_runtime,
)
from app.dynamic.debug_bridge.client import DebugBridge, StopReason
from app.dynamic.models import (
    BreakpointModel,
    LiveDisassemblyResponse,
    LiveInstructionModel,
    MemoryDumpResponse,
    RegisterModel,
    SessionStateResponse,
    StackFrameModel,
)
from app.utils.address import format_address
from app.utils.security import safe_unlink

logger = logging.getLogger(__name__)


class SessionStatus(StrEnum):
    CONNECTING = "connecting"
    ATTACHED = "attached"
    RUNNING = "running"
    BREAK = "break"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class DynamicSessionError(RuntimeError):
    """Session-level failure not caused by the debug bridge itself (bad
    breakpoint id, wrong state, etc) - `api.py` translates this into the
    structured error envelope with `.code`/`.message`."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _Breakpoint:
    id: int
    #: `None` for a breakpoint set directly at a *runtime* address (see
    #: `set_runtime_breakpoint`) - typically somewhere outside the sample's
    #: own module (a system DLL like ntdll), where no meaningful static
    #: address exists at all: the static graph never covered it, and
    #: `address_map`'s rebase delta is only valid for the sample's own
    #: module, not an unrelated one loaded at its own, different base.
    static_address: int | None
    runtime_address: int


class DebugSession:
    """Not safe to use from two threads at once *without* going through the
    methods below - every one of them takes `_lock`, because dbgeng calls
    are inherently serial per target and `go()` can legitimately block for a
    long time."""

    def __init__(
        self,
        session_id: str,
        analysis_id: str,
        bridge: DebugBridge,
        preferred_image_base: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session_id = session_id
        self.analysis_id = analysis_id
        self._bridge = bridge
        self._preferred_image_base = preferred_image_base
        self._clock = clock

        self._lock = threading.Lock()
        self.status = SessionStatus.CONNECTING
        self._module_load_base: int | None = None
        self._breakpoints: dict[int, _Breakpoint] = {}
        self._last_error: str | None = None
        self._last_activity = clock()
        # Set only for local-launch-from-upload sessions - the staged temp
        # file this session is responsible for cleaning up (best-effort, on
        # launch failure and on disconnect). `None` for every other session
        # kind (remote, or local-launch with a user-typed path to a file the
        # user already owns and manages themselves).
        self._owned_temp_file: Path | None = None

    # -- idle tracking, used by session_store.py's reaper ------------------

    def touch(self) -> None:
        self._last_activity = self._clock()

    def is_idle(self, idle_timeout_seconds: int) -> bool:
        return (self._clock() - self._last_activity) >= idle_timeout_seconds

    # -- lifecycle -----------------------------------------------------------

    def connect_and_attach(
        self,
        host: str,
        port: int,
        process_id: int | None,
        process_name: str | None,
        timeout_seconds: float,
    ) -> None:
        with self._lock:
            self.touch()
            try:
                self._bridge.connect(host, port, timeout_seconds)
                module = self._bridge.attach(process_id, process_name)
                self._module_load_base = module.load_base
                logger.warning(
                    "Remote debug attach: session=%s load_base=0x%x preferred_image_base=0x%x",
                    self.session_id,
                    module.load_base,
                    self._preferred_image_base,
                )
                self.status = SessionStatus.ATTACHED
            except Exception as exc:
                self.status = SessionStatus.ERROR
                self._last_error = str(exc)
                # `connect()` may have opened the TCP connection even though
                # `attach()` then failed - avoid leaking it (best-effort;
                # `disconnect()` is documented as idempotent/never-raising).
                try:
                    self._bridge.disconnect()
                except Exception:  # pragma: no cover - best-effort cleanup
                    pass
                raise

    def launch_local(self, command_line: str, owned_temp_file: Path | None = None) -> None:
        """Local-launch path: the bridge itself executes `command_line` on
        this host, directly - see `DebugBridge.create_and_attach_local`'s
        docstring for the full rationale and why this is the one operation
        in this whole package that gets an explicit audit log line. Callers
        (session_store.py/api.py) are responsible for having already shown
        the user the local-launch-specific warning; this method does not
        gate on that itself - it only executes and logs.

        `owned_temp_file`, if given (local-launch-from-upload only - see
        `session_store.create_local_from_upload`), is remembered so
        `disconnect()` can clean it up; on failure here it is cleaned up
        immediately instead, mirroring the existing best-effort bridge
        disconnect below.
        """
        with self._lock:
            self.touch()
            self._owned_temp_file = owned_temp_file
            logger.warning(
                "Local-launch debug: session=%s analysis=%s command_line=%r owned_temp_file=%s",
                self.session_id,
                self.analysis_id,
                command_line,
                owned_temp_file,
            )
            try:
                module = self._bridge.create_and_attach_local(command_line)
                self._module_load_base = module.load_base
                logger.warning(
                    "Local-launch debug: session=%s load_base=0x%x preferred_image_base=0x%x",
                    self.session_id,
                    module.load_base,
                    self._preferred_image_base,
                )
                self.status = SessionStatus.ATTACHED
            except Exception as exc:
                self.status = SessionStatus.ERROR
                self._last_error = str(exc)
                try:
                    self._bridge.disconnect()
                except Exception:  # pragma: no cover - best-effort cleanup
                    pass
                safe_unlink(self._owned_temp_file)
                raise

    def disconnect(self) -> None:
        with self._lock:
            try:
                self._bridge.disconnect()
            finally:
                self.status = SessionStatus.DISCONNECTED
                # Best-effort - covers explicit disconnect, idle-timeout
                # eviction, and capacity eviction, all of which route through
                # here. May silently no-op if the OS still has the image file
                # locked while the launched process is alive; that's fine,
                # `safe_unlink` never raises and there is no other cleanup
                # path that would do better right now.
                safe_unlink(self._owned_temp_file)

    # -- breakpoints -----------------------------------------------------

    def _require_load_base(self) -> int:
        if self._module_load_base is None:
            raise DynamicSessionError(
                "DYNAMIC_NOT_ATTACHED", "Phiên chưa attach vào tiến trình nào"
            )
        return self._module_load_base

    def set_breakpoint(self, static_address: int) -> BreakpointModel:
        """For an address inside the sample's *own* module - the normal
        case, everything reachable from the graph/CFG/function list. Rebases
        through `address_map` using the sample's own load base."""
        with self._lock:
            self.touch()
            load_base = self._require_load_base()
            runtime_address = static_to_runtime(
                static_address, load_base, self._preferred_image_base
            )
            if not is_canonical_x64_address(runtime_address):
                # Confirmed live cause: a *runtime* address (e.g. copied from
                # the "Runtime address" field, or a live-disassembly row -
                # that one should go through `set_runtime_breakpoint`
                # instead) fed into this *static*-address parameter gets the
                # rebase delta applied a second time, landing outside any
                # address x86-64 can even represent - surfaces many calls
                # later as an opaque `ReadVirtual` failure otherwise. Caught
                # right here instead, with a message that says what's
                # actually wrong.
                raise DynamicSessionError(
                    "DYNAMIC_INVALID_ADDRESS",
                    f"Địa chỉ 0x{static_address:x} sau khi quy đổi sang runtime "
                    f"(0x{runtime_address:x}) không phải địa chỉ x86-64 hợp lệ - có thể bạn đã "
                    "nhập nhầm 'Runtime address' thay vì 'Static address' vào ô này.",
                )
            bp_id = self._bridge.set_breakpoint(runtime_address)
            self._breakpoints[bp_id] = _Breakpoint(
                id=bp_id, static_address=static_address, runtime_address=runtime_address
            )
            return BreakpointModel(
                id=bp_id,
                static_address=format_address(static_address),
                runtime_address=format_address(runtime_address),
            )

    def set_runtime_breakpoint(self, runtime_address: int) -> BreakpointModel:
        """For an address the caller already knows is a *runtime* address -
        the live-disassembly assembly view's fallback rows (system DLLs like
        ntdll, outside the sample's own module - see `disassemble_current`'s
        docstring), where `set_breakpoint`'s static->runtime rebase would be
        actively wrong: that math only holds for the sample's own module,
        and applying it to an unrelated module's address produces a bogus
        address that is not actually mapped there, which is exactly what
        produced a live `ReadVirtual` failure (`ERROR_READ_FAULT`) the one
        time this was tried through the static-only `set_breakpoint` path.
        No `address_map` translation here at all - the address is used
        exactly as given.
        """
        with self._lock:
            self.touch()
            self._require_load_base()  # still requires an attached session
            if not is_canonical_x64_address(runtime_address):
                raise DynamicSessionError(
                    "DYNAMIC_INVALID_ADDRESS",
                    f"Địa chỉ 0x{runtime_address:x} không phải địa chỉ x86-64 hợp lệ.",
                )
            bp_id = self._bridge.set_breakpoint(runtime_address)
            self._breakpoints[bp_id] = _Breakpoint(
                id=bp_id, static_address=None, runtime_address=runtime_address
            )
            return BreakpointModel(
                id=bp_id,
                static_address=None,
                runtime_address=format_address(runtime_address),
            )

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        with self._lock:
            self.touch()
            if breakpoint_id not in self._breakpoints:
                raise DynamicSessionError(
                    "DYNAMIC_BREAKPOINT_NOT_FOUND", f"Không có breakpoint id={breakpoint_id}"
                )
            self._bridge.clear_breakpoint(breakpoint_id)
            del self._breakpoints[breakpoint_id]

    # -- register write (Phase 2's first real hook) -------------------------

    def set_register(self, name: str, value: int) -> None:
        """Write `value` into register `name` on the live engine context -
        see `DebugBridge.write_register`'s docstring for why a subsequent
        step/continue just naturally uses it (no coupling code needed here
        beyond the write itself). Logged (unlike the read-only Phase 1
        operations above) because this is the one place in this class that
        mutates the debuggee's execution state rather than only observing
        or controlling *when* it runs.
        """
        with self._lock:
            self.touch()
            if self.status not in (SessionStatus.ATTACHED, SessionStatus.BREAK):
                raise DynamicSessionError(
                    "DYNAMIC_NOT_STOPPED", "Chỉ sửa được register khi đã dừng (attached/break)"
                )
            logger.info(
                "Register write: session=%s analysis=%s name=%s value=%#x",
                self.session_id,
                self.analysis_id,
                name,
                value,
            )
            try:
                self._bridge.write_register(name, value)
            except NotImplementedError as exc:
                raise DynamicSessionError("DYNAMIC_REGISTER_WRITE_UNSUPPORTED", str(exc)) from exc

    # -- execution control -------------------------------------------------

    def step(self, mode: str) -> None:
        with self._lock:
            self.touch()
            self.status = SessionStatus.RUNNING
            try:
                if mode == "over":
                    self._bridge.step_over()
                else:
                    self._bridge.step_into()
                self.status = SessionStatus.BREAK
            except Exception as exc:
                self.status = SessionStatus.ERROR
                self._last_error = str(exc)
                raise

    def go(self, timeout_seconds: float) -> StopReason:
        with self._lock:
            self.touch()
            self.status = SessionStatus.RUNNING
            try:
                # Always the *runtime* addresses (already translated in
                # `set_breakpoint`, never the static ones the API/UI deal
                # in) - `ComtypesDebugBridge.go` needs these to drive its
                # step-loop workaround for free-running past a breakpoint;
                # see that method's docstring for why it exists. A bridge
                # that resumes reliably through its own native breakpoint
                # mechanism is free to just ignore this set.
                breakpoint_addresses = frozenset(
                    bp.runtime_address for bp in self._breakpoints.values()
                )
                reason = self._bridge.go(timeout_seconds, breakpoint_addresses)
                self.status = SessionStatus.BREAK
                return reason
            except Exception as exc:
                self.status = SessionStatus.ERROR
                self._last_error = str(exc)
                raise

    # -- live disassembly (assembly-view fallback for out-of-module PC) ----

    def disassemble_current(self, instruction_count: int) -> LiveDisassemblyResponse:
        """Disassemble forward from the debugger's current runtime address,
        bypassing `address_map` entirely - unlike everything else in this
        class, this never needs a *static* address to mean anything, so it
        works identically whether the PC is inside the analysed sample or in
        some system DLL the static graph never covered. That is the one gap
        this method exists to close: `AssemblyView` on the frontend falls
        back to this exact call whenever it cannot find an enclosing static
        function for the current address (see `App.tsx`'s
        `debugFunctionCfg`/`liveDisassembly` split).
        """
        # `DebugBridgeError` from any bridge call below is deliberately left
        # to propagate as-is (not translated here) - api.py/desktop_bridge.py
        # already catch it the same way every other bridge call in this class
        # does (502 DYNAMIC_CONNECT_FAILED). Only `NotImplementedError` (the
        # `DebugBridge.disassemble_range` extension point's own default, not
        # a `DebugBridgeError`) is session-level enough to translate here.
        with self._lock:
            self.touch()
            if self.status not in (SessionStatus.ATTACHED, SessionStatus.BREAK):
                raise DynamicSessionError(
                    "DYNAMIC_NOT_STOPPED", "Chỉ disassemble được khi đã dừng (attached/break)"
                )
            runtime_address = self._bridge.current_instruction_address()

            try:
                instructions = self._bridge.disassemble_range(runtime_address, instruction_count)
            except NotImplementedError as exc:
                raise DynamicSessionError("DYNAMIC_DISASSEMBLE_UNSUPPORTED", str(exc)) from exc

            module_label: str | None = None
            try:
                module_label = self._bridge.module_label_at(runtime_address)
            except Exception:  # pragma: no cover - cosmetic only, never fatal
                module_label = None

            return LiveDisassemblyResponse(
                runtime_address=format_address(runtime_address),
                module_label=module_label,
                instructions=[
                    LiveInstructionModel(
                        address=format_address(insn.address),
                        mnemonic=insn.mnemonic,
                        operands=insn.operands,
                    )
                    for insn in instructions
                ],
            )

    # -- memory dump (assembly-view's read/write sibling) -------------------

    def dump_memory(self, address: int, size: int) -> MemoryDumpResponse:
        """Read `size` bytes starting at the *runtime* address `address` -
        no `address_map` translation, same as `disassemble_current` (a
        dump target is not necessarily inside the one module the static
        analyzer covers - system DLLs, heap allocations, stack, etc). Size
        clamping to a sane upper bound happens in the caller (api.py/
        desktop_bridge.py), mirroring `disassemble_current`'s `count` clamp.
        """
        with self._lock:
            self.touch()
            if self.status not in (SessionStatus.ATTACHED, SessionStatus.BREAK):
                raise DynamicSessionError(
                    "DYNAMIC_NOT_STOPPED", "Chỉ dump được memory khi đã dừng (attached/break)"
                )
            try:
                data = self._bridge.read_memory(address, size)
            except NotImplementedError as exc:
                raise DynamicSessionError("DYNAMIC_MEMORY_READ_UNSUPPORTED", str(exc)) from exc

            return MemoryDumpResponse(
                address=format_address(address),
                size=len(data),
                bytes_hex=data.hex(),
            )

    # -- state snapshot (applies address_map here) --------------------------

    def snapshot_state(self) -> SessionStateResponse:
        with self._lock:
            self.touch()
            load_base = self._module_load_base

            runtime_address: int | None = None
            static_address: int | None = None
            registers: list[RegisterModel] = []
            stack: list[StackFrameModel] = []

            if load_base is not None and self.status in (
                SessionStatus.ATTACHED,
                SessionStatus.BREAK,
            ):
                try:
                    runtime_address = self._bridge.current_instruction_address()
                    static_address = runtime_to_static(
                        runtime_address, load_base, self._preferred_image_base
                    )
                    registers = [
                        RegisterModel(name=name, value=format_address(value))
                        for name, value in self._bridge.read_registers().items()
                    ]
                    stack = [
                        StackFrameModel(
                            index=frame.index,
                            runtime_return_address=format_address(frame.return_address),
                            static_return_address=format_address(
                                runtime_to_static(
                                    frame.return_address, load_base, self._preferred_image_base
                                )
                            ),
                        )
                        for frame in self._bridge.read_stack(max_frames=32)
                    ]
                except Exception as exc:
                    # A read failure here must not crash the state endpoint -
                    # it just means this snapshot reports what it can and
                    # surfaces the error in `lastError` for the UI to show.
                    self._last_error = str(exc)

            return SessionStateResponse(
                session_id=self.session_id,
                analysis_id=self.analysis_id,
                status=str(self.status),
                runtime_address=(
                    format_address(runtime_address) if runtime_address is not None else None
                ),
                static_address=(
                    format_address(static_address) if static_address is not None else None
                ),
                module_load_base=format_address(load_base) if load_base is not None else None,
                preferred_image_base=(
                    format_address(self._preferred_image_base) if load_base is not None else None
                ),
                registers=registers,
                stack=stack,
                breakpoints=[
                    BreakpointModel(
                        id=bp.id,
                        static_address=(
                            format_address(bp.static_address)
                            if bp.static_address is not None
                            else None
                        ),
                        runtime_address=format_address(bp.runtime_address),
                    )
                    for bp in self._breakpoints.values()
                ],
                last_error=self._last_error,
            )
