"""dbgeng debug client - the only file in this whole app that talks to
`dbgeng.dll`/`pykd`.

`DebugBridge` is the interface `session.py`/`session_store.py` program
against. Two implementations exist:

- `ComtypesDebugBridge` - the default (see `session_store.py`'s
  `bridge_factory`). Calls `dbgeng.dll`'s `IDebugClient`/`IDebugControl`/
  `IDebugRegisters`/`IDebugSymbols` COM interfaces directly via raw vtable
  calls (`ctypes`) plus `comtypes` for GUID/COM plumbing - both install on
  any Python version, unlike `pykd`. Its COM vtable slot indices are
  verified against a real `DbgEng.h` header (not guessed from memory) - see
  its class docstring for exactly how and what is still unverified (a real
  `dbgsrv` session, specifically). This distinction matters because an
  incorrect COM vtable slot calls the wrong function with the wrong
  arguments - a memory-safety hazard in THIS process, not a clean Python
  exception - so it is not something to guess at without a reference header
  in hand.
- `PykdDebugBridge` - kept for reference/comparison, but **not usable on
  this project's Python version**: `pykd`'s newest PyPI release
  (`0.3.4.15`) only ships wheels through Python 3.9, and this project runs
  Python 3.14 (confirmed - `pip install pykd` fails with "No matching
  distribution" here). See docs/dynamic-analysis-vm-setup.md §8.

Neither implementation starts, stops, or automates a VM, or touches the
sample file - both only open a TCP connection to an endpoint the user typed
in (`ConnectProcessServer`/`dbgConnect` against an already-running
`dbgsrv`).

`ctypes` (stdlib, always available) is imported at module level; `comtypes`
and `pykd` - both optional, not-always-installed native dependencies - are
imported lazily inside the specific methods that need them, never at module
import time, so the rest of this package (and its tests) import and run
cleanly without either installed. `FakeDebugBridge` (in the test suite)
stands in for both in every test that does not need a real `dbgsrv`.
"""

from __future__ import annotations

import ctypes  # stdlib, always available - unlike pykd/comtypes this needs
# no lazy-import treatment; only `ctypes.WinDLL(...)` calls (inside
# ComtypesDebugBridge's methods) are Windows-specific, not the module itself.
from abc import ABC, abstractmethod
from dataclasses import dataclass


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
    """One line from a live `IDebugControl::Disassemble` call - distinct
    from `app.models.graph.Instruction` (the static, angr-derived kind)
    because this one only ever exists for the *current* runtime address, is
    never persisted, and needs no rebasing (it is already in the live
    process's own address space)."""

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
    """Phase-1 read-only debug operations against one attached process.

    One instance corresponds to one debug session's connection; instances
    are not reused across sessions.
    """

    @abstractmethod
    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        """Open the TCP connection to a `dbgsrv` already running at host:port."""

    @abstractmethod
    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        """Attach to the target process and return its main module's real
        (runtime) load base, name and size."""

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
    def go(self, timeout_seconds: float) -> StopReason:
        """Resume execution until a breakpoint, exit, or the timeout elapses."""

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
    # itself execute an arbitrary binary on the *host* machine - the "sample
    # is never executed" guarantee (README.md #10, `test_sample_is_never_executed`)
    # does not hold once a bridge overrides this. See
    # `docs/dynamic-analysis-spec.md`'s local-launch addendum and
    # `ComtypesDebugBridge.create_and_attach_local`'s own docstring for the
    # full rationale, scope, and the audit-logging this is paired with in
    # `session.py`. Concrete (not abstract) with a `NotImplementedError`
    # default so `PykdDebugBridge` and any future read-only bridge don't have
    # to opt into this.
    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        raise NotImplementedError("Local launch chưa được cài đặt trên bridge này")

    # --- Phase 2 extension point ---------------------------------------
    # `write_register` is no longer purely theoretical: `ComtypesDebugBridge`
    # now overrides it (see that class's "ADDED, NOT LIVE-TESTED
    # (2026-08-11)" docstring entry and `session.py::DebugSession.set_register`),
    # at explicit user request - edit a register, then step/continue and it
    # uses the edited value. `write_memory` remains unimplemented (not
    # requested yet) - this default still covers `PykdDebugBridge` for both.
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
    # (matching the Phase 2 pattern above) so `PykdDebugBridge` does not have
    # to implement it.
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
    # coordinate space) - concrete with a safe default so `PykdDebugBridge`
    # does not have to implement it.
    def read_memory(self, address: int, size: int) -> bytes:
        raise NotImplementedError("Dump memory chưa được cài đặt trên bridge này")


class PykdDebugBridge(DebugBridge):
    """dbgeng client via `pykd`, talking to a remote `dbgsrv`. See module
    docstring for the lazy-import rule and the known gaps in the calls below.
    """

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        import pykd  # noqa: PLC0415 - lazy on purpose, see module docstring

        try:
            # TOUCH THIS UP against a real dbgsrv: depending on the installed
            # pykd version this may instead be `pykd.startRemote(...)` - the
            # connection-string form varies between pykd releases.
            pykd.dbgConnect(f"tcp:server={host},port={port}")
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(
                f"Không kết nối được tới dbgsrv {host}:{port}: {exc}"
            ) from exc

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        import pykd  # noqa: PLC0415

        try:
            # TOUCH THIS UP: whether an explicit attach call is needed here at
            # all depends on how the user started dbgsrv (bare dbgsrv.exe +
            # attach-after-connect, vs. dbgsrv/cdb launched already attached
            # to the sample) - see docs/dynamic-analysis-vm-setup.md.
            if process_id is not None:
                pykd.attach(process_id)
            elif process_name is not None:
                pykd.attach(pykd.getProcess(process_name))
            # else: dbgsrv was already attached when the connection opened.

            module = pykd.module(0)  # the target's own main module
            load_base = int(module.begin())
            end = int(module.end())
            return ModuleInfo(
                load_base=load_base,
                module_name=str(module.name()),
                size=end - load_base,
            )
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Attach vào tiến trình thất bại: {exc}") from exc

    def set_breakpoint(self, runtime_address: int) -> int:
        import pykd  # noqa: PLC0415

        try:
            return int(pykd.setBp(runtime_address))
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Đặt breakpoint thất bại: {exc}") from exc

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        import pykd  # noqa: PLC0415

        try:
            pykd.removeBp(breakpoint_id)
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Xóa breakpoint thất bại: {exc}") from exc

    def step_into(self) -> StopReason:
        import pykd  # noqa: PLC0415

        try:
            pykd.step()
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Step thất bại: {exc}") from exc
        return StopReason(kind="step")

    def step_over(self) -> StopReason:
        import pykd  # noqa: PLC0415

        try:
            pykd.stepover()
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Step over thất bại: {exc}") from exc
        return StopReason(kind="step")

    def go(self, timeout_seconds: float) -> StopReason:
        import pykd  # noqa: PLC0415

        # TOUCH THIS UP: pykd's `go()` blocks until the next debug event with
        # no built-in timeout parameter. `timeout_seconds` is accepted here
        # for the interface's sake, but real enforcement (e.g. running this
        # call on its own worker thread and racing it) needs to be added once
        # this is exercised against a real dbgsrv - a hung target must not be
        # able to block a session's worker thread forever.
        try:
            pykd.go()
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Continue thất bại: {exc}") from exc
        return StopReason(kind="breakpoint")

    def read_registers(self) -> dict[str, int]:
        import pykd  # noqa: PLC0415

        # x86 GPR set only, plus the individual EFLAGS bits (see
        # _GPR_REGISTER_NAMES_X86/_FLAG_REGISTER_NAMES module constants
        # below) - this class is kept for reference/comparison only (not
        # usable on this project's Python version, see module docstring), so
        # unlike ComtypesDebugBridge it has not been given x64
        # (IsPointer64Bit-driven) bitness detection.
        names = _GPR_REGISTER_NAMES_X86 + _FLAG_REGISTER_NAMES
        try:
            return {name: int(pykd.reg(name)) for name in names}
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Đọc register thất bại: {exc}") from exc

    def read_stack(self, max_frames: int) -> list[StackFrameInfo]:
        import pykd  # noqa: PLC0415

        try:
            frames = pykd.getStack()[:max_frames]
            return [
                StackFrameInfo(index=index, return_address=int(frame.returnAddress))
                for index, frame in enumerate(frames)
            ]
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Đọc stack thất bại: {exc}") from exc

    def current_instruction_address(self) -> int:
        import pykd  # noqa: PLC0415

        try:
            return int(pykd.reg("eip"))
        except Exception as exc:  # pragma: no cover - needs a real dbgsrv
            raise DebugBridgeError(f"Đọc địa chỉ instruction hiện tại thất bại: {exc}") from exc

    def disconnect(self) -> None:
        import pykd  # noqa: PLC0415

        # Best-effort, idempotent: eviction and an explicit user-initiated
        # disconnect can both reach this, and a half-torn-down connection
        # must never raise back into session_store.py's cleanup path.
        try:
            pykd.detachProcess()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
        try:
            pykd.dbgDisconnect()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass


# dbgeng constants below are sourced from the real header (see the
# "VERIFIED AGAINST" note in ComtypesDebugBridge's docstring), not memory -
# two of the values initially guessed here during a first draft
# (STEP_OVER/STEP_INTO, and the ENABLED flag bit) turned out to be wrong
# when checked, which is exactly the failure mode the verification pass was
# meant to catch.
_DEBUG_STATUS_GO = 1
_DEBUG_STATUS_STEP_OVER = 4
_DEBUG_STATUS_STEP_INTO = 5
_DEBUG_ATTACH_DEFAULT = 0x00000000
_DEBUG_BREAKPOINT_CODE = 0
_DEBUG_BREAKPOINT_ENABLED = 0x00000004
_DEBUG_ANY_ID = 0xFFFFFFFF
# Without these, the engine never stops for any debug event by default - it
# silently auto-continues past process creation, module loads, etc., so the
# target just runs completely free and GetNumberModules/GetModuleByIndex
# always see zero modules (confirmed live: PING.EXE ran unimpeded for a full
# 10-second WaitForEvent timeout without these options set). Set via
# AddEngineOptions before attach/create - see `_set_initial_break_options`.
_DEBUG_ENGOPT_INITIAL_BREAK = 0x00000020
_DEBUG_ENGOPT_INITIAL_MODULE_BREAK = 0x00000040
# Standard Win32 CreateProcess debug flag (not dbgeng-specific - this is the
# same constant C/C++ code passes to CreateProcess's own dwCreationFlags,
# extremely stable/well-known, unrelated to the vtable-slot risk described
# above). Used only by ComtypesDebugBridge.create_and_attach_local - see its
# docstring for why that method exists at all.
_DEBUG_ONLY_THIS_PROCESS = 0x00000002
# DbgEng.h `#define DEBUG_VALUE_INT8 1` / `DEBUG_VALUE_INT32 3` /
# `DEBUG_VALUE_INT64 4` (DEBUG_VALUE.Type enum) - used only by
# write_register, to tag the value being written with the right width: 8-bit
# (0/1) for individual EFLAGS bits, 32-bit for x86 GPRs, 64-bit for x64 GPRs.
_DEBUG_VALUE_INT8 = 1
_DEBUG_VALUE_INT32 = 3
_DEBUG_VALUE_INT64 = 4

# GPR name sets both bridges' `read_registers()` pick between, by target
# bitness (`ComtypesDebugBridge._is_target_64bit`, `IsPointer64Bit`) - dbgeng
# only recognises the name matching the *actual* debuggee, so reading "rax"
# against a 32-bit target (or "eax" against a 64-bit one) fails outright, not
# silently. x64 adds the eight extended GPRs (r8-r15) on top of the renamed
# 64-bit versions of the original nine.
_GPR_REGISTER_NAMES_X86 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip")
_GPR_REGISTER_NAMES_X64 = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rsp",
    "rbp",
    "rip",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)
# Added at explicit user request - the individual EFLAGS bits. dbgeng
# exposes each flag as its own named pseudo-register (same GetIndexByName/
# GetValue/SetValue mechanism as any GPR, no new vtable slot needed for
# this, and the names/width are identical on x86 and x64 - EFLAGS is always
# 32 bits wide even in long mode): cf (carry), pf (parity), af (auxiliary
# carry), zf (zero), sf (sign), tf (trap/single-step), if (interrupt
# enable), df (direction), of (overflow) - the same nine WinDbg's own `r`
# command mnemonics correspond to. `tf`/`if` are included even though
# WinDbg's default `r` output does not always show a line for them, since
# both matter for anti-debug analysis in particular (TF especially - some
# malware sets or polls it to detect single-stepping).
_FLAG_REGISTER_NAMES = ("cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of")


class _DebugValueUnion(ctypes.Union):
    """First 24 bytes of `DbgEng.h`'s `DEBUG_VALUE` union - verified layout
    (see `ComtypesDebugBridge`'s docstring), but only the `I64` member is
    actually read here (GPR-sized register values); the float/vector
    interpretations are omitted since Phase 1 only reads general-purpose
    registers. `_raw` exists purely to give the union its real 24-byte size
    so `TailOfRawBytes`/`Type` in `_DebugValue` below land at the right
    offset - it is never read."""

    _fields_ = [("I64", ctypes.c_uint64), ("_raw", ctypes.c_ubyte * 24)]


class _DebugValue(ctypes.Structure):
    """Exact layout of `DbgEng.h`'s `DEBUG_VALUE`: a 24-byte union, then
    `TailOfRawBytes`, then `Type` - 32 bytes total (verified against the
    real header, see `ComtypesDebugBridge`'s docstring)."""

    _fields_ = [
        ("union", _DebugValueUnion),
        ("TailOfRawBytes", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


class _DebugStackFrame(ctypes.Structure):
    """Exact layout of `DbgEng.h`'s `DEBUG_STACK_FRAME` (verified against
    the real header, see `ComtypesDebugBridge`'s docstring)."""

    _fields_ = [
        ("InstructionOffset", ctypes.c_uint64),
        ("ReturnOffset", ctypes.c_uint64),
        ("FrameOffset", ctypes.c_uint64),
        ("StackOffset", ctypes.c_uint64),
        ("FuncTableEntry", ctypes.c_uint64),
        ("Params", ctypes.c_uint64 * 4),
        ("Reserved", ctypes.c_uint64 * 6),
        ("Virtual", ctypes.c_int32),  # BOOL is a 4-byte int in the Win32 ABI
        ("FrameNumber", ctypes.c_ulong),
    ]


class ComtypesDebugBridge(DebugBridge):
    """dbgeng client via `comtypes`/`ctypes`, calling `IDebugClient` and its
    companion interfaces directly through `dbgeng.dll`. This is the default
    bridge (see `session_store.py`'s `bridge_factory`), since `pykd` has no
    PyPI wheel for this project's Python version (see this module's
    docstring and docs/dynamic-analysis-vm-setup.md §8).

    ================================================================
    HOW THE VALUES BELOW WERE OBTAINED - READ BEFORE TRUSTING THEM
    ================================================================
    dbgeng's COM interfaces are not registered in Windows' usual COM
    registry/typelib system, so nothing can discover their method layout
    automatically - calling method X on one of these interfaces means
    calling a specific *numbered slot* in an array of raw function pointers
    (the vtable). Get the number wrong and this calls a different, real
    function with arguments meant for another one - a genuine memory-safety
    hazard in THIS process (the analyst's own machine), not a clean Python
    exception. An earlier draft of this class left every dbgeng-specific
    slot as a `None` placeholder for exactly this reason.

    **VERIFIED AGAINST**: `C:\\Program Files (x86)\\Windows Kits\\10\\Include\\
    10.0.26100.0\\um\\DbgEng.h` (the real header, present on the machine this
    was written on because Debugging Tools for Windows happened to already
    be installed there) - every `_SLOT_*`/GUID/struct-layout constant below
    was read directly from that file, not recalled from memory. The four
    GUIDs were additionally cross-checked at runtime: `DebugCreate` +
    `QueryInterface` against a real, loaded `dbgeng.dll` on that same
    machine returned `S_OK` and a non-null pointer for all of
    `IDebugClient`/`IDebugControl`/`IDebugRegisters`/`IDebugSymbols`. COM
    interface layouts are stable once shipped (that is why `IDebugClient2`,
    `IDebugClient3`, etc. exist as *additional* interfaces rather than
    changed ones), so this should hold on any Windows version, but it has
    only been checked against this one header - re-verify if something
    behaves unexpectedly on a different SDK version.

    **LIVE-TESTED, LOCAL-LAUNCH PATH (2026-08-08)**: `create_and_attach_local()`
    end-to-end - `DebugCreate` -> `AddEngineOptions` -> `CreateProcessAndAttach`
    -> `WaitForEvent` -> `GetNumberModules`/`GetModuleByIndex`/
    `GetInstructionOffset` - against both a real-world sample
    (`samples/04_imports.exe`) and a controllable long-lived process
    (`PING.EXE`, to distinguish "engine genuinely stopped" from "timed out
    with the target running free"). This surfaced and fixed two real,
    confirmed bugs, not just theoretical ones:
    1. **Wrong `IDebugControl` vtable slots.** The original manual count of
       `DbgEng.h`'s `IDebugControl` method list missed 3 `STDMETHODV(...)`
       entries (`Output`, `ControlledOutput`, `OutputPrompt` - a macro
       variant distinct from `STDMETHOD`/`STDMETHOD_`, trivial to miss
       scanning by eye), silently shifting every slot after them by 3
       (`SetExecutionStatus`, `GetStackTrace`, `AddBreakpoint`,
       `RemoveBreakpoint`, `WaitForEvent`, `AddEngineOptions` were all
       wrong). Confirmed via an access violation on the wrong slot for
       `AddEngineOptions`, then re-derived mechanically (grepping for every
       `STDMETHODV`/`STDMETHOD` occurrence so the same class of miss cannot
       recur) and verified live with correct results.
    2. **Missing `DEBUG_ENGOPT_INITIAL_BREAK`/`_INITIAL_MODULE_BREAK`.**
       Without setting these via `AddEngineOptions` *before* attaching, the
       engine never stops for any debug event by default - it silently
       auto-continues past process creation and module loads, so the target
       runs completely free and `WaitForEvent` only ever returns on its own
       timeout (`S_FALSE`). Confirmed live: `PING.EXE` printed 9+ replies
       during a full 10-second `WaitForEvent` call before this fix; after
       adding `_set_initial_break_options()`, the same call returned in
       0.28s with 10 modules enumerated and a real instruction pointer at
       the initial breakpoint (`ntdll`'s debugger-break, matching what a
       human WinDbg session sees immediately after attaching).

    **STILL NOT VERIFIED**: breakpoint/step/register-write-adjacent reads
    (`set_breakpoint`, `step_into`/`step_over`, `read_stack`) on a live
    local target - only the attach-through-first-module-enumeration path
    above has been exercised end-to-end so far. The whole **remote**
    (`dbgsrv`) path shares every fix above (same `_finish_attach`, same
    corrected slots) but has not itself been re-tested against a real
    `dbgsrv` - do that before trusting it purely on the strength of the
    local-launch test.

    **NOT IMPLEMENTED**: attach by `process_name` (only `process_id` - see
    `attach()`), fetching the real module name/size (`ModuleInfo.module_name`
    falls back to whatever the caller already called the process,
    `size` is always 0 - `IDebugSymbols::GetModuleNames`' full signature is
    complex enough that it was left out rather than guessed).

    **ADDED, NOT LIVE-TESTED (2026-08-11)**: `disassemble_range`/
    `module_label_at` (`_SLOT_DISASSEMBLE = 26`, `_SLOT_GET_NAME_BY_OFFSET = 7`)
    - the assembly view's fallback for when the debugger's PC is outside the
    one module the static analyzer covers (system DLLs, most commonly). Both
    slots were counted with the same mechanical grep approach that fixed the
    earlier `IDebugControl` slot bugs (see 2026-08-08 entry above) and
    cross-checked against `GetStackTrace`/`AddBreakpoint`/`GetModuleByIndex`
    landing at their already-confirmed numbers in the same pass - but unlike
    those, this pair has not itself been exercised against a real attached
    process yet. Verify against a live target before relying on it.

    **ADDED, NOT LIVE-TESTED (2026-08-11)**: `write_register`
    (`_SLOT_SET_VALUE = 7`, `IDebugRegisters::SetValue`) - the first of the
    two Phase 2 (patch-and-continue) hooks to get a real implementation, at
    explicit user request (edit a register, then step/continue using the
    edited value - ordinary dbgeng behaviour once the value is actually
    written into the engine's context, nothing bespoke needed on top). Slot
    counted the same mechanical way, landing right after the already-live-
    tested `GetValue`(6) and before `GetValues`(8). Writes
    `DEBUG_VALUE.Type = DEBUG_VALUE_INT32`/`_INT64` for x86/x64 GPRs, or
    `DEBUG_VALUE_INT8` for the individual EFLAGS bits added the same day
    (`_FLAG_REGISTER_NAMES`, also user-requested). `write_memory` remains
    the one Phase 2 hook still unimplemented (not requested yet).

    **ADDED, NOT LIVE-TESTED (2026-08-12)**: x64 register support
    (`_GPR_REGISTER_NAMES_X64`, `_SLOT_IS_POINTER_64_BIT = 42`,
    `IDebugControl::IsPointer64Bit`) - at explicit user request.
    `IsPointer64Bit` is unusual among the slots in this file: it carries its
    answer *in the HRESULT itself* (`S_OK`=64-bit, `S_FALSE`=32-bit), not an
    output parameter - see `_query_is_64bit`'s docstring. Queried once per
    attach (`_finish_attach`, cached as `self._is_64bit`) and used by both
    `read_registers` (picks `_GPR_REGISTER_NAMES_X86` vs `_X64`) and
    `write_register` (picks `DEBUG_VALUE_INT32` vs `_INT64` by checking
    membership in `_GPR_REGISTER_NAMES_X64`, not by re-querying). Slot
    counted in the same re-verified `IDebugControl` pass as the others
    (right after `GetPageSize`(41)). `PykdDebugBridge` was deliberately
    *not* given the same treatment - it remains x86-only, consistent with
    its "reference/comparison only, not usable on this project's Python
    version" status (see module docstring).

    **ADDED, NOT LIVE-TESTED (2026-08-11)**: `read_memory` - a fourth COM
    interface, `IDebugDataSpaces` (`_IID_IDEBUG_DATA_SPACES`, GUID read
    straight from `DbgEng.h`'s own `DEFINE_GUID` block, not cross-checked
    live the way the original four were - see the "VERIFIED AGAINST"
    paragraph above), queried in `_finish_attach()` alongside
    registers/symbols. `_SLOT_READ_VIRTUAL = 3` (`ReadVirtual` is the first
    method after the three standard `IUnknown` ones on this interface, so
    this one is about as low-risk a slot count as they come). Backs the
    memory-dump feature (`DebugSession.dump_memory`,
    `frontend/src/components/MemoryDumpPanel.tsx`) - address is a runtime
    address, not the static graph's coordinate space, same as
    `disassemble_range`. Read-only; there is no `write_memory` override.
    """

    # -- COM plumbing: fixed by the COM spec, not dbgeng-specific. --
    _SLOT_QUERY_INTERFACE = 0
    _SLOT_RELEASE = 2

    # -- GUIDs (DbgEng.h `DEFINE_GUID` block + confirmed via a live
    # QueryInterface chain - see docstring). --
    _IID_IDEBUG_CLIENT = "{27FE5639-8407-4F47-8364-EE118FB08AC8}"
    _IID_IDEBUG_CONTROL = "{5182E668-105E-416E-AD92-24EF800424BA}"
    _IID_IDEBUG_REGISTERS = "{CE289126-9E84-45A7-937E-67BB18691493}"
    _IID_IDEBUG_SYMBOLS = "{8C31E98C-983A-48A5-9016-6FE5D667A950}"
    # Read straight from DbgEng.h's own `DEFINE_GUID(IID_IDebugDataSpaces, ...)`
    # block (not cross-checked live like the four above - see "ADDED,
    # NOT LIVE-TESTED (2026-08-11)" entry below).
    _IID_IDEBUG_DATA_SPACES = "{88F7DFAB-3EA7-4C3A-AEFB-C4E8106173AA}"

    # -- vtable slots, counted directly from DbgEng.h's method declaration
    # order for each interface (0 = QueryInterface). See docstring. --
    _SLOT_CONNECT_PROCESS_SERVER = 7  # IDebugClient::ConnectProcessServer
    _SLOT_ATTACH_PROCESS = 12  # IDebugClient::AttachProcess
    _SLOT_CREATE_PROCESS = 13  # IDebugClient::CreateProcess (unused directly -
    # CreateProcessAndAttach below covers this bridge's one local-launch path;
    # kept documented since it sits at this exact slot regardless)
    _SLOT_CREATE_PROCESS_AND_ATTACH = 14  # IDebugClient::CreateProcessAndAttach -
    # see create_and_attach_local()'s docstring: the one slot in this whole
    # file that causes real process execution, not just observation.
    _SLOT_DETACH_PROCESSES = 25  # IDebugClient::DetachProcesses
    # IDebugControl slots below were RE-VERIFIED (not just re-read) against a
    # live dbgeng.dll on 2026-08-08 after a real local launch surfaced wrong
    # values here - the original manual count of DbgEng.h's IDebugControl
    # method list missed 3 `STDMETHODV(...)` entries (Output,
    # ControlledOutput, OutputPrompt - a macro variant distinct from
    # `STDMETHOD`/`STDMETHOD_`, easy to miss when scanning by eye), silently
    # shifting every slot after them by 3. Re-derived mechanically (grepping
    # `STDMETHODV?_?\(` so nothing gets missed a second time) and confirmed
    # live: with the corrected numbers, `CreateProcessAndAttach` -> (engine
    # options below) -> `WaitForEvent` -> `GetModuleByIndex` all returned
    # real, correct data against `samples/04_imports.exe` and
    # `PING.EXE` (10 modules enumerated, a real load base, a real
    # instruction pointer at the initial breakpoint).
    _SLOT_ADD_ENGINE_OPTIONS = 54  # IDebugControl::AddEngineOptions
    _SLOT_IS_POINTER_64_BIT = 42  # IDebugControl::IsPointer64Bit - counted in
    # the same re-verified pass as the slots above (landing right after
    # GetPageSize(41), before ReadBugCheckData(43)); used to pick the x86 vs
    # x64 GPR name set (_GPR_REGISTER_NAMES_X86/_X64 below).
    _SLOT_SET_EXECUTION_STATUS = 50  # IDebugControl::SetExecutionStatus
    _SLOT_GET_STACK_TRACE = 31  # IDebugControl::GetStackTrace
    _SLOT_ADD_BREAKPOINT = 72  # IDebugControl::AddBreakpoint (base, not ...2)
    _SLOT_REMOVE_BREAKPOINT = 73  # IDebugControl::RemoveBreakpoint (base, not ...2)
    _SLOT_WAIT_FOR_EVENT = 93  # IDebugControl::WaitForEvent
    _SLOT_GET_INDEX_BY_NAME = 5  # IDebugRegisters::GetIndexByName
    _SLOT_GET_VALUE = 6  # IDebugRegisters::GetValue
    _SLOT_SET_VALUE = 7  # IDebugRegisters::SetValue
    _SLOT_GET_INSTRUCTION_OFFSET = 11  # IDebugRegisters::GetInstructionOffset
    _SLOT_GET_MODULE_BY_INDEX = 13  # IDebugSymbols::GetModuleByIndex
    _SLOT_READ_VIRTUAL = 3  # IDebugDataSpaces::ReadVirtual - counted the same
    # mechanical way as every other slot here (0=QueryInterface, 1=AddRef,
    # 2=Release, 3=ReadVirtual - first method after the three IUnknown ones).
    _SLOT_GET_NAME_BY_OFFSET = 7  # IDebugSymbols::GetNameByOffset - used only
    # for the assembly view's cosmetic module label (module_label_at), never
    # for anything address-critical.
    _SLOT_DISASSEMBLE = 26  # IDebugControl::Disassemble - re-counted the same
    # mechanical way as the other IDebugControl slots above (grepping every
    # `STDMETHODV?_?\(` in declaration order, 0-based, QueryInterface/AddRef/
    # Release included), landing right after Assemble(25) and before
    # GetDisassembleEffectiveOffset(27) - see disassemble_range()'s docstring.
    # IDebugBreakpoint (returned by AddBreakpoint) - a *third* interface,
    # separate from IDebugControl, needed to configure the breakpoint's
    # address and enable it once created.
    _SLOT_BP_GET_ID = 3  # IDebugBreakpoint::GetId
    _SLOT_BP_SET_FLAGS = 9  # IDebugBreakpoint::SetFlags
    _SLOT_BP_SET_OFFSET = 11  # IDebugBreakpoint::SetOffset

    def __init__(self) -> None:
        self._client: int | None = None
        self._control: int | None = None
        self._registers: int | None = None
        self._symbols: int | None = None
        self._dataspaces: int | None = None
        # Set once in `_finish_attach()` (needs an actual attached target to
        # mean anything - see `_query_is_64bit`'s docstring), then reused by
        # every `read_registers`/`write_register` call rather than re-queried
        # each time.
        self._is_64bit: bool = False
        self._server_handle: int = 0
        self._breakpoint_pointers: dict[int, int] = {}  # our bp id -> IDebugBreakpoint*

    # -- generic COM helpers --------------------------------------------

    @staticmethod
    def _check_hresult(hresult: int, what: str) -> None:
        if hresult < 0:
            raise DebugBridgeError(f"{what} thất bại: HRESULT=0x{hresult & 0xFFFFFFFF:08x}")

    @staticmethod
    def _com_call(this: int, slot: int, restype: object, argtypes: tuple, *args: object) -> object:
        """Call vtable slot `slot` on raw COM interface pointer `this`.

        This is the standard two-level-pointer-dereference mechanics for
        calling any COM vtable method without a registered typelib
        (`this` -> vtable array -> function pointer at `slot`) - correct
        regardless of which interface/method it is. The risk lives entirely
        in the `slot` integer callers pass, not in this helper itself.
        """
        vtable_address = ctypes.cast(this, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if vtable_address is None:
            raise DebugBridgeError("Con trỏ COM interface là NULL")
        function_pointer = ctypes.cast(
            vtable_address, ctypes.POINTER(ctypes.c_void_p * (slot + 1))
        ).contents[slot]
        prototype = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
        function = prototype(function_pointer)
        return function(this, *args)

    def _query_interface(self, this: int, iid_str: str) -> int:
        import comtypes  # noqa: PLC0415

        iid = comtypes.GUID(iid_str)
        out = ctypes.c_void_p()
        hr = self._com_call(
            this,
            self._SLOT_QUERY_INTERFACE,
            ctypes.c_long,
            (ctypes.c_void_p, ctypes.c_void_p),
            ctypes.byref(iid),
            ctypes.byref(out),
        )
        self._check_hresult(hr, f"QueryInterface({iid_str})")
        if out.value is None:
            raise DebugBridgeError(f"QueryInterface({iid_str}) trả về con trỏ NULL")
        return out.value

    def _release(self, this: int | None) -> None:
        if this is None:
            return
        try:
            self._com_call(this, self._SLOT_RELEASE, ctypes.c_ulong, ())
        except Exception:  # pragma: no cover - best-effort cleanup
            pass

    # -- DebugBridge interface -------------------------------------------

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        import comtypes  # noqa: PLC0415

        try:
            dbgeng = ctypes.WinDLL("dbgeng.dll")
        except OSError as exc:
            raise DebugBridgeError(
                "Không load được dbgeng.dll - cần cài Debugging Tools for Windows trên "
                f"máy host trước (docs/dynamic-analysis-vm-setup.md mục 2): {exc}"
            ) from exc

        # `DebugCreate(REFIID InterfaceId, PVOID *Interface)` - a plain
        # exported DLL function (not a vtable call), documented and stable;
        # this part carries none of the vtable-slot risk described above.
        create = dbgeng.DebugCreate
        create.restype = ctypes.c_long
        iid = comtypes.GUID(self._IID_IDEBUG_CLIENT)
        client_ptr = ctypes.c_void_p()
        hr = create(ctypes.byref(iid), ctypes.byref(client_ptr))
        self._check_hresult(hr, "DebugCreate")
        if client_ptr.value is None:
            raise DebugBridgeError("DebugCreate trả về con trỏ IDebugClient NULL")
        self._client = client_ptr.value

        options = f"tcp:server={host},port={port}".encode("ascii")
        server_handle = ctypes.c_uint64()
        hr = self._com_call(
            self._client,
            self._SLOT_CONNECT_PROCESS_SERVER,
            ctypes.c_long,
            (ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64)),
            options,
            ctypes.byref(server_handle),
        )
        self._check_hresult(hr, "ConnectProcessServer")
        self._server_handle = server_handle.value

    def _set_initial_break_options(self) -> None:
        """Must be called (via `self._control`, so *after* it is queried but
        *before* `AttachProcess`/`CreateProcessAndAttach`) or the engine
        never stops for any debug event - see `_DEBUG_ENGOPT_INITIAL_BREAK`'s
        own comment for the confirmed, live-tested failure mode without this.
        """
        hr = self._com_call(
            self._control,
            self._SLOT_ADD_ENGINE_OPTIONS,
            ctypes.c_long,
            (ctypes.c_ulong,),
            _DEBUG_ENGOPT_INITIAL_BREAK | _DEBUG_ENGOPT_INITIAL_MODULE_BREAK,
        )
        self._check_hresult(hr, "AddEngineOptions")

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        if self._client is None:
            raise DebugBridgeError("Chưa connect() trước khi attach()")
        if process_id is None:
            raise DebugBridgeError(
                "ComtypesDebugBridge hiện chỉ hỗ trợ attach theo processId - attach "
                "theo processName cần thêm một lời gọi liệt kê tiến trình từ xa "
                "(IDebugSymbols::GetModuleByModuleName hoặc tương đương) chưa cài đặt."
            )

        self._control = self._query_interface(self._client, self._IID_IDEBUG_CONTROL)
        self._set_initial_break_options()

        hr = self._com_call(
            self._client,
            self._SLOT_ATTACH_PROCESS,
            ctypes.c_long,
            (ctypes.c_uint64, ctypes.c_ulong, ctypes.c_ulong),
            self._server_handle,
            process_id,
            _DEBUG_ATTACH_DEFAULT,
        )
        self._check_hresult(hr, "AttachProcess")
        return self._finish_attach(module_name_hint=process_name)

    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        """Start `command_line` as a brand-new process **directly on this
        host** and attach from the entry point - no `dbgsrv`, no remote
        connection, no VM. `Server=0` means "local machine" to dbgeng, so
        this skips `connect()`/`ConnectProcessServer` entirely and does its
        own `DebugCreate`.

        ================================================================
        WHY THIS METHOD EXISTS - AND WHY IT IS DIFFERENT FROM EVERY OTHER
        METHOD ON THIS CLASS
        ================================================================
        Every other operation in this whole `app/dynamic/` package (connect,
        attach-by-pid to something already running, breakpoints, step,
        registers, stack) either only reads state or only talks to a
        `dbgsrv` the user started themselves. This method is the one
        exception: calling it makes THIS application directly execute an
        arbitrary binary on the analyst's own machine, via
        `IDebugClient::CreateProcessAndAttach` - functionally identical to
        calling `CreateProcess` yourself. There is no way for this code to
        tell "the caller's own trusted executable" apart from "a real
        malware sample's temp path" - both are just a string.

        This was added at the user's explicit, twice-confirmed request
        (see `docs/dynamic-analysis-spec.md`'s local-launch addendum) after
        being told plainly that it means the project's own long-standing
        "sample is never executed" guarantee (README.md #10,
        `test_sample_is_never_executed`) no longer holds for this one
        method. It is intentionally isolated to this single method (see
        `test_dynamic_security.py::test_local_launch_is_isolated_to_one_method`,
        which asserts nothing else in this package can reach
        `CreateProcessAndAttach`), and every call is logged with the exact
        command line by `session.py::DebugSession.launch_local` - this
        method itself does not log, since it has no session context; the
        caller is responsible for that audit trail.

        Never call this against a path you have not personally verified is
        safe to run un-sandboxed. It must never be wired to accept a path
        the user did not type in fresh, themselves, in this session (e.g.
        never pre-filled from an upload/analysis path).
        """
        import comtypes  # noqa: PLC0415

        iid = comtypes.GUID(self._IID_IDEBUG_CLIENT)
        client_ptr = ctypes.c_void_p()
        dbgeng = ctypes.WinDLL("dbgeng.dll")
        create = dbgeng.DebugCreate
        create.restype = ctypes.c_long
        hr = create(ctypes.byref(iid), ctypes.byref(client_ptr))
        self._check_hresult(hr, "DebugCreate")
        if client_ptr.value is None:
            raise DebugBridgeError("DebugCreate trả về con trỏ IDebugClient NULL")
        self._client = client_ptr.value
        self._server_handle = 0  # 0 = local machine, no process server involved

        self._control = self._query_interface(self._client, self._IID_IDEBUG_CONTROL)
        self._set_initial_break_options()

        hr = self._com_call(
            self._client,
            self._SLOT_CREATE_PROCESS_AND_ATTACH,
            ctypes.c_long,
            (
                ctypes.c_uint64,
                ctypes.c_char_p,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ),
            0,  # Server = 0 (local)
            command_line.encode("ascii"),
            _DEBUG_ONLY_THIS_PROCESS,
            0,  # ProcessId = 0 (creating new, not attaching to existing)
            _DEBUG_ATTACH_DEFAULT,
        )
        self._check_hresult(hr, "CreateProcessAndAttach")
        return self._finish_attach(module_name_hint=command_line)

    def _finish_attach(self, module_name_hint: str | None) -> ModuleInfo:
        """Shared by `attach()` and `create_and_attach_local()`: once a
        target is attached (however it got that way - both callers already
        set `self._control` and called `_set_initial_break_options()` before
        the actual `AttachProcess`/`CreateProcessAndAttach` call), acquire
        the remaining interfaces and read the main module's runtime load base.

        `AttachProcess`/`CreateProcessAndAttach` only *start* the attach -
        the engine has not actually processed the initial create-process/
        module-load event yet at that point, so the module list is still
        empty. One `WaitForEvent` call lets the engine reach the initial
        stop (the same "initial breakpoint" a human WinDbg session sees
        right after attaching); only after that is module/register state
        valid to query - and only *because* `_set_initial_break_options()`
        already told the engine to actually stop there, rather than silently
        auto-continuing past every event (the second, deeper bug: without
        that option set, `WaitForEvent` returns only on its own timeout,
        S_FALSE, having let the target run completely free the whole time -
        confirmed live: `PING.EXE` printed 9+ replies during a 10-second
        `WaitForEvent` call with no engine options set). Both bugs (this one
        and the vtable-slot miscounts noted on `_SLOT_ADD_ENGINE_OPTIONS`
        et al. above) were live-tested and fixed together.
        """
        self._registers = self._query_interface(self._client, self._IID_IDEBUG_REGISTERS)
        self._symbols = self._query_interface(self._client, self._IID_IDEBUG_SYMBOLS)
        self._dataspaces = self._query_interface(self._client, self._IID_IDEBUG_DATA_SPACES)

        self._wait_for_event(30.0)
        self._is_64bit = self._query_is_64bit()

        base = ctypes.c_uint64()
        hr = self._com_call(
            self._symbols,
            self._SLOT_GET_MODULE_BY_INDEX,
            ctypes.c_long,
            (ctypes.c_ulong, ctypes.POINTER(ctypes.c_uint64)),
            0,
            ctypes.byref(base),
        )
        self._check_hresult(hr, "GetModuleByIndex")

        return ModuleInfo(
            load_base=base.value,
            # Not fetched here (IDebugSymbols::GetModuleNames' full signature
            # has more parameters than were worth adding for information this
            # bridge does not otherwise need) - fall back to whatever the
            # caller already knows the process as. See class docstring.
            module_name=module_name_hint or "sample",
            size=0,
        )

    def set_breakpoint(self, runtime_address: int) -> int:
        bp_ptr = ctypes.c_void_p()
        hr = self._com_call(
            self._control,
            self._SLOT_ADD_BREAKPOINT,
            ctypes.c_long,
            (ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)),
            _DEBUG_BREAKPOINT_CODE,
            _DEBUG_ANY_ID,  # let dbgeng assign the breakpoint id
            ctypes.byref(bp_ptr),
        )
        self._check_hresult(hr, "AddBreakpoint")
        breakpoint_interface = bp_ptr.value
        if breakpoint_interface is None:
            raise DebugBridgeError("AddBreakpoint trả về con trỏ IDebugBreakpoint NULL")

        hr = self._com_call(
            breakpoint_interface,
            self._SLOT_BP_SET_OFFSET,
            ctypes.c_long,
            (ctypes.c_uint64,),
            runtime_address,
        )
        self._check_hresult(hr, "IDebugBreakpoint::SetOffset")

        hr = self._com_call(
            breakpoint_interface,
            self._SLOT_BP_SET_FLAGS,
            ctypes.c_long,
            (ctypes.c_ulong,),
            _DEBUG_BREAKPOINT_ENABLED,
        )
        self._check_hresult(hr, "IDebugBreakpoint::SetFlags")

        bp_id = ctypes.c_ulong()
        hr = self._com_call(
            breakpoint_interface,
            self._SLOT_BP_GET_ID,
            ctypes.c_long,
            (ctypes.POINTER(ctypes.c_ulong),),
            ctypes.byref(bp_id),
        )
        self._check_hresult(hr, "IDebugBreakpoint::GetId")

        self._breakpoint_pointers[bp_id.value] = breakpoint_interface
        return bp_id.value

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        breakpoint_interface = self._breakpoint_pointers.pop(breakpoint_id, None)
        if breakpoint_interface is None:
            raise DebugBridgeError(f"Không có breakpoint id={breakpoint_id} (ComtypesDebugBridge)")

        # RemoveBreakpoint(THIS_ PDEBUG_BREAKPOINT Bp) - the base IDebugControl
        # method (not RemoveBreakpoint2, which belongs to a different
        # interface, IDebugControl2, not queried here) takes just the
        # breakpoint pointer itself.
        hr = self._com_call(
            self._control,
            self._SLOT_REMOVE_BREAKPOINT,
            ctypes.c_long,
            (ctypes.c_void_p,),
            breakpoint_interface,
        )
        self._check_hresult(hr, "RemoveBreakpoint")

    def _set_execution_status(self, status: int) -> None:
        hr = self._com_call(
            self._control, self._SLOT_SET_EXECUTION_STATUS, ctypes.c_long, (ctypes.c_ulong,), status
        )
        self._check_hresult(hr, "SetExecutionStatus")

    def _wait_for_event(self, timeout_seconds: float) -> None:
        timeout_ms = max(0, int(timeout_seconds * 1000))
        hr = self._com_call(
            self._control,
            self._SLOT_WAIT_FOR_EVENT,
            ctypes.c_long,
            (ctypes.c_ulong, ctypes.c_ulong),
            0,
            timeout_ms,
        )
        self._check_hresult(hr, "WaitForEvent")

    def step_into(self) -> StopReason:
        self._set_execution_status(_DEBUG_STATUS_STEP_INTO)
        self._wait_for_event(30.0)
        return StopReason(kind="step")

    def step_over(self) -> StopReason:
        self._set_execution_status(_DEBUG_STATUS_STEP_OVER)
        self._wait_for_event(30.0)
        return StopReason(kind="step")

    def go(self, timeout_seconds: float) -> StopReason:
        self._set_execution_status(_DEBUG_STATUS_GO)
        self._wait_for_event(timeout_seconds)
        return StopReason(kind="breakpoint")

    def _query_is_64bit(self) -> bool:
        """`IDebugControl::IsPointer64Bit` is unlike almost every other call
        in this file: it has no output parameter at all - the answer *is*
        the HRESULT itself (`S_OK` (0) = 64-bit target, `S_FALSE` (1) =
        32-bit target, per its own MSDN doc). Only a genuine negative
        HRESULT is an error here, so this deliberately does not go through
        `_check_hresult` (which only ever checks `hr < 0`, so it would
        actually have been safe to reuse - but calling it out explicitly
        here is clearer than leaning on that being incidentally true).
        A real error is treated as "assume 32-bit": `read_registers`/
        `write_register` then just fail cleanly on a wrong-bitness register
        name (`GetIndexByName` error) rather than silently misinterpreting
        a 64-bit target's register width.
        """
        hr = self._com_call(self._control, self._SLOT_IS_POINTER_64_BIT, ctypes.c_long, ())
        if hr < 0:
            return False
        return hr == 0

    def read_registers(self) -> dict[str, int]:
        # GPR set picked by the attached target's actual bitness (queried
        # once in `_finish_attach`), plus the individual EFLAGS bits (added
        # at explicit user request - see _FLAG_REGISTER_NAMES's comment) -
        # same names/width on both x86 and x64.
        gpr_names = _GPR_REGISTER_NAMES_X64 if self._is_64bit else _GPR_REGISTER_NAMES_X86
        names = gpr_names + _FLAG_REGISTER_NAMES
        result: dict[str, int] = {}
        for name in names:
            index = ctypes.c_ulong()
            hr = self._com_call(
                self._registers,
                self._SLOT_GET_INDEX_BY_NAME,
                ctypes.c_long,
                (ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulong)),
                name.encode("ascii"),
                ctypes.byref(index),
            )
            self._check_hresult(hr, f"GetIndexByName({name})")

            value = _DebugValue()
            hr = self._com_call(
                self._registers,
                self._SLOT_GET_VALUE,
                ctypes.c_long,
                (ctypes.c_ulong, ctypes.POINTER(_DebugValue)),
                index.value,
                ctypes.byref(value),
            )
            self._check_hresult(hr, f"GetValue({name})")
            result[name] = int(value.union.I64)
        return result

    def write_register(self, name: str, value: int) -> None:
        """Overrides `DebugBridge`'s Phase 2 stub - see this class's
        docstring for the "ADDED, NOT LIVE-TESTED (2026-08-11)" entry.
        Writing here mutates the *engine's* register context directly, so a
        subsequent `step_into`/`step_over`/`go` naturally uses the new value
        - no extra plumbing needed between this method and those.

        Covers all three register widths this bridge reads
        (`read_registers`): `DEBUG_VALUE_INT8` (0/1) for the individual
        EFLAGS bits, `DEBUG_VALUE_INT32`/`_INT64` for x86/x64 GPRs
        respectively - picked by name against `_FLAG_REGISTER_NAMES`/
        `_GPR_REGISTER_NAMES_X64`, not by re-querying `IsPointer64Bit` (the
        cached `self._is_64bit` from `_finish_attach` already answers "is r8
        a valid name to be writing right now" implicitly, since
        `GetIndexByName` below would itself fail first on a wrong-bitness
        name).
        """
        index = ctypes.c_ulong()
        hr = self._com_call(
            self._registers,
            self._SLOT_GET_INDEX_BY_NAME,
            ctypes.c_long,
            (ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulong)),
            name.encode("ascii"),
            ctypes.byref(index),
        )
        self._check_hresult(hr, f"GetIndexByName({name})")

        if name in _FLAG_REGISTER_NAMES:
            width_mask, value_type = 0xFF, _DEBUG_VALUE_INT8
        elif name in _GPR_REGISTER_NAMES_X64:
            width_mask, value_type = 0xFFFFFFFFFFFFFFFF, _DEBUG_VALUE_INT64
        else:
            width_mask, value_type = 0xFFFFFFFF, _DEBUG_VALUE_INT32

        debug_value = _DebugValue()
        # Truncated to the register's real width on purpose - a value that
        # does not fit is the caller's mistake, not something to silently
        # reinterpret.
        debug_value.union.I64 = value & width_mask
        debug_value.Type = value_type
        hr = self._com_call(
            self._registers,
            self._SLOT_SET_VALUE,
            ctypes.c_long,
            (ctypes.c_ulong, ctypes.POINTER(_DebugValue)),
            index.value,
            ctypes.byref(debug_value),
        )
        self._check_hresult(hr, f"SetValue({name})")

    def read_stack(self, max_frames: int) -> list[StackFrameInfo]:
        frame_array = (_DebugStackFrame * max_frames)()
        filled = ctypes.c_ulong()
        hr = self._com_call(
            self._control,
            self._SLOT_GET_STACK_TRACE,
            ctypes.c_long,
            (
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.c_uint64,
                ctypes.POINTER(_DebugStackFrame),
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ),
            # 0/0/0 = use the engine's current frame/stack/instruction
            # registers, per DbgEng.h's own comment on GetStackTrace.
            0,
            0,
            0,
            frame_array,
            max_frames,
            ctypes.byref(filled),
        )
        self._check_hresult(hr, "GetStackTrace")
        return [
            StackFrameInfo(index=i, return_address=int(frame_array[i].ReturnOffset))
            for i in range(filled.value)
        ]

    def current_instruction_address(self) -> int:
        offset = ctypes.c_uint64()
        hr = self._com_call(
            self._registers,
            self._SLOT_GET_INSTRUCTION_OFFSET,
            ctypes.c_long,
            (ctypes.POINTER(ctypes.c_uint64),),
            ctypes.byref(offset),
        )
        self._check_hresult(hr, "GetInstructionOffset")
        return offset.value

    @staticmethod
    def _split_disassembly_line(line: str) -> tuple[str, str]:
        """dbgeng's `Disassemble` returns one already-formatted text line -
        e.g. ``"00401000 55              push    ebp"`` (address, raw opcode
        bytes, mnemonic, operands, column-aligned with spaces - the exact
        padding is undocumented and processor-dependent, but the *order* of
        those four fields is not, so a plain whitespace split is enough: the
        address and byte-dump are always the first two tokens, never the
        mnemonic). Defensive on purpose - this only feeds a read-only display,
        so a line that does not match the expected shape still shows
        *something* (the raw text as "mnemonic") rather than raising.
        """
        parts = line.split(None, 2)
        if len(parts) < 3:
            return (line.strip(), "")
        rest = parts[2].split(None, 1)
        mnemonic = rest[0] if rest else ""
        operands = rest[1] if len(rest) > 1 else ""
        return (mnemonic, operands)

    def disassemble_range(self, address: int, instruction_count: int) -> list[LiveInstruction]:
        """Disassemble forward from `address` for up to `instruction_count`
        instructions, using dbgeng's own disassembler (so it understands
        whatever code is actually loaded there, unlike the static graph -
        see the `DebugBridge.disassemble_range` extension-point docstring
        for why this exists at all). Deliberately forward-only: walking
        *backward* from a runtime address would mean guessing previous
        instruction boundaries on a variable-length ISA with no anchor -
        genuinely ambiguous, not just inconvenient - so this only ever shows
        "here and what comes next", which is also the part an analyst
        stepping through code actually needs most.

        **NOT LIVE-TESTED** (unlike attach/module-enumeration - see this
        class's own docstring) - added after the local-launch live-test
        pass. The vtable slot itself (`_SLOT_DISASSEMBLE = 26`) was
        re-derived with the same mechanical grep-count that fixed the
        earlier `IDebugControl` slot bugs, but the call has not yet been
        exercised against a real attached process.
        """
        buffer = ctypes.create_string_buffer(256)
        instructions: list[LiveInstruction] = []
        cursor = address
        for _ in range(instruction_count):
            size = ctypes.c_ulong()
            end_offset = ctypes.c_uint64()
            hr = self._com_call(
                self._control,
                self._SLOT_DISASSEMBLE,
                ctypes.c_long,
                (
                    ctypes.c_uint64,
                    ctypes.c_ulong,
                    ctypes.c_char_p,
                    ctypes.c_ulong,
                    ctypes.POINTER(ctypes.c_ulong),
                    ctypes.POINTER(ctypes.c_uint64),
                ),
                cursor,
                0,  # Flags - no special disassembly flags requested
                buffer,
                len(buffer),
                ctypes.byref(size),
                ctypes.byref(end_offset),
            )
            self._check_hresult(hr, "Disassemble")
            line = buffer.raw[: size.value].decode("ascii", errors="replace").rstrip("\r\n\x00")
            mnemonic, operands = self._split_disassembly_line(line)
            instructions.append(LiveInstruction(address=cursor, mnemonic=mnemonic, operands=operands))
            if end_offset.value <= cursor:
                break  # malformed/zero-length decode - stop rather than loop forever
            cursor = end_offset.value
        return instructions

    def module_label_at(self, address: int) -> str | None:
        buffer = ctypes.create_string_buffer(260)
        size = ctypes.c_ulong()
        displacement = ctypes.c_uint64()
        hr = self._com_call(
            self._symbols,
            self._SLOT_GET_NAME_BY_OFFSET,
            ctypes.c_long,
            (
                ctypes.c_uint64,
                ctypes.c_char_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_uint64),
            ),
            address,
            buffer,
            len(buffer),
            ctypes.byref(size),
            ctypes.byref(displacement),
        )
        if hr < 0:
            return None  # no symbol info for this address - cosmetic only, never raise
        label = buffer.raw[: max(size.value - 1, 0)].decode("ascii", errors="replace")
        if not label:
            return None
        return f"{label}+0x{displacement.value:x}" if displacement.value else label

    def read_memory(self, address: int, size: int) -> bytes:
        """Reads `size` bytes starting at the runtime address `address` via
        `IDebugDataSpaces::ReadVirtual`. Returns however many bytes dbgeng
        actually reported (`BytesRead`), which can be short of `size` -
        e.g. a dump that runs off the end of a mapped region - never
        padded/faked here; the caller sees exactly what was read.

        **NOT LIVE-TESTED** (2026-08-11) - same caveat as `disassemble_range`/
        `write_register`: `_SLOT_READ_VIRTUAL = 3` and
        `_IID_IDEBUG_DATA_SPACES` were read directly from `DbgEng.h`, not
        cross-checked against a live `dbgeng.dll` the way the four
        originally-queried interfaces were (see class docstring).
        """
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_ulong()
        hr = self._com_call(
            self._dataspaces,
            self._SLOT_READ_VIRTUAL,
            ctypes.c_long,
            (
                ctypes.c_uint64,
                ctypes.c_char_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ),
            address,
            buffer,
            size,
            ctypes.byref(bytes_read),
        )
        self._check_hresult(hr, "ReadVirtual")
        return buffer.raw[: bytes_read.value]

    def disconnect(self) -> None:
        # Best-effort, idempotent - both explicit disconnect and idle-timeout
        # eviction reach this, and a half-torn-down connection must never
        # raise back into session_store.py's cleanup path.
        if self._client is not None:
            try:
                self._com_call(self._client, self._SLOT_DETACH_PROCESSES, ctypes.c_long, ())
            except Exception:  # pragma: no cover - best-effort cleanup
                pass

        for breakpoint_interface in self._breakpoint_pointers.values():
            self._release(breakpoint_interface)
        self._breakpoint_pointers.clear()

        self._release(self._dataspaces)
        self._release(self._symbols)
        self._release(self._registers)
        self._release(self._control)
        self._release(self._client)
        self._dataspaces = self._symbols = self._registers = self._control = self._client = None
