"""Local-process debugging via the plain Win32 debug API
(`kernel32.dll`: `CreateProcess`+`DEBUG_PROCESS`, `WaitForDebugEvent`,
`ContinueDebugEvent`, `ReadProcessMemory`, `WriteProcessMemory`,
`GetThreadContext`/`SetThreadContext`) - deliberately NOT `dbgeng.dll`/COM.

Why this exists, replacing `ComtypesDebugBridge` for the local-launch path:
every bug chased in this whole package's live-testing history -
off-by-N COM vtable slots (twice, confirmed), `IDebugBreakpoint` corrupting
engine state just from being registered, `ERROR_READ_FAULT` from a
mis-rebased address only surfacing three calls later inside `WaitForEvent`,
and finally a plain `WaitForEvent` `E_UNEXPECTED` resuming past an exception
with the wrong `SetExecutionStatus` value (`GO` vs `GO_HANDLED`) - traces
back to the SAME root problem: `dbgeng.dll`'s `IDebugClient`/`IDebugControl`
COM interfaces have no public typelib, so every call in that file is a raw,
hand-counted vtable-slot invocation with no way to verify correctness short
of a live target, and no compiler/type-checker catching a wrong slot number
or a wrong status constant.

This module trades that for Microsoft's *other*, much older and better
documented debugging surface: the plain Win32 debug API. Every function
here is:
- a stable, ordinary DLL export (found by *name*, not a numeric offset into
  an undocumented vtable) - `ctypes.WinDLL("kernel32").WaitForDebugEvent`
  simply cannot silently resolve to the wrong function the way a
  miscounted COM slot can;
- unchanged since Windows NT and extensively publicly documented (MSDN,
  and used as the foundation of essentially every third-party Windows
  debugger/exploit-dev tool - x64dbg, OllyDbg, `pydbg`, `winappdbg`, WinDbg
  itself under the hood);
- built around an explicit, two-value continuation status
  (`DBG_CONTINUE`/`DBG_EXCEPTION_NOT_HANDLED`) with none of dbgeng's
  `GO`/`GO_HANDLED`/`GO_NOT_HANDLED`/`STEP_INTO`/`STEP_OVER` five-way
  ambiguity that caused the most recent live failure.

Scope: **local-launch only** (`create_and_attach_local`) - `connect`/
`attach` (the remote "Connect to dbgsrv" path) raise `NotImplementedError`
here on purpose. There is no Win32-debug-API equivalent of `dbgsrv`'s
network process-server protocol - that protocol is dbgeng-proprietary, so
remote debugging still goes through `ComtypesDebugBridge`
(`session_store.py`'s `bridge_factory`, unchanged). This module only backs
`local_bridge_factory` there.

Same safety scope as `ComtypesDebugBridge.create_and_attach_local`: calling
`create_and_attach_local` makes this application directly execute an
arbitrary binary on the machine it runs on, unsandboxed - see that method's
docstring (still the canonical explanation, referenced rather than
duplicated) for the full rationale and the "never wire this to an
unverified path" constraint.
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes
from dataclasses import dataclass

from app.dynamic.debug_bridge.client import (
    DebugBridge,
    DebugBridgeError,
    LiveInstruction,
    ModuleInfo,
    StackFrameInfo,
    StopReason,
)

logger = logging.getLogger(__name__)

# -- Win32 constants (kernel32.h / winbase.h / winnt.h - stable, public,
# unchanged since Windows NT) --------------------------------------------

_DEBUG_ONLY_THIS_PROCESS = 0x00000002
# Debug event codes (winbase.h).
_EXCEPTION_DEBUG_EVENT = 1
_CREATE_THREAD_DEBUG_EVENT = 2
_CREATE_PROCESS_DEBUG_EVENT = 3
_EXIT_THREAD_DEBUG_EVENT = 4
_EXIT_PROCESS_DEBUG_EVENT = 5
_LOAD_DLL_DEBUG_EVENT = 6
_UNLOAD_DLL_DEBUG_EVENT = 7
_OUTPUT_DEBUG_STRING_EVENT = 8
_RIP_EVENT = 9
# Continue-status values (winbase.h) - the whole point of this module, see
# its docstring: an explicit two-value choice, not dbgeng's five-way
# GO/GO_HANDLED/GO_NOT_HANDLED/STEP_INTO/STEP_OVER.
_DBG_CONTINUE = 0x00010002
_DBG_EXCEPTION_NOT_HANDLED = 0x80010001
# Exception codes (ntstatus.h/winnt.h) relevant to a debug event loop.
_EXCEPTION_BREAKPOINT = 0x80000003
_EXCEPTION_SINGLE_STEP = 0x80000004
# Win32 system error code (winerror.h) `WaitForDebugEvent` reports on a
# legitimate "no event yet" timeout - see `_wait_for_raw_event`'s docstring.
_ERROR_SEM_TIMEOUT = 121
# Memory protection (winnt.h) - PAGE_EXECUTE_READWRITE, used only to
# temporarily unlock a code page for the one write that plants/removes a
# software breakpoint's `0xCC` byte.
_PAGE_EXECUTE_READWRITE = 0x40
# Thread access rights (winnt.h) - broad on purpose: this app owns the
# debuggee entirely as its debugger, no reason to narrow it.
_THREAD_ALL_ACCESS = 0x1FFFFF
# CONTEXT.ContextFlags (winnt.h, AMD64) - what GetThreadContext/
# SetThreadContext actually reads/writes. CONTEXT_AMD64 | CONTROL | INTEGER
# | SEGMENTS covers Rip/EFlags and every GPR this bridge reads/writes;
# floating point/debug registers are never touched.
_CONTEXT_AMD64 = 0x00100000
_CONTEXT_CONTROL = _CONTEXT_AMD64 | 0x00000001
_CONTEXT_INTEGER = _CONTEXT_AMD64 | 0x00000002
_CONTEXT_SEGMENTS = _CONTEXT_AMD64 | 0x00000004
_CONTEXT_FULL = _CONTEXT_CONTROL | _CONTEXT_INTEGER | _CONTEXT_SEGMENTS


# -- Win32 structs (winnt.h/winbase.h - field order/types are the public,
# stable ABI; this is the same struct every native Windows debugger marshals
# the exact same way) -----------------------------------------------------


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _EXCEPTION_RECORD(ctypes.Structure):
    pass


_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_uint64 * 15),
]


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", _EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]


class _CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class _CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class _EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class _UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class _OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.c_char_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class _RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", wintypes.DWORD), ("dwType", wintypes.DWORD)]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", _EXCEPTION_DEBUG_INFO),
        ("CreateThread", _CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", _CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", _EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", _EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", _LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", _UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", _OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", _RIP_INFO),
    ]


class _DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]


# AMD64 CONTEXT (winnt.h) - the FltSave/VectorRegister areas are opaque byte
# blobs here (correct total size only) since this bridge never reads/writes
# floating-point or vector register state, only Rip/EFlags/the integer GPRs
# and segment selectors, all of which come *before* those blobs in the real
# struct layout.
class _CONTEXT(ctypes.Structure):
    _pack_ = 16  # DECLSPEC_ALIGN(16) in the real struct
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("_FltSaveOpaque", ctypes.c_byte * 512),  # XMM_SAVE_AREA32, unused
        ("_VectorRegisterOpaque", ctypes.c_byte * (26 * 16)),  # M128A[26], unused
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


#: `_CONTEXT` field name (case-sensitive, matches the struct above) for
#: every general-purpose register this bridge exposes, in the same order
#: `read_registers`/`session.py` already expect from `ComtypesDebugBridge` -
#: lowercase register name -> `_CONTEXT` field name.
_GPR_FIELD_BY_NAME = {
    "rax": "Rax",
    "rbx": "Rbx",
    "rcx": "Rcx",
    "rdx": "Rdx",
    "rsi": "Rsi",
    "rdi": "Rdi",
    "rsp": "Rsp",
    "rbp": "Rbp",
    "rip": "Rip",
    "r8": "R8",
    "r9": "R9",
    "r10": "R10",
    "r11": "R11",
    "r12": "R12",
    "r13": "R13",
    "r14": "R14",
    "r15": "R15",
}
#: EFLAGS bit position for each individual flag this app exposes - same set
#: `client.py`'s `_FLAG_REGISTER_NAMES` reads/writes, same bit positions
#: Intel's own manual (and every x86 reference) documents.
_EFLAGS_BIT_BY_NAME = {
    "cf": 0,
    "pf": 2,
    "af": 4,
    "zf": 6,
    "sf": 7,
    "tf": 8,
    "if": 9,
    "df": 10,
    "of": 11,
}


def _configure_kernel32_signatures(kernel32: ctypes.WinDLL) -> None:
    """Sets explicit `argtypes`/`restype` for every `kernel32` function this
    module calls.

    Not optional: without this, `ctypes` falls back to assuming every
    argument and the return value are plain 32-bit `int`s. On 64-bit
    Windows that silently truncates every `HANDLE`/pointer-sized parameter
    (`HANDLE`, `LPVOID`, `SIZE_T` are all 64-bit) - the kind of corruption
    that "mostly works" until it doesn't, exactly the class of bug this
    whole module exists to get away from (see module docstring). `wintypes`
    (stdlib, `ctypes.wintypes`) already defines the correctly-sized
    Win32 type aliases used below.
    """
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL

    kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(_DEBUG_EVENT), wintypes.DWORD]
    kernel32.WaitForDebugEvent.restype = wintypes.BOOL

    kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    kernel32.ContinueDebugEvent.restype = wintypes.BOOL

    kernel32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
    kernel32.DebugSetProcessKillOnExit.restype = wintypes.BOOL

    kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
    kernel32.DebugActiveProcessStop.restype = wintypes.BOOL

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(_CONTEXT)]
    kernel32.GetThreadContext.restype = wintypes.BOOL

    kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(_CONTEXT)]
    kernel32.SetThreadContext.restype = wintypes.BOOL

    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL

    kernel32.VirtualProtectEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.VirtualProtectEx.restype = wintypes.BOOL

    kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.FlushInstructionCache.restype = wintypes.BOOL

    # Module-name resolution for `list_modules` - exported directly from
    # kernel32 since Vista (no separate psapi.dll link needed). `hModule`
    # here is the module's base address *as seen inside the target process*
    # (a `LOAD_DLL_DEBUG_EVENT`'s `lpBaseOfDll`), never one of our own
    # process's handles - this is the standard technique every native
    # Windows debugger/process-inspection tool uses to resolve a remote
    # process's own module path.
    kernel32.K32GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.K32GetModuleFileNameExW.restype = wintypes.DWORD


@dataclass
class _PendingEvent:
    """The most recent `_DEBUG_EVENT` this bridge has not yet continued
    past - `ContinueDebugEvent` needs its `dwProcessId`/`dwThreadId`, and
    `go`/`step_into`/`step_over` need to know whether it was an exception
    (needs a `DBG_CONTINUE`/`DBG_EXCEPTION_NOT_HANDLED` choice) or a benign
    notification event (module load, thread exit, ...) that just gets
    acknowledged.

    `pass_through`: `True` means this exception was NOT something this
    bridge itself caused (not one of our planted `0xCC` breakpoints, not
    our own single-step trap) - continuing it needs `DBG_EXCEPTION_NOT_HANDLED`
    ("I did not handle this"), not `DBG_CONTINUE`. Confirmed live: a stop at
    a plain instruction (no int3, no single-step involved - most likely an
    `EXCEPTION_GUARD_PAGE`, which fires constantly during totally normal
    stack growth) that kept `DBG_CONTINUE`-ing back into the *exact same*
    faulting instruction forever - `Step`/`Continue` both looked like they
    "did nothing" because the thread never actually advanced. Windows only
    performs its own default handling for an exception (committing the
    guard page and letting the faulting instruction retry, in that
    example) when told `DBG_EXCEPTION_NOT_HANDLED` - `DBG_CONTINUE` tells
    it "the debugger already fixed this, just retry", which for an
    exception this bridge did nothing about just faults again immediately,
    every time, one exception forwarded right back into another. `False`
    (the default) for events this bridge *did* cause and fully process
    itself (a matched breakpoint hit, our own single-step trap) - those are
    genuinely "handled" and must stay `DBG_CONTINUE`.
    """

    process_id: int
    thread_id: int
    is_exception: bool
    exception_code: int
    exception_address: int
    pass_through: bool = False


class Win32DebugBridge(DebugBridge):
    """See module docstring for the full rationale. Local-launch only."""

    def __init__(self) -> None:
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_kernel32_signatures(self._kernel32)
        self._process_handle: int | None = None
        self._process_id: int | None = None
        self._main_thread_id: int | None = None
        self._thread_handles: dict[int, int] = {}
        self._current_thread_id: int | None = None
        self._pending: _PendingEvent | None = None
        # Software breakpoints - id -> runtime address (bookkeeping only,
        # same split as ComtypesDebugBridge: the physical 0xCC lives in
        # `self._planted`, planted/unplanted lazily by `go`/`step_*`. See
        # that class's `set_breakpoint` docstring for why breakpoints are
        # never a native OS/engine object, only bytes this bridge itself
        # manages - same reasoning applies here even though this bridge
        # doesn't share ComtypesDebugBridge's specific COM failure, the
        # software-breakpoint technique itself is still the right one.
        self._software_breakpoints: dict[int, int] = {}
        self._next_software_breakpoint_id = 1
        self._planted: dict[int, bytes] = {}
        self._pending_rearm: int | None = None
        # Every module currently mapped in the debuggee - the main EXE
        # (registered at `_CREATE_PROCESS_DEBUG_EVENT`) plus every DLL loaded
        # since (`_LOAD_DLL_DEBUG_EVENT`), dropped again on
        # `_UNLOAD_DLL_DEBUG_EVENT` - see `_register_module`/
        # `_unregister_module`. Keyed by load base, the same key `ModuleInfo`
        # itself carries, so a lookup never needs a linear scan.
        self._modules: dict[int, ModuleInfo] = {}

    # -- remote path: not implemented here, see module docstring ----------

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        raise NotImplementedError(
            "Win32DebugBridge chỉ hỗ trợ local-launch - dùng ComtypesDebugBridge cho remote/dbgsrv"
        )

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        raise NotImplementedError(
            "Win32DebugBridge chỉ hỗ trợ local-launch - dùng ComtypesDebugBridge cho remote/dbgsrv"
        )

    # -- process creation ---------------------------------------------------

    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        startup_info = _STARTUPINFOW()
        startup_info.cb = ctypes.sizeof(_STARTUPINFOW)
        process_info = _PROCESS_INFORMATION()
        # CreateProcessW may write into this buffer in place - must be a
        # real mutable buffer, never a Python str/LPCWSTR.
        cmdline_buffer = ctypes.create_unicode_buffer(command_line)

        ok = self._kernel32.CreateProcessW(
            None,
            cmdline_buffer,
            None,
            None,
            False,
            _DEBUG_ONLY_THIS_PROCESS,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info),
        )
        if not ok:
            raise DebugBridgeError(f"CreateProcess thất bại: {self._last_error()}")

        self._process_handle = process_info.hProcess
        self._process_id = process_info.dwProcessId
        self._main_thread_id = process_info.dwThreadId
        self._current_thread_id = process_info.dwThreadId
        self._thread_handles[process_info.dwThreadId] = process_info.hThread

        # By default Windows kills every debuggee when its debugger process
        # exits/detaches - this app's own `disconnect()` is a clean detach
        # (the sample keeps running un-debugged), matching
        # ComtypesDebugBridge's DetachProcesses semantics, so that default
        # must be turned off.
        self._kernel32.DebugSetProcessKillOnExit(False)

        module_base = self._pump_to_initial_break()
        return ModuleInfo(load_base=module_base, module_name=command_line, size=0)

    def _pump_to_initial_break(self) -> int:
        """Auto-continues past every benign startup event (process
        creation, DLL loads, thread creation) exactly the way
        `DEBUG_ENGOPT_INITIAL_BREAK`/`_INITIAL_MODULE_BREAK` made
        `ComtypesDebugBridge` do - stops at the first real exception, which
        for a freshly-created process is always ntdll's own hardcoded
        "initial breakpoint" (the same stop every debugger, WinDbg
        included, shows immediately after attach/create)."""
        import time as _time  # noqa: PLC0415 - only used for the deadline loop below

        module_base = None
        deadline = _time.monotonic() + 30.0
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise DebugBridgeError("Không nhận được initial breakpoint trong 30s sau khi tạo tiến trình")
            event = self._wait_for_raw_event(min(remaining, 30.0))
            if event is None:
                continue  # legitimate wait-timeout on this slice - recheck the deadline
            code = event.dwDebugEventCode
            if code == _CREATE_PROCESS_DEBUG_EVENT:
                info = event.u.CreateProcessInfo
                module_base = int(info.lpBaseOfImage or 0)
                if info.hFile:
                    self._kernel32.CloseHandle(info.hFile)
                self._register_module(module_base)
                self._continue_raw(event, handled=True)
                continue
            if code == _LOAD_DLL_DEBUG_EVENT:
                if event.u.LoadDll.hFile:
                    self._kernel32.CloseHandle(event.u.LoadDll.hFile)
                self._register_module(int(event.u.LoadDll.lpBaseOfDll or 0))
                self._continue_raw(event, handled=True)
                continue
            if code == _CREATE_THREAD_DEBUG_EVENT:
                self._thread_handles[event.dwThreadId] = event.u.CreateThread.hThread
                self._continue_raw(event, handled=True)
                continue
            if code == _EXCEPTION_DEBUG_EVENT:
                exception_code = event.u.Exception.ExceptionRecord.ExceptionCode
                self._current_thread_id = event.dwThreadId
                self._pending = _PendingEvent(
                    process_id=event.dwProcessId,
                    thread_id=event.dwThreadId,
                    is_exception=True,
                    exception_code=exception_code,
                    exception_address=int(
                        event.u.Exception.ExceptionRecord.ExceptionAddress or 0
                    ),
                )
                if module_base is None:
                    raise DebugBridgeError(
                        "Nhận exception trước khi có CREATE_PROCESS_DEBUG_EVENT - không rõ module base"
                    )
                return module_base
            if code == _EXIT_PROCESS_DEBUG_EVENT:
                raise DebugBridgeError(
                    f"Tiến trình thoát ngay khi khởi động (exit code {event.u.ExitProcess.dwExitCode})"
                )
            # OUTPUT_DEBUG_STRING/UNLOAD_DLL/EXIT_THREAD/RIP - acknowledge
            # and keep pumping, nothing this bridge needs from them.
            self._continue_raw(event, handled=True)

    # -- breakpoints (software INT3 - see class/module docstrings) --------

    def set_breakpoint(self, runtime_address: int) -> int:
        bp_id = self._next_software_breakpoint_id
        self._next_software_breakpoint_id += 1
        self._software_breakpoints[bp_id] = runtime_address
        return bp_id

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        address = self._software_breakpoints.pop(breakpoint_id, None)
        if address is None:
            raise DebugBridgeError(f"Không có breakpoint id={breakpoint_id} (Win32DebugBridge)")
        if address not in self._software_breakpoints.values():
            self._unplant_breakpoint(address)

    def _plant_breakpoint(self, address: int) -> bool:
        """See `ComtypesDebugBridge._plant_breakpoint`'s docstring for the
        general design (never raises, isolates one bad address from every
        other breakpoint) - identical contract here, just backed by
        `ReadProcessMemory`/`WriteProcessMemory` instead of dbgeng calls."""
        if address in self._planted:
            return True
        original = self.read_memory(address, 1)
        if len(original) != 1:
            logger.warning("Không đọc được byte gốc tại 0x%x - bỏ qua lần resume này", address)
            return False
        self._planted[address] = original
        try:
            self._write_process_memory(address, b"\xcc")
        except DebugBridgeError:
            del self._planted[address]
            logger.warning("Không cấy được breakpoint tại 0x%x - bỏ qua lần resume này", address)
            return False
        return True

    def _unplant_breakpoint(self, address: int) -> None:
        original = self._planted.pop(address, None)
        if original is not None:
            self._write_process_memory(address, original)

    def _sync_planted_breakpoints(self, breakpoint_addresses: frozenset[int]) -> None:
        for address in breakpoint_addresses:
            self._plant_breakpoint(address)
        for address in list(self._planted):
            if address not in breakpoint_addresses:
                self._unplant_breakpoint(address)

    def is_breakpoint_planted(self, runtime_address: int) -> bool:
        return runtime_address in self._planted

    # -- module tracking (main EXE + every DLL load/unload) -----------------

    def list_modules(self) -> list[ModuleInfo]:
        # Re-resolve any module still stuck on its hex-address fallback name
        # (see `_module_name`'s docstring: `K32GetModuleFileNameExW` reliably
        # fails for a module registered *during* the initial debug-event
        # pump - confirmed live, the loader has not finished settling that
        # module into the process's own module list yet at that exact
        # instant) - by the time anything actually calls `list_modules`
        # (well after attach), the loader has long since caught up, so a
        # fresh attempt here is cheap and self-healing without needing a
        # background retry mechanism.
        for base, module in list(self._modules.items()):
            if module.module_name == self._fallback_module_name(base):
                self._modules[base] = ModuleInfo(
                    load_base=base, module_name=self._module_name(base), size=module.size
                )
        return sorted(self._modules.values(), key=lambda module: module.load_base)

    @staticmethod
    def _fallback_module_name(base: int) -> str:
        return f"0x{base:x}"

    def _module_size(self, base: int) -> int:
        """Best-effort `SizeOfImage` for the module mapped at `base`, parsed
        from its own PE headers via `ReadProcessMemory` + `pefile` (lazy
        import, matching this module's existing convention for `capstone` -
        both are hard dependencies transitively pulled in by angr, imported
        lazily anyway for consistency). `0` on any failure (partial read,
        corrupt/packed header, the module unloading mid-read) - callers
        treat that as "size unknown, not fatal": the module is still tracked
        as loaded, just without a size hint, and `_unregister_module` simply
        won't find any breakpoints to clean up inside a 0-byte range."""
        try:
            import pefile  # noqa: PLC0415

            header = self.read_memory(base, 4096)
            pe = pefile.PE(data=header, fast_load=True)
            return int(pe.OPTIONAL_HEADER.SizeOfImage)
        except Exception as exc:
            logger.debug("Không đọc được SizeOfImage cho module tại 0x%x: %s", base, exc)
            return 0

    def _module_name(self, base: int) -> str:
        """Best-effort file path for the module at `base`, via
        `GetModuleFileNameExW` - the standard technique for resolving a
        *target* process's own module path from its base address (an
        `HMODULE` here is just that base address, reinterpreted - never one
        of this process's own handles). Falls back to the bare hex address
        if resolution fails (process exiting mid-call, insufficient buffer -
        520 chars covers `MAX_PATH` with room to spare) - cosmetic only, a
        failure here must never block tracking the module as loaded."""
        buffer = ctypes.create_unicode_buffer(520)
        length = self._kernel32.K32GetModuleFileNameExW(
            self._process_handle, ctypes.c_void_p(base), buffer, len(buffer)
        )
        return buffer.value if length else self._fallback_module_name(base)

    def _register_module(self, base: int) -> None:
        if base == 0 or base in self._modules:
            return
        self._modules[base] = ModuleInfo(
            load_base=base, module_name=self._module_name(base), size=self._module_size(base)
        )

    def _unregister_module(self, base: int) -> None:
        module = self._modules.pop(base, None)
        if module is None or module.size <= 0:
            return
        # Windows freely recycles freed virtual address ranges - the moment
        # this module unmaps, any `0xCC` this bridge left planted somewhere
        # inside its range becomes a landmine for whatever unrelated module
        # (or plain heap/stack memory) happens to get mapped over the same
        # addresses next. Confirmed as a real, live "stuck at an unexpected
        # address" report: Continue/Step appearing to freeze at a location
        # the user never set a breakpoint at - a stale planted byte in
        # memory that used to be a since-unloaded DLL is exactly that
        # symptom. Drop the bookkeeping now, before that can happen; the
        # physical byte is gone with the unmapped page regardless, only the
        # bookkeeping needs cleaning up so a future module loaded at an
        # overlapping address never gets "unplanted" (i.e. have an
        # unrelated byte written back into it) by mistake.
        low, high = module.load_base, module.load_base + module.size
        for address in [addr for addr in self._planted if low <= addr < high]:
            del self._planted[address]
        if self._pending_rearm is not None and low <= self._pending_rearm < high:
            self._pending_rearm = None

    def _rearm_if_pending(self) -> None:
        address = self._pending_rearm
        if address is None:
            return
        self._pending_rearm = None
        self._resume_and_wait(30.0, single_step=True)
        self._plant_breakpoint(address)

    # -- execution control ---------------------------------------------------

    def step_into(self) -> StopReason:
        self._rearm_if_pending()
        # Propagates whatever `_resume_and_wait` actually observed (`"step"`
        # in the ordinary case, but also `"exited"`/`"timeout"` when the
        # debuggee terminates or the wait deadline passes mid-step) instead
        # of a hardcoded `"step"` - a previous version discarded this return
        # value entirely, which meant single-stepping the process's own
        # final instruction (a `ret` immediately followed by process exit,
        # not unusual at all) reported "step" instead of "exited". See
        # `DebugSession.SessionStatus.EXITED`'s docstring for why that
        # distinction matters (a wrong status here made a normal process
        # exit look like the debugger permanently freezing) - see
        # `app.dynamic.session.SessionStatus.EXITED`'s docstring.
        return self._resume_and_wait(30.0, single_step=True)

    def step_over(self) -> StopReason:
        """Steps one source-level "unit": if the current instruction is a
        `CALL`, runs to its return address instead of stepping into the
        callee (a temporary breakpoint at `rip + instruction_length`, the
        same technique `ComtypesDebugBridge` got for free from dbgeng's own
        `DEBUG_STATUS_STEP_OVER` - this bridge has no such built-in, so it's
        implemented explicitly here using capstone, already a transitive
        dependency via angr). Falls back to a plain single step for every
        other instruction."""
        self._rearm_if_pending()
        current = self.current_instruction_address()
        instruction_length = self._call_instruction_length(current)
        if instruction_length is None:
            # Same fix as `step_into` - propagate the real outcome instead of
            # hardcoding "step" (this branch handles every non-CALL
            # instruction, including a `ret` that happens to be the
            # process's very last instruction).
            return self._resume_and_wait(30.0, single_step=True)

        return_address = current + instruction_length
        planted_temp = return_address not in self._planted
        self._plant_breakpoint(return_address)
        try:
            reason = self._resume_and_wait(30.0, single_step=False)
        finally:
            if planted_temp and return_address not in self._software_breakpoints.values():
                self._unplant_breakpoint(return_address)
                if self._pending_rearm == return_address:
                    self._pending_rearm = None
        return reason

    def _call_instruction_length(self, address: int) -> int | None:
        """`None` unless the instruction at `address` is a `CALL` - in
        which case, its length in bytes. Lazy `capstone` import, matching
        this package's existing lazy-import convention for optional native
        dependencies."""
        import capstone  # noqa: PLC0415

        code = self.read_memory(address, 16)  # max x86-64 instruction length is 15 bytes
        if not code:
            return None
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for instruction in disassembler.disasm(code, address, count=1):
            if instruction.mnemonic.lower().startswith("call"):
                return instruction.size
            return None
        return None

    def go(
        self, timeout_seconds: float, breakpoint_addresses: frozenset[int] = frozenset()
    ) -> StopReason:
        """Resume until a planted breakpoint fires, the process exits, or
        `timeout_seconds` elapses. See `ComtypesDebugBridge.go`'s docstring
        for the same four-step breakpoint dance this mirrors (rearm-pending
        -> sync-planted -> resume -> fix-up-rip-on-hit); the only thing
        that changes here is *how* "resume" and "continuation status" work
        (`_resume_and_wait` below), not the breakpoint bookkeeping itself.
        """
        self._rearm_if_pending()
        self._sync_planted_breakpoints(breakpoint_addresses)
        return self._resume_and_wait(timeout_seconds, single_step=False)

    def _resume_and_wait(self, timeout_seconds: float, single_step: bool) -> StopReason:
        import time as _time  # noqa: PLC0415 - only used for the deadline loop below

        if single_step:
            self._set_trap_flag(self._current_thread_id, True)

        if self._pending is not None:
            # `handled=False` (DBG_EXCEPTION_NOT_HANDLED) for a pass-through
            # exception (see `_PendingEvent.pass_through`'s docstring for
            # the guard-page "step does nothing forever" failure this
            # distinction fixes) - `handled=True` for one this bridge
            # caused and fully processed itself (a matched breakpoint hit,
            # our own single-step trap).
            self._continue_pending(handled=not self._pending.pass_through)
        elif single_step:
            # No pending event to continue past (e.g. a fresh session that
            # hasn't hit anything yet) but the caller wants exactly one
            # instruction - WaitForDebugEvent below still needs a real
            # event to consume, which the trap flag set above will produce.
            pass

        deadline = _time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return StopReason(kind="timeout")
            event = self._wait_for_raw_event(min(remaining, 30.0))
            if event is None:
                continue  # legitimate wait-timeout on this slice - recheck the outer deadline
            code = event.dwDebugEventCode

            if code == _EXIT_PROCESS_DEBUG_EVENT:
                self._pending = None
                return StopReason(kind="exited")

            if code == _CREATE_THREAD_DEBUG_EVENT:
                # A thread created *after* the initial attach (extremely
                # common - CRT/TLS init, thread pools, anything genuinely
                # multi-threaded) - without registering its handle here,
                # `current_instruction_address`/`read_registers` fail with a
                # opaque `GetThreadContext`/`WinError 31` the moment an
                # exception happens to land on this thread, since
                # `_pump_to_initial_break` (attach time) is the only other
                # place that populates `self._thread_handles`.
                self._thread_handles[event.dwThreadId] = event.u.CreateThread.hThread
                self._continue_raw(event, handled=True)
                continue

            if code == _EXIT_THREAD_DEBUG_EVENT:
                # Mirror image of the above - close the handle and forget
                # it, so a later `current_instruction_address()` call can
                # never land on a dead thread's stale handle.
                handle = self._thread_handles.pop(event.dwThreadId, None)
                if handle:
                    self._kernel32.CloseHandle(handle)
                self._continue_raw(event, handled=True)
                continue

            if code == _LOAD_DLL_DEBUG_EVENT:
                if event.u.LoadDll.hFile:
                    self._kernel32.CloseHandle(event.u.LoadDll.hFile)
                self._register_module(int(event.u.LoadDll.lpBaseOfDll or 0))
                self._continue_raw(event, handled=True)
                continue

            if code == _UNLOAD_DLL_DEBUG_EVENT:
                # See `_unregister_module`'s docstring - this is also where a
                # stale planted breakpoint inside the unloading module's
                # range gets cleaned up, before the address range can be
                # recycled by whatever loads next.
                self._unregister_module(int(event.u.UnloadDll.lpBaseOfDll or 0))
                self._continue_raw(event, handled=True)
                continue

            if code != _EXCEPTION_DEBUG_EVENT:
                # Any other benign notification (DLL unload, output debug
                # string, RIP) - acknowledge and keep waiting for something
                # that actually matters.
                self._continue_raw(event, handled=True)
                continue

            exception_code = event.u.Exception.ExceptionRecord.ExceptionCode
            exception_address = int(event.u.Exception.ExceptionRecord.ExceptionAddress or 0)
            self._current_thread_id = event.dwThreadId
            self._pending = _PendingEvent(
                process_id=event.dwProcessId,
                thread_id=event.dwThreadId,
                is_exception=True,
                exception_code=exception_code,
                exception_address=exception_address,
            )

            if exception_code == _EXCEPTION_SINGLE_STEP:
                if single_step:
                    self._set_trap_flag(event.dwThreadId, False)
                    return StopReason(kind="step")
                # A single-step trap while free-running should not happen
                # (nothing sets TF outside `_resume_and_wait(single_step=True)`)
                # - acknowledge and keep going rather than getting stuck.
                self._continue_pending(handled=True)
                continue

            if exception_code == _EXCEPTION_BREAKPOINT:
                hit_address = exception_address
                if hit_address in self._planted:
                    self._fix_up_breakpoint_hit(hit_address)
                    return StopReason(kind="breakpoint")
                # An INT3 this bridge did not plant (e.g. ntdll's own
                # padding bytes/another hardcoded breakpoint, or the
                # process's own code deliberately executing INT3) - not
                # actionable, acknowledge and keep running so a real,
                # user-set breakpoint further ahead still has a chance to
                # fire in this same call.
                self._continue_pending(handled=True)
                continue

            # Any other exception (access violation, illegal instruction,
            # a guard-page fault from ordinary stack growth, ...) - not
            # something this bridge tries to interpret; hand it back to the
            # debuggee's own exception handling (second-chance semantics
            # match what a real crash needs) and stop here so the caller
            # can inspect state rather than silently eating it.
            # `pass_through = True`: whichever resume call comes next
            # (Step or Continue) must continue this with
            # `DBG_EXCEPTION_NOT_HANDLED`, not `DBG_CONTINUE` - see
            # `_PendingEvent.pass_through`'s docstring for why getting this
            # wrong makes the thread look permanently frozen.
            self._pending.pass_through = True
            return StopReason(kind="exception")

    def _fix_up_breakpoint_hit(self, hit_address: int) -> None:
        """After a planted `0xCC` fires, `ExceptionAddress` (unlike
        dbgeng's post-hit RIP) is already the *correct* breakpoint address
        - Win32's `EXCEPTION_RECORD.ExceptionAddress` for `EXCEPTION_BREAKPOINT`
        is documented as the INT3's own address, not one past it. `Rip`
        itself, however, *did* already advance past the `0xCC` byte (the
        CPU executed it) - still needs winding back before resuming,
        exactly as `ComtypesDebugBridge.go` does, so the restored original
        instruction executes for real on the next step/continue instead of
        being skipped."""
        self.write_register("rip", hit_address)
        self._unplant_breakpoint(hit_address)
        self._pending_rearm = hit_address

    def _set_trap_flag(self, thread_id: int | None, enabled: bool) -> None:
        if thread_id is None:
            return
        context = self._get_thread_context(thread_id)
        trap_flag_bit = 1 << 8  # EFLAGS.TF
        if enabled:
            context.EFlags |= trap_flag_bit
        else:
            context.EFlags &= ~trap_flag_bit
        self._set_thread_context(thread_id, context)

    def _continue_pending(self, handled: bool) -> None:
        pending = self._pending
        if pending is None:
            return
        status = _DBG_CONTINUE if handled else _DBG_EXCEPTION_NOT_HANDLED
        ok = self._kernel32.ContinueDebugEvent(pending.process_id, pending.thread_id, status)
        self._pending = None
        if not ok:
            raise DebugBridgeError(f"ContinueDebugEvent thất bại: {self._last_error()}")

    def _continue_raw(self, event: _DEBUG_EVENT, handled: bool) -> None:
        status = _DBG_CONTINUE if handled else _DBG_EXCEPTION_NOT_HANDLED
        ok = self._kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status)
        if not ok:
            raise DebugBridgeError(f"ContinueDebugEvent thất bại: {self._last_error()}")

    def _wait_for_raw_event(self, timeout_seconds: float) -> _DEBUG_EVENT | None:
        """`None` on a *legitimate* timeout - no debug event arrived within
        `timeout_seconds` because the debuggee is simply still running with
        nothing to report yet. `WaitForDebugEvent` reports that exact,
        expected case as a `FALSE` return with
        `GetLastError() == ERROR_SEM_TIMEOUT` (121) - confirmed live: a
        second `Continue` (nothing left to report after the first one
        already ran the target to a quiet stretch) surfaced exactly this,
        which a previous version of this method treated as a hard failure
        instead of "keep waiting". Any other `GetLastError()` is a genuine
        failure and still raises.
        """
        event = _DEBUG_EVENT()
        timeout_ms = max(0, int(timeout_seconds * 1000))
        ok = self._kernel32.WaitForDebugEvent(ctypes.byref(event), timeout_ms)
        if not ok:
            if ctypes.get_last_error() == _ERROR_SEM_TIMEOUT:
                return None
            raise DebugBridgeError(f"WaitForDebugEvent thất bại: {self._last_error()}")
        return event

    # -- registers ------------------------------------------------------

    def _get_thread_context(self, thread_id: int) -> _CONTEXT:
        handle = self._thread_handles.get(thread_id)
        if handle is None:
            raise DebugBridgeError(f"Không có handle cho thread {thread_id}")
        context = _CONTEXT()
        context.ContextFlags = _CONTEXT_FULL
        ok = self._kernel32.GetThreadContext(handle, ctypes.byref(context))
        if not ok:
            raise DebugBridgeError(f"GetThreadContext thất bại: {self._last_error()}")
        return context

    def _set_thread_context(self, thread_id: int, context: _CONTEXT) -> None:
        handle = self._thread_handles.get(thread_id)
        if handle is None:
            raise DebugBridgeError(f"Không có handle cho thread {thread_id}")
        ok = self._kernel32.SetThreadContext(handle, ctypes.byref(context))
        if not ok:
            raise DebugBridgeError(f"SetThreadContext thất bại: {self._last_error()}")

    def read_registers(self) -> dict[str, int]:
        if self._current_thread_id is None:
            raise DebugBridgeError("Chưa có thread nào đang dừng")
        context = self._get_thread_context(self._current_thread_id)
        result = {name: getattr(context, field) for name, field in _GPR_FIELD_BY_NAME.items()}
        for name, bit in _EFLAGS_BIT_BY_NAME.items():
            result[name] = (context.EFlags >> bit) & 1
        return result

    def write_register(self, name: str, value: int) -> None:
        if self._current_thread_id is None:
            raise DebugBridgeError("Chưa có thread nào đang dừng")
        context = self._get_thread_context(self._current_thread_id)
        if name in _GPR_FIELD_BY_NAME:
            setattr(context, _GPR_FIELD_BY_NAME[name], value & 0xFFFFFFFFFFFFFFFF)
        elif name in _EFLAGS_BIT_BY_NAME:
            bit = _EFLAGS_BIT_BY_NAME[name]
            if value & 1:
                context.EFlags |= 1 << bit
            else:
                context.EFlags &= ~(1 << bit)
        else:
            raise DebugBridgeError(f"Không nhận diện được register '{name}'")
        self._set_thread_context(self._current_thread_id, context)

    def current_instruction_address(self) -> int:
        if self._current_thread_id is None:
            raise DebugBridgeError("Chưa có thread nào đang dừng")
        return self._get_thread_context(self._current_thread_id).Rip

    # -- stack --------------------------------------------------------------

    def read_stack(self, max_frames: int) -> list[StackFrameInfo]:
        """Best-effort, heuristic stack walk: reads successive quadwords
        upward from the current `rsp`, treating each one that lands inside
        the main module's mapped range as a plausible return address.

        Deliberately NOT a real AMD64 unwind (`RtlVirtualUnwind` +
        `.pdata`/`RUNTIME_FUNCTION` lookup, what dbgeng's own
        `GetStackTrace` and every proper x64 debugger actually does) - that
        needs walking the target's own PE unwind-info tables, a
        meaningfully larger undertaking left for later. This heuristic
        (`rbp`-independent since MSVC x64 rarely keeps a frame pointer) can
        both miss real frames and report false positives; treat it as a
        rough guide, not ground truth, same spirit as
        `disassemble_range`/`module_label_at` below.
        """
        if self._current_thread_id is None:
            return []
        context = self._get_thread_context(self._current_thread_id)
        frames: list[StackFrameInfo] = []
        cursor = context.Rsp
        # Scan a generous window - most of these qwords are locals/spilled
        # registers, not return addresses; `looks_like_code_address` below
        # is the only filter, so overscan a bit to still find `max_frames`
        # plausible hits.
        for index in range(max_frames * 8):
            if len(frames) >= max_frames:
                break
            try:
                data = self.read_memory(cursor, 8)
            except DebugBridgeError:
                # Walked off the end of the stack's actually-committed
                # memory (`ERROR_PARTIAL_COPY`, confirmed live) - this
                # heuristic has no way to know in advance where that edge
                # is, so hitting it is the expected way this loop ends, not
                # a real failure. Stop quietly with whatever frames were
                # already found instead of raising - a crash here must
                # never surface as if the *step/continue* that just
                # succeeded had failed (see `session.snapshot_state`'s own
                # catch-and-report-as-lastError wrapping around this call,
                # which is what turned this into a confusing "Continue
                # failed"-looking banner before this fix).
                break
            cursor += 8
            if len(data) != 8:
                break
            candidate = int.from_bytes(data, "little")
            if self._looks_like_code_address(candidate):
                frames.append(StackFrameInfo(index=len(frames), return_address=candidate))
        return frames

    def _looks_like_code_address(self, address: int) -> bool:
        from app.dynamic.debug_bridge.address_map import is_canonical_x64_address  # noqa: PLC0415

        if address == 0 or not is_canonical_x64_address(address):
            return False
        # Cheap plausibility check only (no section/permission lookup) -
        # a real address in the low, non-kernel half of the address space.
        return address < 0x0000800000000000

    # -- memory ---------------------------------------------------------

    def read_memory(self, address: int, size: int) -> bytes:
        if self._process_handle is None:
            raise DebugBridgeError("Chưa có tiến trình nào để đọc bộ nhớ")
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            self._process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read),
        )
        if not ok and bytes_read.value == 0:
            raise DebugBridgeError(f"ReadProcessMemory thất bại tại 0x{address:x}: {self._last_error()}")
        return buffer.raw[: bytes_read.value]

    def write_memory(self, address: int, data: bytes) -> None:
        self._write_process_memory(address, data)

    def _write_process_memory(self, address: int, data: bytes) -> None:
        if self._process_handle is None:
            raise DebugBridgeError("Chưa có tiến trình nào để ghi bộ nhớ")
        old_protect = wintypes.DWORD(0)
        protected = self._kernel32.VirtualProtectEx(
            self._process_handle,
            ctypes.c_void_p(address),
            len(data),
            _PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        )
        try:
            bytes_written = ctypes.c_size_t(0)
            ok = self._kernel32.WriteProcessMemory(
                self._process_handle,
                ctypes.c_void_p(address),
                data,
                len(data),
                ctypes.byref(bytes_written),
            )
            if not ok or bytes_written.value != len(data):
                raise DebugBridgeError(
                    f"WriteProcessMemory thất bại tại 0x{address:x}: {self._last_error()}"
                )
        finally:
            if protected:
                self._kernel32.VirtualProtectEx(
                    self._process_handle,
                    ctypes.c_void_p(address),
                    len(data),
                    old_protect.value,
                    ctypes.byref(old_protect),
                )
        # Code was just modified (breakpoint plant/removal, or an explicit
        # patch) - without this, the CPU's instruction cache on some
        # microarchitectures can keep executing the stale bytes.
        self._kernel32.FlushInstructionCache(self._process_handle, ctypes.c_void_p(address), len(data))

    # -- live disassembly / cosmetic labels ------------------------------

    def disassemble_range(self, address: int, instruction_count: int) -> list[LiveInstruction]:
        import capstone  # noqa: PLC0415

        # A conservative upper bound on bytes needed - 15 is the max x86-64
        # instruction length; reading that much per requested instruction
        # is always enough, capstone just stops decoding once it runs out.
        code = self.read_memory(address, instruction_count * 15)
        if not code:
            return []
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions: list[LiveInstruction] = []
        for instruction in disassembler.disasm(code, address, count=instruction_count):
            instructions.append(
                LiveInstruction(
                    address=instruction.address,
                    mnemonic=instruction.mnemonic,
                    operands=instruction.op_str,
                )
            )
        return instructions

    def module_label_at(self, address: int) -> str | None:
        # No symbol resolution implemented for this bridge yet (would need
        # PDB/export-table lookups this module doesn't do) - cosmetic-only
        # per the abstract method's own contract, safe to just omit.
        return None

    # -- lifecycle --------------------------------------------------------

    def disconnect(self) -> None:
        """Idempotent, best-effort - matches `DebugBridge.disconnect`'s
        contract. Detaches (`DebugActiveProcessStop`) rather than killing
        the debuggee, matching `ComtypesDebugBridge.disconnect`'s
        `DetachProcesses` semantics - `DebugSetProcessKillOnExit(False)`
        already set in `create_and_attach_local` is what makes a clean
        detach (not a kill) the actual outcome here."""
        if self._pending is not None:
            try:
                self._continue_pending(handled=True)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass

        if self._process_id is not None:
            try:
                self._kernel32.DebugActiveProcessStop(self._process_id)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass

        for handle in self._thread_handles.values():
            try:
                self._kernel32.CloseHandle(handle)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        self._thread_handles.clear()

        if self._process_handle is not None:
            try:
                self._kernel32.CloseHandle(self._process_handle)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        self._process_handle = None
        self._process_id = None

    # -- helpers --------------------------------------------------------

    def _last_error(self) -> str:
        code = ctypes.get_last_error()
        return f"WinError {code}"
