"""Request/response models for the dynamic analysis API.

Reuses ``CamelModel`` from ``app.models.graph`` so the wire format matches
the rest of the API (camelCase JSON, snake_case Python) - a read-only import
of a leaf type, not of the static analyzer's services.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.graph import CamelModel


class LocalLaunchRequest(CamelModel):
    """Body of ``POST /dynamic/sessions/local``.

    Deliberately a separate model from ``ConnectRequest`` rather than an
    optional-mode field on it - the two request shapes correspond to two
    structurally distinct code paths (session_store.py's ``create()`` vs
    ``create_local()``), and keeping them separate here mirrors that.

    Unlike every other request in this module, submitting this one causes
    the app to directly execute ``command_line`` on the host machine - see
    ``app.dynamic.debug_bridge.client.DebugBridge.create_and_attach_local``'s
    docstring for the full rationale.
    """

    analysis_id: str
    command_line: str


class BreakpointCreateRequest(CamelModel):
    #: Hex string in the *static* address space (e.g. "0x401000"), the same
    #: form every other address in this app's API already uses.
    static_address: str


class RuntimeBreakpointCreateRequest(CamelModel):
    #: Hex string in the *runtime* address space directly - no address_map
    #: rebase applied. For addresses outside the sample's own module (system
    #: DLLs like ntdll) where no meaningful static address exists - see
    #: `DebugSession.set_runtime_breakpoint`'s docstring.
    runtime_address: str


class StepRequest(CamelModel):
    mode: Literal["into", "over"] = "into"


class RegisterWriteRequest(CamelModel):
    """Body of ``POST /dynamic/sessions/{id}/registers/{name}``.

    ``value`` is a hex string, the same convention every other
    address/value in this API already uses (e.g. ``"0x401000"``) - the
    register name itself is a path parameter, not part of the body.
    """

    value: str


class RegisterModel(CamelModel):
    name: str
    value: str


class StackFrameModel(CamelModel):
    index: int
    runtime_return_address: str
    #: ``None`` when the frame's return address falls outside the analysed
    #: module (e.g. a return into a system DLL never covered by the static
    #: graph) - nothing to highlight in that case.
    static_return_address: str | None = None


class BreakpointModel(CamelModel):
    id: int
    #: ``None`` for a breakpoint set via ``set_runtime_breakpoint`` (outside
    #: the sample's own module) - see `DebugSession.set_runtime_breakpoint`'s
    #: docstring.
    static_address: str | None
    runtime_address: str
    #: Whether the physical ``0xCC`` is currently written into the debuggee.
    #: ``False`` most commonly means "the module this address is inside
    #: hasn't loaded yet" (a DLL loaded later via ``LoadLibrary``, most
    #: often) - not broken, just not plantable *yet*. Breakpoints are
    #: planted lazily inside ``go()`` (see ``Win32DebugBridge.go``'s
    #: docstring), so this reflects the outcome of the *last* resume, not a
    #: live poll; a not-yet-loaded module's breakpoint keeps retrying every
    #: subsequent ``go()`` automatically until it succeeds.
    planted: bool = True


class ModuleModel(CamelModel):
    """One row of the debuggee's module list (main EXE + every DLL currently
    mapped) - see ``DebugSession.list_modules``'s docstring."""

    load_base: str
    module_name: str
    #: ``0`` when the module's own ``SizeOfImage`` could not be read (best-
    #: effort, see ``Win32DebugBridge._module_size``'s docstring) - not an
    #: error, just "size unknown".
    size: int


class SessionStateResponse(CamelModel):
    session_id: str
    analysis_id: str
    status: str
    runtime_address: str | None = None
    #: The address_map-translated equivalent of ``runtime_address`` in the
    #: coordinate space the already-rendered static graph uses - this is
    #: what the frontend matches against ``GraphNode.address`` to highlight
    #: "where execution is" (spec's address-sync requirement).
    static_address: str | None = None
    module_load_base: str | None = None
    #: The analysed module's *preferred* ImageBase (from the PE header,
    #: what every static address in the app - function list, graph nodes,
    #: CFG - is already computed against). Paired with ``moduleLoadBase``
    #: above, the frontend derives ``rebaseDelta = moduleLoadBase -
    #: preferredImageBase`` once and applies it to *display only* wherever a
    #: static address is shown, so the whole UI reads in the same runtime
    #: coordinate space a real debugger would show - never sent separately
    #: from ``moduleLoadBase`` since it is meaningless on its own.
    preferred_image_base: str | None = None
    registers: list[RegisterModel] = Field(default_factory=list)
    stack: list[StackFrameModel] = Field(default_factory=list)
    breakpoints: list[BreakpointModel] = Field(default_factory=list)
    last_error: str | None = None


class LiveInstructionModel(CamelModel):
    """One line from a live `IDebugControl::Disassemble` call - distinct
    from `app.models.graph.Instruction` (the static, angr-derived kind) used
    everywhere else in this app; see
    `app.dynamic.debug_bridge.client.LiveInstruction`'s docstring."""

    address: str
    mnemonic: str
    operands: str = ""


class LiveDisassemblyResponse(CamelModel):
    """Fallback for the assembly view when the debugger's PC falls outside
    the one module the static analyzer covers - see
    `DebugSession.disassemble_current`'s docstring."""

    runtime_address: str
    #: Best-effort ``module!symbol+offset`` label, ``None`` if dbgeng could
    #: not resolve one - cosmetic only.
    module_label: str | None = None
    instructions: list[LiveInstructionModel] = Field(default_factory=list)


class MemoryDumpResponse(CamelModel):
    """Response of ``GET /dynamic/sessions/{id}/memory`` - see
    ``DebugSession.dump_memory``'s docstring. ``address`` is a *runtime*
    address (same coordinate space the request's ``address`` query param
    is in), not the static graph's - there is no rebasing here, unlike most
    other addresses in this API.
    """

    address: str
    size: int
    #: Raw bytes as a plain hex string (no spaces/prefix, e.g. "9090c3") -
    #: the frontend formats this into the classic address/hex/ASCII rows.
    #: May be shorter than the requested ``size`` if the read ran off the
    #: end of a mapped region - never padded/faked.
    bytes_hex: str


class RiskCheckResponse(CamelModel):
    """Feeds the mandatory warning modal's copy (safety constraint #6)."""

    risk_bucket: str
    risk_score: int
    sample_name: str
    likely_packed: bool
