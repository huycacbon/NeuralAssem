"""Dynamic analysis REST endpoints.

Local-launch only - `POST /dynamic/sessions/local` and
`POST /dynamic/sessions/local/upload` cause the app to directly execute a
binary on the host machine (via `Win32DebugBridge`) - see
`app.dynamic.debug_bridge.client.DebugBridge.create_and_attach_local`'s
docstring and `docs/dynamic-analysis-spec.md`'s local-launch addenda for the
full rationale. Every other route is an in-memory session bookkeeping
change against an already-attached session - there is no fallback path
anywhere - a missing analysis or a failed launch is always a structured
error, never a retried/alternate action (safety constraint #8). See
`app.dynamic`'s package docstring and `docs/dynamic-analysis-spec.md` for
the full constraint list.

The remote "Connect to dbgsrv" path (`POST /dynamic/sessions`, a TCP client
to a `dbgsrv` the user ran themselves) that used to sit alongside these was
removed at explicit user request, along with the `ComtypesDebugBridge`
(`dbgeng.dll`/COM) implementation it depended on - see
`app.dynamic.session_store.SessionStore`'s `bridge_factory` docstring for
why.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.dependencies import get_repository
from app.dynamic.config import dynamic_settings
from app.dynamic.debug_bridge.client import DebugBridgeError
from app.dynamic.dependencies import get_session_store
from app.dynamic.models import (
    BreakpointCreateRequest,
    BreakpointModel,
    LiveDisassemblyResponse,
    LocalLaunchRequest,
    MemoryDumpResponse,
    ModuleModel,
    RegisterWriteRequest,
    RiskCheckResponse,
    RuntimeBreakpointCreateRequest,
    SessionStateResponse,
    StepRequest,
)
from app.dynamic.risk_gate import derive_risk_bucket
from app.dynamic.session import DynamicSessionError
from app.dynamic.session_store import (
    DynamicAnalysisNotFound,
    DynamicSessionNotFound,
    SessionStore,
)
from app.repositories.base import AnalysisRepository
from app.utils.address import try_parse_address
from app.utils.security import UploadValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dynamic", tags=["dynamic"])

StoreDep = Annotated[SessionStore, Depends(get_session_store)]
RepositoryDep = Annotated[AnalysisRepository, Depends(get_repository)]


def _error(status_code: int, code: str, message: str, details: str | None = None) -> HTTPException:
    """Same structured `{"error": {...}}` envelope as `app.api.analysis._error`
    - duplicated rather than imported, so this package's only external
    dependency stays "reads the static analyzer's public surface", not "reuses
    an implementation detail of one specific router module"."""
    payload = {
        "error": {
            "code": code,
            "message": message,
            "details": None if settings.is_production else details,
        }
    }
    return HTTPException(status_code=status_code, detail=payload)


def _not_found_analysis(analysis_id: str) -> HTTPException:
    return _error(
        404,
        "DYNAMIC_ANALYSIS_NOT_FOUND",
        "Không tìm thấy kết quả phân tích tĩnh cho sample này",
        f"analysisId={analysis_id}",
    )


def _not_found_session(session_id: str) -> HTTPException:
    return _error(
        404,
        "DYNAMIC_SESSION_NOT_FOUND",
        "Phiên debug không tồn tại (chưa kết nối hoặc đã bị ngắt do idle timeout)",
        f"sessionId={session_id}",
    )


def _invalid_address(value: str) -> HTTPException:
    return _error(400, "DYNAMIC_INVALID_ADDRESS", "Địa chỉ không hợp lệ", f"address={value}")


@router.get("/risk-check/{analysis_id}", response_model=RiskCheckResponse)
def risk_check(analysis_id: str, repository: RepositoryDep) -> RiskCheckResponse:
    """Feeds the mandatory Debug warning modal's copy.

    Never used to decide *whether* the modal shows - it always does, once
    per page session, regardless of risk (safety constraint #6) - only what
    it emphasises.
    """
    record = repository.get(analysis_id)
    if record is None:
        raise _not_found_analysis(analysis_id)

    bucket, score = derive_risk_bucket(record.summary)
    return RiskCheckResponse(
        risk_bucket=bucket,
        risk_score=score,
        sample_name=record.file.name,
        likely_packed=record.summary.likely_packed,
    )


@router.post("/sessions/local", response_model=SessionStateResponse)
async def create_local_session(body: LocalLaunchRequest, store: StoreDep) -> SessionStateResponse:
    """Local-launch: the app itself executes `commandLine` directly on this
    host and attaches from the entry point - no `dbgsrv`, no VM, no remote
    connection of any kind.

    This is the one route in this whole router that makes the app execute a
    binary. It exists at explicit, twice-confirmed user request; see
    `app.dynamic.debug_bridge.client.DebugBridge.create_and_attach_local`'s
    docstring for the full rationale, and
    `docs/dynamic-analysis-spec.md`'s local-launch addendum for how this
    changes the project's "sample is never executed" guarantee. The frontend
    is expected to have already shown its own local-launch-specific warning
    (shown every time, not once-per-session, unlike the general Debug
    warning) before ever calling this - this endpoint does not re-verify
    that client-side gate itself, matching how the general connect flow's
    warning modal isn't re-verified server-side either.
    """
    try:
        session = await run_in_threadpool(
            store.create_local,
            body.analysis_id,
            body.command_line,
            dynamic_settings.connect_timeout_seconds,
        )
    except DynamicAnalysisNotFound as exc:
        raise _not_found_analysis(body.analysis_id) from exc
    except DebugBridgeError as exc:
        raise _error(
            502, "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
        ) from exc
    except Exception as exc:  # pragma: no cover - unexpected bridge failure
        logger.exception("Local-launch debug session thất bại ngoài dự kiến")
        raise _error(
            502, "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
        ) from exc

    return session.snapshot_state()


@router.post("/sessions/local/upload", response_model=SessionStateResponse)
async def create_local_session_from_upload(
    store: StoreDep,
    analysis_id: Annotated[str, Form()],
    file: Annotated[UploadFile, File(description="File cần debug trực tiếp (.exe/.dll)")],
) -> SessionStateResponse:
    """Local-launch from the exact file the frontend still holds in memory
    from the original upload - re-sent here fresh (the static analyzer's own
    copy is already deleted by this point) and staged to a *new*, dynamic/-
    owned temp file (`local_upload.stage_upload`, same validation as the
    static analyzer's own upload - extension, size cap, PE magic bytes).

    Same execution caveat as `POST /dynamic/sessions/local` above, with an
    even larger consequence: this is the one route that turns "upload a
    sample" directly into "the app can execute it" with no manual step left
    at all. See `docs/dynamic-analysis-spec.md`'s local-launch addenda.
    """
    try:
        session = await run_in_threadpool(
            store.create_local_from_upload,
            analysis_id,
            file.file,
            file.filename,
            dynamic_settings.connect_timeout_seconds,
            settings.max_upload_bytes,
        )
    except DynamicAnalysisNotFound as exc:
        raise _not_found_analysis(analysis_id) from exc
    except UploadValidationError as exc:
        raise _error(400, exc.code, exc.message, exc.details) from exc
    except DebugBridgeError as exc:
        raise _error(
            502, "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
        ) from exc
    except Exception as exc:  # pragma: no cover - unexpected bridge failure
        logger.exception("Local-launch-from-upload debug session thất bại ngoài dự kiến")
        raise _error(
            502, "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
        ) from exc
    finally:
        await file.close()

    return session.snapshot_state()


@router.get("/sessions/{session_id}/state", response_model=SessionStateResponse)
def get_state(session_id: str, store: StoreDep) -> SessionStateResponse:
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc
    return session.snapshot_state()


@router.post("/sessions/{session_id}/breakpoints", response_model=BreakpointModel)
def create_breakpoint(
    session_id: str, body: BreakpointCreateRequest, store: StoreDep
) -> BreakpointModel:
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    static_address = try_parse_address(body.static_address)
    if static_address is None:
        raise _invalid_address(body.static_address)

    try:
        return session.set_breakpoint(static_address)
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Không đặt được breakpoint", str(exc)) from exc


@router.post("/sessions/{session_id}/breakpoints/runtime", response_model=BreakpointModel)
def create_runtime_breakpoint(
    session_id: str, body: RuntimeBreakpointCreateRequest, store: StoreDep
) -> BreakpointModel:
    """Same as `create_breakpoint` above, except `body.runtime_address` is
    used as-is - no `address_map` rebase. For addresses outside the sample's
    own module (system DLLs like ntdll) - see
    `DebugSession.set_runtime_breakpoint`'s docstring for why that rebase
    would be actively wrong there, not just unnecessary."""
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    runtime_address = try_parse_address(body.runtime_address)
    if runtime_address is None:
        raise _invalid_address(body.runtime_address)

    try:
        return session.set_runtime_breakpoint(runtime_address)
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Không đặt được breakpoint", str(exc)) from exc


@router.delete("/sessions/{session_id}/breakpoints/{breakpoint_id}")
def delete_breakpoint(session_id: str, breakpoint_id: int, store: StoreDep) -> dict[str, bool]:
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    try:
        session.clear_breakpoint(breakpoint_id)
    except DynamicSessionError as exc:
        raise _error(404, exc.code, exc.message) from exc
    return {"deleted": True}


@router.post("/sessions/{session_id}/registers/{name}", response_model=SessionStateResponse)
async def set_register(
    session_id: str, name: str, body: RegisterWriteRequest, store: StoreDep
) -> SessionStateResponse:
    """Write a register on the live engine context, then return the updated
    snapshot - a subsequent step/continue call naturally uses the new value
    (see `DebugSession.set_register`'s docstring), no separate coupling
    needed between this route and `/step`/`/continue`.
    """
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    value = try_parse_address(body.value)
    if value is None:
        raise _invalid_address(body.value)

    try:
        await run_in_threadpool(session.set_register, name, value)
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Không ghi được register", str(exc)) from exc
    return session.snapshot_state()


@router.get("/sessions/{session_id}/memory", response_model=MemoryDumpResponse)
async def dump_memory(
    session_id: str, store: StoreDep, address: str, size: int = 256
) -> MemoryDumpResponse:
    """Raw memory dump at a *runtime* address (no address_map translation -
    see `DebugSession.dump_memory`'s docstring), the "Dump"/`db` capability
    every other debugger has. `size` is clamped server-side (1-4096)
    regardless of what the caller passes.
    """
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    parsed_address = try_parse_address(address)
    if parsed_address is None:
        raise _invalid_address(address)

    try:
        return await run_in_threadpool(
            session.dump_memory, parsed_address, min(max(size, 1), 4096)
        )
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Dump memory thất bại", str(exc)) from exc


@router.get("/sessions/{session_id}/disassembly", response_model=LiveDisassemblyResponse)
async def get_live_disassembly(
    session_id: str, store: StoreDep, count: int = 40
) -> LiveDisassemblyResponse:
    """Live disassembly around the debugger's current runtime address -
    the assembly view's fallback for when the PC is outside the one module
    the static analyzer covers (see
    `DebugSession.disassemble_current`'s docstring). `count` is clamped
    server-side (1-200) regardless of what the caller passes.
    """
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    try:
        return await run_in_threadpool(session.disassemble_current, min(max(count, 1), 200))
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Disassemble thất bại", str(exc)) from exc


@router.get("/sessions/{session_id}/disassembly/at", response_model=LiveDisassemblyResponse)
async def get_live_disassembly_at(
    session_id: str, store: StoreDep, address: str, count: int = 40
) -> LiveDisassemblyResponse:
    """Same as `GET .../disassembly`, except `address` is an explicit
    *runtime* address rather than the debugger's current PC - the Ctrl+G
    "jump into a loaded DLL" leg (see `DebugSession.disassemble_at`'s
    docstring). `count` clamped the same way (1-200).
    """
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    parsed_address = try_parse_address(address)
    if parsed_address is None:
        raise _invalid_address(address)

    try:
        return await run_in_threadpool(
            session.disassemble_at, parsed_address, min(max(count, 1), 200)
        )
    except DynamicSessionError as exc:
        raise _error(409, exc.code, exc.message) from exc
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Disassemble thất bại", str(exc)) from exc


@router.get("/sessions/{session_id}/modules", response_model=list[ModuleModel])
async def get_modules(session_id: str, store: StoreDep) -> list[ModuleModel]:
    """Every module currently mapped in the debuggee - main EXE plus every
    DLL loaded since (including ones loaded well after attach) - see
    `DebugSession.list_modules`'s docstring."""
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc
    return await run_in_threadpool(session.list_modules)


@router.post("/sessions/{session_id}/step", response_model=SessionStateResponse)
async def step(session_id: str, body: StepRequest, store: StoreDep) -> SessionStateResponse:
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    try:
        await run_in_threadpool(session.step, body.mode)
    except DebugBridgeError as exc:
        raise _error(502, "DYNAMIC_CONNECT_FAILED", "Step thất bại", str(exc)) from exc
    return session.snapshot_state()


@router.post("/sessions/{session_id}/continue", response_model=SessionStateResponse)
async def continue_execution(session_id: str, store: StoreDep) -> SessionStateResponse:
    try:
        session = store.get(session_id)
    except DynamicSessionNotFound as exc:
        raise _not_found_session(session_id) from exc

    try:
        await run_in_threadpool(session.go, dynamic_settings.continue_timeout_seconds)
    except DebugBridgeError as exc:
        raise _error(504, "DYNAMIC_TIMEOUT", "Continue thất bại hoặc timeout", str(exc)) from exc
    return session.snapshot_state()


@router.delete("/sessions/{session_id}")
def disconnect_session(session_id: str, store: StoreDep) -> dict[str, bool]:
    return {"deleted": store.delete(session_id)}
