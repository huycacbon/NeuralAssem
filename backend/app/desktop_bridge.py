"""In-process bridge for the packaged desktop app - no HTTP involved.

The web deployment talks to the backend over HTTP (`app.api.analysis`,
served by FastAPI/uvicorn). The desktop build used to do the same thing
against a copy of that same server running on a loopback port. This module
replaces that: it is registered as pywebview's `js_api`
(`webview.create_window(..., js_api=DesktopApi())`), so the frontend calls
`window.pywebview.api.<method>(...)` directly - a same-process function
call, not a network request. No socket is opened for the API at all.

This is deliberately NOT a second implementation of the analysis logic: every
method below just calls the exact same `AnalysisService` the HTTP routes in
`app.api.analysis` call, so behaviour (validation, risk scoring, error codes)
is identical between the web and desktop builds - only the transport differs.

Error handling note: pywebview's JS<->Python bridge does not preserve
structured exceptions - a raised Python exception reaches JS as a bare string
message, which would lose the `{code, message, details}` envelope the
frontend's `ApiError` already knows how to parse (see
`frontend/src/services/analysisApi.ts`). So nothing here ever raises across
the bridge: every method always returns a JSON-serialisable value, either the
successful payload or an `{"error": {...}}` envelope in exactly the shape
`app.main`'s HTTP exception handlers already produce for the web deployment.
"""

from __future__ import annotations

import base64
import binascii
import io
import logging
from typing import Any

from pydantic import BaseModel

from app.analyzers.angr_analyzer import AnalysisError
from app.config import settings
from app.dynamic.config import dynamic_settings
from app.dynamic.debug_bridge.client import DebugBridgeError
from app.dynamic.models import (
    BreakpointCreateRequest,
    LocalLaunchRequest,
    RegisterWriteRequest,
    RuntimeBreakpointCreateRequest,
    StepRequest,
)
from app.dynamic.risk_gate import derive_risk_bucket
from app.dynamic.session import DynamicSessionError
from app.dynamic.session_store import (
    DynamicAnalysisNotFound,
    DynamicSessionNotFound,
    SessionStore,
)
from app.repositories import InMemoryAnalysisRepository
from app.services.analysis_service import AnalysisNotFound, AnalysisService
from app.utils.address import try_parse_address
from app.utils.security import UploadValidationError

logger = logging.getLogger(__name__)


def _dump(model: BaseModel) -> dict[str, Any]:
    """Same wire shape FastAPI produces: aliased (camelCase) JSON."""
    return model.model_dump(mode="json", by_alias=True)


def _error_envelope(code: str, message: str, details: str | None = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": None if settings.is_production else details,
        }
    }


def _not_found(analysis_id: str) -> dict[str, Any]:
    return _error_envelope(
        "ANALYSIS_NOT_FOUND", "Không tìm thấy kết quả phân tích", f"analysisId={analysis_id}"
    )


def _not_found_function(address: str) -> dict[str, Any]:
    return _error_envelope(
        "FUNCTION_NOT_FOUND", "Không tìm thấy function tại địa chỉ này", f"address={address}"
    )


class DesktopApi:
    """Registered as `js_api` on the desktop window.

    Every public method becomes callable from JS as
    `window.pywebview.api.<name>(...)`; pywebview maps positional JS
    arguments onto this method's positional parameters and marshals the
    return value back to JS as JSON.
    """

    def __init__(self) -> None:
        # Own repository/service instance - equivalent to `app.dependencies`'
        # lru_cache-wrapped singletons, just without FastAPI's DI container
        # (there is nothing to inject into here). Kept as a local so the
        # dynamic module's SessionStore below can share the exact same
        # repository the analysis service writes to (the web deployment's
        # equivalent wiring is app.dynamic.dependencies.get_session_store,
        # which does the same thing with the shared repository singleton).
        repository = InMemoryAnalysisRepository(capacity=settings.max_stored_analyses)
        self._repository = repository
        self._service = AnalysisService(repository)
        self._debug_store = SessionStore(
            repository=repository,
            capacity=dynamic_settings.max_concurrent_sessions,
            idle_timeout_seconds=dynamic_settings.session_idle_timeout_seconds,
            reaper_interval_seconds=dynamic_settings.reaper_interval_seconds,
        )

    # -- health -------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        try:
            import angr  # noqa: F401

            angr_available = True
            angr_error: str | None = None
        except Exception as exc:  # pragma: no cover - only on a broken install
            angr_available = False
            angr_error = str(exc)

        return {
            "status": "ok" if angr_available else "degraded",
            "angrAvailable": angr_available,
            "angrError": angr_error,
            "maxUploadMb": settings.max_upload_mb,
            "analysisTimeoutSeconds": settings.analysis_timeout_seconds,
            "environment": settings.environment,
        }

    # -- analysis -------------------------------------------------------------

    def analyze(self, file_base64: str, filename: str | None) -> dict[str, Any]:
        """Decode a base64-encoded file and run the full analysis.

        The renderer reads the picked `File` with `FileReader.readAsDataURL`
        and sends the base64 payload here instead of a `multipart/form-data`
        POST - same bytes, different transport. From this point on the sample
        goes through the exact same path as the web upload: a UUID temp file
        under `AnalysisService.analyze_upload` -> `file_service.received_upload`,
        deleted in a `finally` block, never executed.
        """
        try:
            raw = base64.b64decode(file_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            return _error_envelope(
                "VALIDATION_ERROR", "Dữ liệu file không hợp lệ (base64 hỏng)", str(exc)
            )

        try:
            response = self._service.analyze_upload(io.BytesIO(raw), filename)
            return _dump(response)
        except UploadValidationError as exc:
            return _error_envelope(exc.code, exc.message, exc.details)
        except AnalysisError as exc:
            return _error_envelope(exc.code, exc.message, exc.details)
        except Exception as exc:  # pragma: no cover - unexpected analyser failure
            logger.exception("Phân tích thất bại ngoài dự kiến")
            return _error_envelope(
                "ANALYSIS_FAILED", "Không thể phân tích binary", f"{type(exc).__name__}: {exc}"
            )

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        try:
            return _dump(self._service.get_analysis(analysis_id))
        except AnalysisNotFound:
            return _not_found(analysis_id)

    def list_functions(
        self,
        analysis_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
        min_risk_score: int = 0,
    ) -> dict[str, Any]:
        try:
            return _dump(
                self._service.list_functions(
                    analysis_id,
                    search=search,
                    limit=limit,
                    offset=offset,
                    min_risk_score=min_risk_score,
                )
            )
        except AnalysisNotFound:
            return _not_found(analysis_id)

    def get_function(self, analysis_id: str, address: str) -> dict[str, Any]:
        try:
            detail = self._service.get_function(analysis_id, address)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        if detail is None:
            return _not_found_function(address)
        return _dump(detail)

    def decompile_function(self, analysis_id: str, address: str) -> dict[str, Any]:
        try:
            detail = self._service.decompile_function(analysis_id, address)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        if detail is None:
            return _not_found_function(address)
        return _dump(detail)

    def get_function_cfg(self, analysis_id: str, address: str) -> dict[str, Any]:
        try:
            graph = self._service.get_function_cfg(analysis_id, address)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        if graph is None:
            return _not_found_function(address)
        return _dump(graph)

    def get_call_graph(
        self,
        analysis_id: str,
        depth: int = 2,
        max_nodes: int = 500,
        include_apis: bool = True,
    ) -> dict[str, Any]:
        try:
            return _dump(
                self._service.get_call_graph(
                    analysis_id, depth=depth, max_nodes=max_nodes, include_apis=include_apis
                )
            )
        except AnalysisNotFound:
            return _not_found(analysis_id)

    def get_api_graph(
        self,
        analysis_id: str,
        max_nodes: int = 500,
        capability: str | None = None,
    ) -> dict[str, Any]:
        try:
            return _dump(
                self._service.get_api_graph(
                    analysis_id, max_nodes=max_nodes, capability=capability
                )
            )
        except AnalysisNotFound:
            return _not_found(analysis_id)

    def get_imports(self, analysis_id: str) -> list[dict[str, Any]] | dict[str, Any]:
        try:
            imports = self._service.get_imports(analysis_id)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        return [_dump(item) for item in imports]

    def get_strings(
        self, analysis_id: str, limit: int = 500, search: str | None = None
    ) -> list[dict[str, Any]] | dict[str, Any]:
        try:
            return self._service.get_strings(analysis_id, limit=limit, search=search)
        except AnalysisNotFound:
            return _not_found(analysis_id)

    def expand(self, analysis_id: str, address: str, max_nodes: int = 60) -> dict[str, Any]:
        try:
            graph = self._service.expand(analysis_id, address, max_nodes=max_nodes)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        if graph is None:
            return _not_found_function(address)
        return _dump(graph)

    def export_markdown(self, analysis_id: str) -> dict[str, Any]:
        """Same compact Markdown report as the web deployment's `/export.md`.

        Returned as `{filename, content}` rather than an HTTP response with
        `Content-Disposition` - the frontend builds a `Blob` + object URL to
        trigger the save, which works identically with or without a server.
        """
        try:
            markdown = self._service.export_markdown(analysis_id)
        except AnalysisNotFound:
            return _not_found(analysis_id)
        return {"filename": f"analysis-{analysis_id[:8]}.md", "content": markdown}

    def delete_analysis(self, analysis_id: str) -> dict[str, Any]:
        return {"deleted": self._service.delete(analysis_id)}

    # -- dynamic analysis (Phase 1, debug client only) -----------------------
    #
    # Every method below mirrors one endpoint in `app.dynamic.api` 1:1, using
    # this instance's own `self._debug_store` (wired to the same repository
    # as `self._service` above, see `__init__`). Same never-raise convention
    # as the rest of this class: pywebview's bridge does not preserve
    # structured exceptions, so every domain error is caught here and
    # returned as `_error_envelope(...)` instead.

    def debug_risk_check(self, analysis_id: str) -> dict[str, Any]:
        record = self._repository.get(analysis_id)
        if record is None:
            return _not_found(analysis_id)
        bucket, score = derive_risk_bucket(record.summary)
        return {
            "riskBucket": bucket,
            "riskScore": score,
            "sampleName": record.file.name,
            "likelyPacked": record.summary.likely_packed,
        }

    def debug_launch_local(self, analysis_id: str, command_line: str) -> dict[str, Any]:
        """Local-launch: makes THIS process execute `command_line` directly
        on this machine - see
        `app.dynamic.debug_bridge.client.DebugBridge.create_and_attach_local`'s
        docstring for the full rationale. The frontend is expected to have
        already shown its own local-launch-specific warning (every time, not
        once-per-session) before calling this."""
        try:
            LocalLaunchRequest(analysisId=analysis_id, commandLine=command_line)
        except Exception as exc:
            return _error_envelope("VALIDATION_ERROR", "Tham số local-launch không hợp lệ", str(exc))

        try:
            session = self._debug_store.create_local(
                analysis_id, command_line, dynamic_settings.connect_timeout_seconds
            )
        except DynamicAnalysisNotFound:
            return _not_found(analysis_id)
        except DebugBridgeError as exc:
            return _error_envelope(
                "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
            )
        except Exception as exc:  # pragma: no cover - unexpected bridge failure
            logger.exception("Local-launch debug session thất bại ngoài dự kiến")
            return _error_envelope(
                "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
            )

        return _dump(session.snapshot_state())

    def debug_launch_local_upload(
        self, analysis_id: str, file_base64: str, filename: str | None
    ) -> dict[str, Any]:
        """Local-launch from the exact file the frontend still holds in
        memory from the original upload - decoded the same way `analyze()`
        above decodes its own base64 payload, then staged to a *new*,
        dynamic/-owned temp file (`app.dynamic.local_upload.stage_upload`)
        and executed. See `POST /dynamic/sessions/local/upload`'s docstring
        (`app/dynamic/api.py`) for the same rationale - this is the desktop
        transport's equivalent of that route."""
        try:
            raw = base64.b64decode(file_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            return _error_envelope(
                "VALIDATION_ERROR", "Dữ liệu file không hợp lệ (base64 hỏng)", str(exc)
            )

        try:
            session = self._debug_store.create_local_from_upload(
                analysis_id,
                io.BytesIO(raw),
                filename,
                dynamic_settings.connect_timeout_seconds,
                settings.max_upload_bytes,
            )
        except DynamicAnalysisNotFound:
            return _not_found(analysis_id)
        except UploadValidationError as exc:
            return _error_envelope(exc.code, exc.message, exc.details)
        except DebugBridgeError as exc:
            return _error_envelope(
                "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
            )
        except Exception as exc:  # pragma: no cover - unexpected bridge failure
            logger.exception("Local-launch-from-upload debug session thất bại ngoài dự kiến")
            return _error_envelope(
                "DYNAMIC_CONNECT_FAILED", "Không chạy/attach được tiến trình cục bộ", str(exc)
            )

        return _dump(session.snapshot_state())

    def debug_get_state(self, session_id: str) -> dict[str, Any]:
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)
        return _dump(session.snapshot_state())

    def debug_set_breakpoint(self, session_id: str, static_address: str) -> dict[str, Any]:
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        BreakpointCreateRequest(staticAddress=static_address)  # validates shape only
        address = try_parse_address(static_address)
        if address is None:
            return _error_envelope(
                "DYNAMIC_INVALID_ADDRESS", "Địa chỉ không hợp lệ", f"address={static_address}"
            )

        try:
            return _dump(session.set_breakpoint(address))
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Không đặt được breakpoint", str(exc))

    def debug_set_runtime_breakpoint(self, session_id: str, runtime_address: str) -> dict[str, Any]:
        """Same as `debug_set_breakpoint` above, except `runtime_address` is
        used as-is - no `address_map` rebase. For addresses outside the
        sample's own module (system DLLs like ntdll) - see
        `DebugSession.set_runtime_breakpoint`'s docstring."""
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        RuntimeBreakpointCreateRequest(runtimeAddress=runtime_address)  # validates shape only
        address = try_parse_address(runtime_address)
        if address is None:
            return _error_envelope(
                "DYNAMIC_INVALID_ADDRESS", "Địa chỉ không hợp lệ", f"address={runtime_address}"
            )

        try:
            return _dump(session.set_runtime_breakpoint(address))
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Không đặt được breakpoint", str(exc))

    def debug_remove_breakpoint(self, session_id: str, breakpoint_id: int) -> dict[str, Any]:
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        try:
            session.clear_breakpoint(breakpoint_id)
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        return {"deleted": True}

    def debug_step(self, session_id: str, mode: str) -> dict[str, Any]:
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        StepRequest(mode=mode)  # validates "into"/"over" only
        try:
            session.step(mode)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Step thất bại", str(exc))
        return _dump(session.snapshot_state())

    def debug_set_register(self, session_id: str, name: str, value: str) -> dict[str, Any]:
        """Mirrors `POST /dynamic/sessions/{id}/registers/{name}` - see
        `app.dynamic.session.DebugSession.set_register`'s docstring."""
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        RegisterWriteRequest(value=value)  # validates shape only
        parsed = try_parse_address(value)
        if parsed is None:
            return _error_envelope(
                "DYNAMIC_INVALID_ADDRESS", "Giá trị không hợp lệ", f"value={value}"
            )

        try:
            session.set_register(name, parsed)
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Không ghi được register", str(exc))
        return _dump(session.snapshot_state())

    def debug_dump_memory(self, session_id: str, address: str, size: int = 256) -> dict[str, Any]:
        """Mirrors `GET /dynamic/sessions/{id}/memory` - see
        `app.dynamic.session.DebugSession.dump_memory`'s docstring."""
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        parsed_address = try_parse_address(address)
        if parsed_address is None:
            return _error_envelope(
                "DYNAMIC_INVALID_ADDRESS", "Địa chỉ không hợp lệ", f"address={address}"
            )

        try:
            return _dump(session.dump_memory(parsed_address, min(max(size, 1), 4096)))
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Dump memory thất bại", str(exc))

    def debug_disassemble(self, session_id: str, count: int = 40) -> dict[str, Any]:
        """Mirrors `GET /dynamic/sessions/{id}/disassembly` - see
        `app.dynamic.session.DebugSession.disassemble_current`'s docstring
        for why this exists (assembly-view fallback outside the analysed
        module)."""
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        try:
            return _dump(session.disassemble_current(min(max(count, 1), 200)))
        except DynamicSessionError as exc:
            return _error_envelope(exc.code, exc.message)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_CONNECT_FAILED", "Disassemble thất bại", str(exc))

    def debug_continue(self, session_id: str) -> dict[str, Any]:
        try:
            session = self._debug_store.get(session_id)
        except DynamicSessionNotFound:
            return _not_found_session(session_id)

        try:
            session.go(dynamic_settings.continue_timeout_seconds)
        except DebugBridgeError as exc:
            return _error_envelope("DYNAMIC_TIMEOUT", "Continue thất bại hoặc timeout", str(exc))
        return _dump(session.snapshot_state())

    def debug_disconnect(self, session_id: str) -> dict[str, Any]:
        return {"deleted": self._debug_store.delete(session_id)}


def _not_found_session(session_id: str) -> dict[str, Any]:
    return _error_envelope(
        "DYNAMIC_SESSION_NOT_FOUND",
        "Phiên debug không tồn tại (chưa kết nối hoặc đã bị ngắt do idle timeout)",
        f"sessionId={session_id}",
    )
