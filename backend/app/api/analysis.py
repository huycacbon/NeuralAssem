"""Analysis REST endpoints."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from starlette.concurrency import run_in_threadpool

from app.analyzers.angr_analyzer import AnalysisError
from app.analyzers.call_graph_builder import MAX_DEPTH, MIN_DEPTH
from app.config import settings
from app.dependencies import get_analysis_service
from app.models.analysis import (
    AnalysisResponse,
    FunctionDetail,
    FunctionListResponse,
    ImportedApi,
)
from app.models.graph import Graph
from app.services.analysis_service import AnalysisNotFound, AnalysisService
from app.utils.security import UploadValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analysis", tags=["analysis"])

ServiceDep = Annotated[AnalysisService, Depends(get_analysis_service)]


def _error(status_code: int, code: str, message: str, details: str | None = None):
    """Raise an HTTPException carrying the structured error envelope.

    ``details`` is dropped in production so internals never reach the browser.
    """
    payload = {
        "error": {
            "code": code,
            "message": message,
            "details": None if settings.is_production else details,
        }
    }
    return HTTPException(status_code=status_code, detail=payload)


def _not_found(analysis_id: str) -> HTTPException:
    return _error(
        404,
        "ANALYSIS_NOT_FOUND",
        "Không tìm thấy kết quả phân tích",
        f"analysisId={analysis_id}",
    )


@router.post("", response_model=AnalysisResponse, response_model_by_alias=True)
@router.post("/", response_model=AnalysisResponse, include_in_schema=False)
async def create_analysis(
    service: ServiceDep,
    file: Annotated[UploadFile, File(description="PE file (.exe hoặc .dll)")],
) -> AnalysisResponse:
    """Upload a PE file and run the full static analysis.

    The sample is written to a UUID-named temp file, analysed as data, and
    deleted before this handler returns. It is never executed.
    """
    try:
        # ``analyze_upload`` blocks synchronously for the whole analysis
        # (it waits on a Future from its own internal thread pool to enforce
        # the timeout - see analysis_service._run_with_timeout). Called
        # directly from an `async def` handler, that would freeze uvicorn's
        # single event loop for the entire run (many seconds to a minute+),
        # starving every other request on the connection - including, in the
        # packaged desktop app, the same window's own follow-up calls, which
        # can show up as a spurious "cannot connect to backend". Running it
        # via `run_in_threadpool` keeps the event loop free the whole time.
        # ``file.file`` is a SpooledTemporaryFile; the service streams from it
        # with a hard size cap rather than reading the whole body into memory.
        return await run_in_threadpool(service.analyze_upload, file.file, file.filename)
    except UploadValidationError as exc:
        raise _error(400, exc.code, exc.message, exc.details) from exc
    except AnalysisError as exc:
        status = 504 if exc.code == "ANALYSIS_TIMEOUT" else 422
        raise _error(status, exc.code, exc.message, exc.details) from exc
    except Exception as exc:  # pragma: no cover - unexpected analyser failure
        logger.exception("Phân tích thất bại ngoài dự kiến")
        raise _error(
            500,
            "ANALYSIS_FAILED",
            "Không thể phân tích binary",
            f"{type(exc).__name__}: {exc}",
        ) from exc
    finally:
        await file.close()


@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(analysis_id: str, service: ServiceDep) -> AnalysisResponse:
    try:
        return service.get_analysis(analysis_id)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/functions", response_model=FunctionListResponse)
def list_functions(
    analysis_id: str,
    service: ServiceDep,
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    min_risk_score: int = Query(default=0, ge=0, alias="minRiskScore"),
) -> FunctionListResponse:
    try:
        return service.list_functions(
            analysis_id,
            search=search,
            limit=limit,
            offset=offset,
            min_risk_score=min_risk_score,
        )
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/functions/{function_address}", response_model=FunctionDetail)
def get_function(
    analysis_id: str,
    function_address: str,
    service: ServiceDep,
) -> FunctionDetail:
    try:
        detail = service.get_function(analysis_id, function_address)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    if detail is None:
        raise _error(
            404,
            "FUNCTION_NOT_FOUND",
            "Không tìm thấy function tại địa chỉ này",
            f"address={function_address}",
        )
    return detail


@router.post(
    "/{analysis_id}/functions/{function_address}/decompile",
    response_model=FunctionDetail,
)
def decompile_function(
    analysis_id: str,
    function_address: str,
    service: ServiceDep,
) -> FunctionDetail:
    """Decompile one function on demand (best-effort, angr's own decompiler).

    Only meaningfully does work the first time for a given function: if
    pseudocode is already available (from the eager pass or an earlier call
    here), this just returns the cached result without re-running anything.
    """
    try:
        detail = service.decompile_function(analysis_id, function_address)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    if detail is None:
        raise _error(
            404,
            "FUNCTION_NOT_FOUND",
            "Không tìm thấy function tại địa chỉ này",
            f"address={function_address}",
        )
    return detail


@router.post("/{analysis_id}/decompile-all")
def decompile_all_functions(analysis_id: str, service: ServiceDep) -> dict[str, int]:
    """Decompile every function that still lacks pseudocode, best-effort.

    No count/time budget unlike the eager pass at analysis time or the
    30/45s-ish window that pass allows itself - a binary with many
    non-trivial functions can genuinely take minutes here. See
    `AnalysisService.decompile_all_functions`'s docstring for the full
    rationale (including why this can't safely time out mid-function and
    move on). Meant to be called right before `export-full.md` so that
    export's Function Detail section covers as much of the binary as
    possible.
    """
    try:
        return service.decompile_all_functions(analysis_id)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/functions/{function_address}/cfg", response_model=Graph)
def get_function_cfg(
    analysis_id: str,
    function_address: str,
    service: ServiceDep,
) -> Graph:
    """Control-flow graph for one function, built lazily on first request."""
    try:
        graph = service.get_function_cfg(analysis_id, function_address)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    if graph is None:
        raise _error(
            404,
            "FUNCTION_NOT_FOUND",
            "Không tìm thấy function tại địa chỉ này",
            f"address={function_address}",
        )
    return graph


@router.get("/{analysis_id}/functions/{function_address}/export.md")
def export_function_markdown(
    analysis_id: str, function_address: str, service: ServiceDep
) -> Response:
    """Compact Markdown for exactly one function - full disassembly and
    pseudocode (if available), not risk-filtered like `/export.md` or
    `/export-full.md`. Does not decompile anything itself - see
    `app.services.export_service.build_function_markdown_export`.
    """
    try:
        markdown = service.export_function_markdown(analysis_id, function_address)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    if markdown is None:
        raise _error(
            404,
            "FUNCTION_NOT_FOUND",
            "Không tìm thấy function tại địa chỉ này",
            f"address={function_address}",
        )

    filename = f"function-{function_address.replace('0x', '')}.md"
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{analysis_id}/call-graph", response_model=Graph)
def get_call_graph(
    analysis_id: str,
    service: ServiceDep,
    depth: int = Query(default=settings.default_graph_depth, ge=MIN_DEPTH, le=MAX_DEPTH),
    max_nodes: int = Query(
        default=settings.default_max_nodes, ge=10, le=5000, alias="maxNodes"
    ),
    include_apis: bool = Query(default=True, alias="includeApis"),
) -> Graph:
    try:
        return service.get_call_graph(
            analysis_id, depth=depth, max_nodes=max_nodes, include_apis=include_apis
        )
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/api-graph", response_model=Graph)
def get_api_graph(
    analysis_id: str,
    service: ServiceDep,
    max_nodes: int = Query(
        default=settings.default_max_nodes, ge=10, le=5000, alias="maxNodes"
    ),
    capability: str | None = Query(default=None, max_length=64),
) -> Graph:
    """``Function -> Imported API`` graph. One node per API, regardless of callers."""
    try:
        return service.get_api_graph(analysis_id, max_nodes=max_nodes, capability=capability)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/imports", response_model=list[ImportedApi])
def get_imports(analysis_id: str, service: ServiceDep) -> list[ImportedApi]:
    try:
        return service.get_imports(analysis_id)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/export.md")
def export_markdown(analysis_id: str, service: ServiceDep) -> Response:
    """Compact Markdown report of this analysis - built for pasting into an
    LLM chat or handing to a colleague, not a full raw-data dump.

    Tables + fenced code blocks instead of nested JSON, and only functions
    that matter for triage (entry point, non-zero risk, already-decompiled)
    get full write-ups; everything else is a one-line row. See
    `app.services.export_service` for the exact rules.
    """
    try:
        markdown = service.export_markdown(analysis_id)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    filename = f"analysis-{analysis_id[:8]}.md"
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{analysis_id}/export-full.md")
def export_markdown_full(analysis_id: str, service: ServiceDep) -> Response:
    """Same report as `/export.md`, except the Function Detail section covers
    every function that currently has pseudocode, not a risk-curated top-25 -
    the "export everything" counterpart. Does not decompile anything itself;
    call `POST .../decompile-all` first to fill in as much pseudocode as
    possible before exporting. Can be a genuinely large file for a binary
    with hundreds of non-trivial functions - see `export_service` for the
    rationale (this is deliberately not the token-efficient default meant
    for pasting into an LLM chat - that one is `/export.md`).
    """
    try:
        markdown = service.export_markdown_full(analysis_id)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    filename = f"analysis-{analysis_id[:8]}-full.md"
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{analysis_id}/strings")
def get_strings(
    analysis_id: str,
    service: ServiceDep,
    limit: int = Query(default=500, ge=1, le=5000),
    search: str | None = Query(default=None, max_length=200),
) -> list[dict[str, Any]]:
    try:
        return service.get_strings(analysis_id, limit=limit, search=search)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc


@router.get("/{analysis_id}/expand/{function_address}", response_model=Graph)
def expand(
    analysis_id: str,
    function_address: str,
    service: ServiceDep,
    max_nodes: int = Query(default=60, ge=2, le=500, alias="maxNodes"),
) -> Graph:
    """One-hop neighbourhood, used by the frontend's node Expand action."""
    try:
        graph = service.expand(analysis_id, function_address, max_nodes=max_nodes)
    except AnalysisNotFound as exc:
        raise _not_found(analysis_id) from exc

    if graph is None:
        raise _error(
            404,
            "FUNCTION_NOT_FOUND",
            "Không tìm thấy function tại địa chỉ này",
            f"address={function_address}",
        )
    return graph


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: str, service: ServiceDep) -> dict[str, bool]:
    return {"deleted": service.delete(analysis_id)}
