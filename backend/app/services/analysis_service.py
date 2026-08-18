"""Orchestrates one analysis run and answers follow-up queries about it."""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import BinaryIO

from app.analyzers.angr_analyzer import (
    AnalysisArtifacts,
    AnalysisError,
    AnalyzedFunction,
    analyze_binary,
    decompile_one_function,
)
from app.analyzers.call_graph_builder import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_NODES,
    build_api_graph,
    build_call_graph,
    expand_node,
)
from app.analyzers.cfg_builder import build_function_cfg
from app.config import settings
from app.models.analysis import (
    AnalysisRecord,
    AnalysisResponse,
    AnalysisSummary,
    FileInfo,
    FunctionDetail,
    FunctionListResponse,
    FunctionSummary,
    ImportedApi,
    ReferencedString,
)
from app.models.graph import Graph
from app.repositories.base import AnalysisRepository
from app.services.export_service import (
    build_full_markdown_export,
    build_function_markdown_export,
    build_markdown_export,
)
from app.services.file_service import received_upload
from app.utils.address import format_address, function_node_id, try_parse_address

logger = logging.getLogger(__name__)

#: angr offers no cancellation hook, so the run happens on a worker thread that
#: we stop waiting on after the timeout. The thread is daemonic and finishes on
#: its own; the request is not left hanging.
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="angr")


class AnalysisNotFound(LookupError):
    pass


def _to_summary(function: AnalyzedFunction, entry_point: int) -> FunctionSummary:
    return FunctionSummary(
        address=format_address(function.address),
        name=function.display_name,
        size=function.size,
        block_count=function.block_count,
        caller_count=len(function.callers),
        callee_count=len(function.callees),
        is_imported=function.is_imported,
        is_plt=function.is_plt,
        is_entry_point=function.address == entry_point,
        is_syscall=function.is_syscall,
        has_unresolved_calls=function.has_unresolved_calls,
        risk_score=function.risk_score,
        risk_reasons=function.risk_reasons,
        imported_apis=list(function.api_names),
        string_count=len(function.strings),
        node_id=function_node_id(function.address),
    )


def _to_detail(function: AnalyzedFunction, entry_point: int) -> FunctionDetail:
    summary = _to_summary(function, entry_point)
    return FunctionDetail(
        **summary.model_dump(),
        strings=[
            ReferencedString(
                address=format_address(item.address) if item.address is not None else "",
                value=item.value,
                length=item.length,
            )
            for item in function.strings
        ],
        block_addresses=[format_address(address) for address in sorted(function.blocks)],
        pseudocode=function.pseudocode,
        pseudocode_status=function.pseudocode_status,
        pseudocode_note=function.pseudocode_note,
        pseudocode_address_lines=(
            {format_address(addr): line for addr, line in function.pseudocode_address_lines.items()}
            if function.pseudocode_address_lines
            else None
        ),
    )


def _build_record(
    analysis_id: str,
    display_name: str,
    sha256: str,
    size: int,
    artifacts: AnalysisArtifacts,
) -> AnalysisRecord:
    entry_point = artifacts.entry_point

    functions = {
        format_address(address): _to_detail(function, entry_point)
        for address, function in artifacts.functions.items()
    }

    top_risk = sorted(
        (function for function in artifacts.functions.values() if function.risk_score > 0),
        key=lambda function: -function.risk_score,
    )[:10]

    imports = [
        ImportedApi(
            module=entry.module,
            name=entry.name,
            address=format_address(entry.iat_address) if entry.iat_address else None,
            node_id=entry.node_id,
            capability=entry.capability,
            reference_count=artifacts.api_references.get(entry.node_id, 0),
            callers=[
                format_address(caller)
                for caller in sorted(artifacts.api_callers.get(entry.node_id, set()))
            ],
        )
        for entry in artifacts.imports
    ]

    summary = AnalysisSummary(
        function_count=len(artifacts.functions),
        basic_block_count=artifacts.basic_block_count,
        import_count=len(artifacts.imports),
        string_count=len(artifacts.strings),
        highest_risk_functions=[_to_summary(item, entry_point) for item in top_risk],
        warnings=artifacts.warnings,
        analysis_duration_seconds=artifacts.duration_seconds,
        likely_packed=artifacts.likely_packed,
    )

    return AnalysisRecord(
        analysis_id=analysis_id,
        file=FileInfo(
            name=display_name,
            sha256=sha256,
            size=size,
            architecture=artifacts.architecture,
            entry_point=format_address(entry_point),
            format=artifacts.binary_format,
            bits=artifacts.bits,
            image_base=format_address(artifacts.image_base),
        ),
        summary=summary,
        call_graph=build_call_graph(
            artifacts,
            depth=settings.default_graph_depth,
            max_nodes=settings.default_max_nodes,
        ),
        api_graph=build_api_graph(artifacts, max_nodes=settings.default_max_nodes),
        functions=functions,
        imports=imports,
        raw={"artifacts": artifacts},
    )


class AnalysisService:
    def __init__(self, repository: AnalysisRepository) -> None:
        self._repository = repository

    # -- analysis ---------------------------------------------------------

    def analyze_upload(self, stream: BinaryIO, filename: str | None) -> AnalysisResponse:
        """Validate, analyse, store, and return the first response.

        The uploaded sample lives only inside the ``received_upload`` context;
        it is deleted before this method returns, on every path.
        """
        with received_upload(stream, filename) as upload:
            artifacts = self._run_with_timeout(upload.path, upload.read_bytes())

            record = _build_record(
                analysis_id=uuid.uuid4().hex,
                display_name=upload.display_name,
                sha256=upload.sha256,
                size=upload.size,
                artifacts=artifacts,
            )

        self._repository.save(record)
        logger.info(
            "Lưu analysis %s (%d function)",
            record.analysis_id,
            record.summary.function_count,
        )

        return AnalysisResponse(
            analysis_id=record.analysis_id,
            file=record.file,
            summary=record.summary,
            call_graph=record.call_graph,
        )

    def _run_with_timeout(self, path: Path, raw_data: bytes) -> AnalysisArtifacts:
        future = _executor.submit(analyze_binary, path, raw_data)
        try:
            return future.result(timeout=settings.analysis_timeout_seconds)
        except FutureTimeout as exc:
            future.cancel()
            raise AnalysisError(
                code="ANALYSIS_TIMEOUT",
                message=(
                    f"Phân tích vượt quá {settings.analysis_timeout_seconds}s và đã bị hủy"
                ),
                details="Binary có thể quá lớn hoặc bị obfuscate nặng",
            ) from exc

    # -- queries ----------------------------------------------------------

    def _require(self, analysis_id: str) -> AnalysisRecord:
        record = self._repository.get(analysis_id)
        if record is None:
            raise AnalysisNotFound(analysis_id)
        return record

    def _artifacts(self, record: AnalysisRecord) -> AnalysisArtifacts:
        return record.raw["artifacts"]

    def get_analysis(self, analysis_id: str) -> AnalysisResponse:
        record = self._require(analysis_id)
        return AnalysisResponse(
            analysis_id=record.analysis_id,
            file=record.file,
            summary=record.summary,
            call_graph=record.call_graph,
        )

    def list_functions(
        self,
        analysis_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
        min_risk_score: int = 0,
    ) -> FunctionListResponse:
        record = self._require(analysis_id)

        items = list(record.functions.values())

        if min_risk_score > 0:
            items = [item for item in items if item.risk_score >= min_risk_score]

        if search:
            needle = search.strip().lower()
            # Address search accepts "401000" as well as "0x401000".
            wanted_address = try_parse_address(needle)
            def matches(item: FunctionSummary) -> bool:
                if needle in item.name.lower() or needle in item.address.lower():
                    return True
                if wanted_address is not None and item.address == format_address(wanted_address):
                    return True
                return any(needle in api.lower() for api in item.imported_apis)

            items = [item for item in items if matches(item)]

        # Most interesting first: entry point, then risk, then connectivity.
        items.sort(
            key=lambda item: (
                0 if item.is_entry_point else 1,
                -item.risk_score,
                -(item.caller_count + item.callee_count),
                item.address,
            )
        )

        total = len(items)
        offset = max(0, offset)
        limit = max(1, min(limit, 1000))
        window = items[offset : offset + limit]

        return FunctionListResponse(
            total=total,
            limit=limit,
            offset=offset,
            items=[FunctionSummary(**item.model_dump(include=set(FunctionSummary.model_fields)))
                   for item in window],
        )

    def get_function(self, analysis_id: str, address: str) -> FunctionDetail | None:
        record = self._require(analysis_id)
        parsed = try_parse_address(address)
        if parsed is None:
            return None
        return record.functions.get(format_address(parsed))

    def decompile_function(self, analysis_id: str, address: str) -> FunctionDetail | None:
        """Decompile one function on demand and return its refreshed detail.

        Used for functions the eager, bounded pass at analysis time skipped
        (see `pseudocode_status`). Reuses the analysis's still-alive angr
        project - the uploaded sample's temp file is long gone by now, but
        that was never needed for this (see `AnalysisArtifacts.live_project`).
        If pseudocode is already available, this is a no-op that just returns
        the cached detail - a second click never re-runs the decompiler.
        """
        record = self._require(analysis_id)
        parsed = try_parse_address(address)
        if parsed is None:
            return None

        artifacts = self._artifacts(record)
        function = artifacts.functions.get(parsed)
        if function is None:
            return None

        if function.pseudocode_status != "available":
            if artifacts.live_project is None or artifacts.live_cfg_model is None:
                # Should not happen in normal operation - only if a future
                # change strips the live project from a cached analysis.
                function.pseudocode_status = "failed"
                function.pseudocode_note = (
                    "Không thể decompile: dữ liệu phân tích gốc không còn khả dụng."
                )
            else:
                decompile_one_function(artifacts.live_project, artifacts.live_cfg_model, function)

        detail = _to_detail(function, artifacts.entry_point)
        record.functions[format_address(parsed)] = detail
        return detail

    def decompile_all_functions(self, analysis_id: str) -> dict[str, int]:
        """Decompile every function that still lacks pseudocode, one at a
        time, best-effort - a function the decompiler chokes on is skipped
        (never raises, see `decompile_one_function`) and the rest still run.

        Deliberately has **no** count/time budget unlike the eager pass at
        analysis time (`MAX_DECOMPILE_FUNCTIONS`/`DECOMPILE_TIME_BUDGET_SECONDS`
        in `angr_analyzer.py`) - this exists specifically for "decompile
        everything", so a caller invoking it has already accepted that a
        binary with many non-trivial functions can take minutes. Also
        deliberately does **not** run functions off-thread with a per-function
        timeout: angr's `Decompiler` is not safe to call concurrently against
        the same shared `live_project`/`live_cfg_model`, so there is no way to
        "give up and move on" without risking two decompile calls touching
        that shared state at once - a stuck function stays stuck for the
        whole call, same tradeoff the rest of this module already accepts for
        the initial CFGFast pass (see README's "Timeout không thực sự hủy
        angr" limitation).

        Skips functions already marked `not_applicable` (import thunks,
        simprocedures, syscalls, or anything with zero blocks - the eager
        pass already determined there is nothing to decompile) since nothing
        would change by retrying those.
        """
        record = self._require(analysis_id)
        artifacts = self._artifacts(record)

        total = len(artifacts.functions)
        already_available = 0
        decompiled = 0
        failed = 0
        skipped_not_applicable = 0

        for function in artifacts.functions.values():
            if function.pseudocode_status == "available":
                already_available += 1
                continue
            if function.pseudocode_status == "not_applicable":
                skipped_not_applicable += 1
                continue

            if artifacts.live_project is None or artifacts.live_cfg_model is None:
                # Should not happen in normal operation - only if a future
                # change strips the live project from a cached analysis.
                function.pseudocode_status = "failed"
                function.pseudocode_note = (
                    "Không thể decompile: dữ liệu phân tích gốc không còn khả dụng."
                )
            else:
                decompile_one_function(artifacts.live_project, artifacts.live_cfg_model, function)

            if function.pseudocode_status == "available":
                decompiled += 1
            else:
                failed += 1

            # Refresh the cached `FunctionDetail` immediately so a reader
            # (single-function GET, CFG view, or the export built right after
            # this call returns) sees the freshly computed pseudocode without
            # needing a separate re-decompile.
            record.functions[format_address(function.address)] = _to_detail(
                function, artifacts.entry_point
            )

        logger.info(
            "Decompile-all analysis %s: %d/%d function(s) đã có sẵn, %d decompile mới, "
            "%d thất bại, %d bỏ qua (không áp dụng được)",
            analysis_id,
            already_available,
            total,
            decompiled,
            failed,
            skipped_not_applicable,
        )
        return {
            "total": total,
            "alreadyAvailable": already_available,
            "decompiled": decompiled,
            "failed": failed,
            "skippedNotApplicable": skipped_not_applicable,
        }

    def get_function_cfg(self, analysis_id: str, address: str) -> Graph | None:
        """Build (and cache) the CFG for one function.

        Built on demand so the initial analysis response never carries
        instruction listings for the whole binary.
        """
        record = self._require(analysis_id)
        parsed = try_parse_address(address)
        if parsed is None:
            return None

        key = format_address(parsed)
        cached = record.cfgs.get(key)
        if cached is not None:
            return cached

        graph = build_function_cfg(self._artifacts(record), parsed)
        if graph is not None:
            record.cfgs[key] = graph
        return graph

    def get_call_graph(
        self,
        analysis_id: str,
        depth: int = DEFAULT_DEPTH,
        max_nodes: int = DEFAULT_MAX_NODES,
        include_apis: bool = True,
    ) -> Graph:
        record = self._require(analysis_id)
        return build_call_graph(
            self._artifacts(record),
            depth=depth,
            max_nodes=max_nodes,
            include_apis=include_apis,
        )

    def get_api_graph(
        self,
        analysis_id: str,
        max_nodes: int = DEFAULT_MAX_NODES,
        capability: str | None = None,
    ) -> Graph:
        record = self._require(analysis_id)
        return build_api_graph(
            self._artifacts(record),
            max_nodes=max_nodes,
            capability=capability,
        )

    def get_imports(self, analysis_id: str) -> list[ImportedApi]:
        return self._require(analysis_id).imports

    def export_markdown(self, analysis_id: str) -> str:
        """Compact Markdown report for handing this analysis to an LLM or a
        colleague - see `export_service` for the format's design rationale."""
        record = self._require(analysis_id)
        return build_markdown_export(record)

    def export_markdown_full(self, analysis_id: str) -> str:
        """Same report, but the Function Detail section covers every function
        that currently has pseudocode - not a risk-curated top-25. Does not
        itself decompile anything; call `decompile_all_functions` first if the
        goal is "every function that *can* be decompiled, is" before export -
        see `export_service.build_full_markdown_export`'s docstring."""
        record = self._require(analysis_id)
        return build_full_markdown_export(record)

    def export_function_markdown(self, analysis_id: str, address: str) -> str | None:
        """Compact Markdown for exactly one function - full disassembly and
        pseudocode (if available), not risk-filtered like the whole-analysis
        exports. `None` if the function doesn't exist (mirrors
        `get_function`/`decompile_function`'s not-found convention). Does not
        decompile anything itself - a function without pseudocode yet just
        reports why, same as the other export variants."""
        record = self._require(analysis_id)
        parsed = try_parse_address(address)
        if parsed is None:
            return None
        detail = record.functions.get(format_address(parsed))
        if detail is None:
            return None
        cfg = self.get_function_cfg(analysis_id, address)
        return build_function_markdown_export(record, detail, cfg)

    def expand(self, analysis_id: str, address: str, max_nodes: int = 60) -> Graph | None:
        record = self._require(analysis_id)
        parsed = try_parse_address(address)
        if parsed is None:
            return None
        return expand_node(self._artifacts(record), parsed, max_nodes=max_nodes)

    def get_strings(self, analysis_id: str, limit: int = 500, search: str | None = None):
        record = self._require(analysis_id)
        artifacts = self._artifacts(record)
        values = artifacts.strings
        if search:
            needle = search.lower()
            values = [item for item in values if needle in item.value.lower()]
        return [item.to_dict() for item in values[:limit]]

    def delete(self, analysis_id: str) -> bool:
        return self._repository.delete(analysis_id)
