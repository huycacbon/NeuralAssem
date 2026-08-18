"""Response models for the analysis API and the in-memory analysis record."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models.graph import CamelModel, Graph


class FileInfo(CamelModel):
    name: str
    sha256: str
    size: int
    architecture: str
    entry_point: str
    format: str = "PE"
    bits: int = 32
    #: The PE's own preferred `ImageBase` (Optional Header) - every "static"
    #: address shown elsewhere in the app (function list, graphs, CFG,
    #: `entryPoint` above) is already expressed in this coordinate space, so
    #: this is what a user needs to compute a `module+RVA` expression
    #: (`address - imageBase`) for pasting into x64dbg/WinDbg's own "go to"
    #: box - those tools resolve `module+RVA` against *their own* attach's
    #: real (ASLR-randomised, and therefore almost never numerically equal
    #: to this app's own debug session) load base, so the raw static address
    #: alone is not portable between two independently-launched debuggers,
    #: only the RVA is.
    image_base: str = "0x0"


class ImportedApi(CamelModel):
    module: str
    name: str
    address: str | None = None
    node_id: str
    capability: str = "other"
    reference_count: int = 0
    callers: list[str] = Field(default_factory=list)


class ReferencedString(CamelModel):
    address: str
    value: str
    length: int


class FunctionSummary(CamelModel):
    """One row of the function list panel. Deliberately instruction-free:
    disassembly is only fetched when the user opens a specific function."""

    address: str
    name: str
    size: int | None = None
    block_count: int = 0
    caller_count: int = 0
    callee_count: int = 0
    is_imported: bool = False
    is_plt: bool = False
    is_entry_point: bool = False
    is_syscall: bool = False
    has_unresolved_calls: bool = False
    risk_score: int = 0
    risk_reasons: list[str] = Field(default_factory=list)
    imported_apis: list[str] = Field(default_factory=list)
    string_count: int = 0
    node_id: str


class FunctionDetail(FunctionSummary):
    strings: list[ReferencedString] = Field(default_factory=list)
    block_addresses: list[str] = Field(default_factory=list)
    #: Best-effort C-like pseudocode from angr's Decompiler (heuristic, not
    #: guaranteed correct). Only a bounded, prioritised subset of functions
    #: gets attempted - see `pseudocode_status` for why one might be missing.
    pseudocode: str | None = None
    pseudocode_status: str = "not_attempted"
    pseudocode_note: str | None = None
    #: Instruction address (hex string, e.g. "0x401000") -> 1-indexed line
    #: number in `pseudocode` - lets the UI sync a disassembly row with the
    #: pseudocode line it decompiled into (IDA/x64dbg-style). `None` when
    #: pseudocode isn't available, or when it is but the map itself could not
    #: be built (best-effort on top of an already best-effort decompile).
    pseudocode_address_lines: dict[str, int] | None = None


class FunctionListResponse(CamelModel):
    total: int
    limit: int
    offset: int
    items: list[FunctionSummary] = Field(default_factory=list)


class AnalysisSummary(CamelModel):
    function_count: int = 0
    basic_block_count: int = 0
    import_count: int = 0
    string_count: int = 0
    highest_risk_functions: list[FunctionSummary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    analysis_duration_seconds: float = 0.0
    likely_packed: bool = False


class AnalysisResponse(CamelModel):
    analysis_id: str
    file: FileInfo
    summary: AnalysisSummary
    call_graph: Graph


class ErrorDetail(CamelModel):
    code: str
    message: str
    details: str | None = None


class ErrorResponse(BaseModel):
    """Structured error envelope: ``{"error": {...}}``.

    ``details`` is suppressed in production mode by ``app.main`` so stack traces
    never reach the browser.
    """

    error: ErrorDetail


class AnalysisRecord(BaseModel):
    """Everything the API needs to answer follow-up queries for one upload.

    Held in memory (see ``repositories.AnalysisRepository``). The uploaded sample
    itself is NOT part of this record - it is deleted as soon as analysis ends.
    ``cfgs`` is populated lazily, one function at a time, when the user opens it.
    """

    model_config = {"arbitrary_types_allowed": True}

    analysis_id: str
    file: FileInfo
    summary: AnalysisSummary
    call_graph: Graph
    api_graph: Graph
    functions: dict[str, FunctionDetail] = Field(default_factory=dict)
    imports: list[ImportedApi] = Field(default_factory=list)
    cfgs: dict[str, Graph] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
