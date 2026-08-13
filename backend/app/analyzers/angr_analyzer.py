"""angr driver: load a PE as data, recover the CFG, and flatten it to plain data.

Design note - why everything is extracted eagerly
-------------------------------------------------
The uploaded sample must be deleted as soon as analysis finishes, and an
``angr.Project`` keeps the file mapped for lazy disassembly. So instead of
keeping the project alive to serve CFG requests later, this module extracts
*everything it will ever need* - functions, blocks, instructions, call edges,
strings - into ordinary dataclasses while the project is alive, then lets the
project go. Follow-up requests (``/functions/{addr}/cfg``) are answered from
those dataclasses. The HTTP layer still serves them lazily, so the first
response stays small.

Safety: the binary is loaded with ``auto_load_libs=False`` and is only ever
disassembled. No state is stepped, no code is emulated, nothing is executed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from app.analyzers.import_extractor import ImportEntry, ImportTable, extract_imports
from app.analyzers.risk_scorer import score_function
from app.analyzers.string_extractor import (
    ExtractedString,
    collect_function_strings,
    extract_strings,
)
from app.utils.address import format_address

logger = logging.getLogger(__name__)

#: Guard rails so a pathological binary cannot exhaust memory.
MAX_BLOCKS_PER_FUNCTION = 512
MAX_INSTRUCTIONS_PER_BLOCK = 256
MAX_FUNCTIONS_WITH_DISASSEMBLY = 4000

#: Decompilation is orders of magnitude more expensive than disassembly - a
#: single ~330-block function measured ~19s versus ~0.1s to just disassemble
#: it. These three limits work together: skip functions too big to be worth
#: it, cap how many are attempted at all, and stop early once a time budget
#: is spent, so one large binary cannot make analysis blow past its timeout.
MAX_DECOMPILE_FUNCTIONS = 60
MAX_DECOMPILE_BLOCK_COUNT = 200
DECOMPILE_TIME_BUDGET_SECONDS = 45.0


class AnalysisError(RuntimeError):
    """Raised when the binary cannot be analysed at all."""

    def __init__(self, code: str, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


@dataclass(slots=True)
class AnalyzedInstruction:
    address: int
    mnemonic: str
    operands: str = ""


@dataclass(slots=True)
class AnalyzedBlock:
    address: int
    size: int
    instructions: list[AnalyzedInstruction] = field(default_factory=list)
    #: (target_address, edge_kind) - edge kinds are the EdgeKind string values.
    successors: list[tuple[int, str]] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    #: Calls leaving this block, as node ids (function or API).
    call_targets: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass(slots=True)
class AnalyzedFunction:
    address: int
    name: str
    size: int | None = None
    is_plt: bool = False
    is_simprocedure: bool = False
    is_syscall: bool = False
    is_entry_point: bool = False
    is_imported: bool = False
    has_unresolved_calls: bool = False
    blocks: dict[int, AnalyzedBlock] = field(default_factory=dict)
    callers: set[int] = field(default_factory=set)
    callees: set[int] = field(default_factory=set)
    #: api node id -> call-site addresses
    api_calls: dict[str, list[int]] = field(default_factory=dict)
    api_names: list[str] = field(default_factory=list)
    strings: list[ExtractedString] = field(default_factory=list)
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    #: Best-effort C-like pseudocode from angr's Decompiler. Only a bounded,
    #: prioritised subset of functions gets attempted - see
    #: `_decompile_selected_functions`. "not_attempted" until that pass runs.
    pseudocode: str | None = None
    pseudocode_status: str = "not_attempted"
    pseudocode_note: str | None = None

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def display_name(self) -> str:
        return self.name or format_address(self.address)


@dataclass(slots=True)
class AnalysisArtifacts:
    """Everything the API layer needs.

    Almost entirely plain Python - the one exception is `live_project` /
    `live_cfg_model`, kept around specifically so a function that was not part
    of the eager decompile pass can still be decompiled later, on demand, from
    a cached analysis. This is safe to do *after* the uploaded sample's temp
    file has been deleted: angr's loader reads the whole binary into memory at
    `Project()` construction time and never re-reads the original path
    afterward (verified - deleting the file while `project` is still alive,
    then decompiling a fresh function from it, both succeed on Windows).
    """

    architecture: str
    bits: int
    entry_point: int
    image_base: int
    binary_format: str
    functions: dict[int, AnalyzedFunction] = field(default_factory=dict)
    #: (caller_addr, callee_addr) -> call count
    call_edges: dict[tuple[int, int], int] = field(default_factory=dict)
    #: (caller_addr, callee_addr) -> representative call-site address
    call_sites: dict[tuple[int, int], int] = field(default_factory=dict)
    imports: list[ImportEntry] = field(default_factory=list)
    #: api node id -> caller function addresses
    api_callers: dict[str, set[int]] = field(default_factory=dict)
    #: api node id -> total reference count
    api_references: dict[str, int] = field(default_factory=dict)
    strings: list[ExtractedString] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    likely_packed: bool = False
    duration_seconds: float = 0.0
    #: Retained only to support on-demand decompilation of functions outside
    #: the eager pass. Never serialised; garbage-collected along with this
    #: record when the analysis is evicted from the repository.
    live_project: Any | None = None
    live_cfg_model: Any | None = None

    @property
    def basic_block_count(self) -> int:
        return sum(function.block_count for function in self.functions.values())


# --------------------------------------------------------------------------
# angr plumbing
# --------------------------------------------------------------------------


def _load_project(path: Path) -> Any:
    """Open the binary with angr. Libraries are NOT loaded (auto_load_libs=False)."""
    import angr  # local import: angr is heavy and only needed on this path

    try:
        return angr.Project(str(path), auto_load_libs=False)
    except Exception as exc:
        raise AnalysisError(
            code="LOAD_FAILED",
            message="angr không nạp được binary",
            details=str(exc),
        ) from exc


def _run_cfg(project: Any) -> Any:
    """Run CFGFast. Falls back to a cheaper configuration on failure."""
    try:
        return project.analyses.CFGFast(normalize=True, data_references=True)
    except Exception as exc:
        logger.warning("CFGFast (data_references=True) thất bại: %s", exc)
        try:
            # Data references are the expensive part; without them we still get
            # functions and basic blocks, just no string attribution.
            return project.analyses.CFGFast(normalize=True, data_references=False)
        except Exception as fallback_exc:
            raise AnalysisError(
                code="CFG_FAILED",
                message="Không dựng được control flow graph",
                details=str(fallback_exc),
            ) from fallback_exc


def _architecture_name(project: Any) -> tuple[str, int]:
    arch = getattr(project, "arch", None)
    if arch is None:
        return "unknown", 32
    name = getattr(arch, "name", None) or "unknown"
    bits = int(getattr(arch, "bits", 32) or 32)
    # angr uses "X86"/"AMD64"; present the names an analyst expects.
    friendly = {"X86": "x86", "AMD64": "x86-64", "ARMEL": "arm", "AARCH64": "arm64"}
    return friendly.get(name, str(name).lower()), bits


def _is_conditional_branch(mnemonic: str) -> bool:
    """True for x86/ARM conditional branches (jcc, but not jmp)."""
    lowered = mnemonic.lower()
    if lowered in {"jmp", "jmpq", "b", "bx", "bl"}:
        return False
    return lowered.startswith(("j", "b.", "cb", "tb", "loop"))


def _disassemble_block(project: Any, address: int, size: int | None) -> list[AnalyzedInstruction]:
    """Disassemble one basic block with capstone.

    Returns an empty list rather than raising: a single undecodable block (very
    common in packed samples) must not take down the whole function's CFG.
    """
    try:
        block = project.factory.block(address, size=size) if size else project.factory.block(address)
        instructions: list[AnalyzedInstruction] = []
        for insn in block.capstone.insns[:MAX_INSTRUCTIONS_PER_BLOCK]:
            instructions.append(
                AnalyzedInstruction(
                    address=insn.address,
                    mnemonic=str(insn.mnemonic),
                    operands=str(insn.op_str),
                )
            )
        return instructions
    except Exception as exc:
        logger.debug("Không disassemble được block 0x%x: %s", address, exc)
        return []


def _edge_kind_from_angr(data: dict[str, Any]) -> str:
    """Map an angr transition-graph edge to one of our EdgeKind values."""
    edge_type = str(data.get("type") or "").lower()
    jumpkind = str(data.get("jumpkind") or "").lower()

    if edge_type == "call" or jumpkind == "ijk_call":
        return "CALL"
    if edge_type in {"return", "fake_return"} or jumpkind == "ijk_ret":
        return "RETURN" if edge_type == "return" else "FALLTHROUGH"
    return "JUMP"


def _extract_function_cfg(
    project: Any,
    function: Any,
    analyzed: AnalyzedFunction,
) -> None:
    """Populate ``analyzed.blocks`` from the function's transition graph."""
    transition_graph = getattr(function, "transition_graph", None)
    if transition_graph is None:
        return

    # 1. Materialise the block nodes (skipping Function nodes, which represent
    #    call targets living outside this function).
    for node in list(transition_graph.nodes())[:MAX_BLOCKS_PER_FUNCTION]:
        address = getattr(node, "addr", None)
        if address is None:
            continue
        # A call edge's target is a Function object, not a block of this function.
        if node.__class__.__name__ == "Function":
            continue

        size = getattr(node, "size", None)
        instructions = _disassemble_block(project, address, size)
        analyzed.blocks[address] = AnalyzedBlock(
            address=address,
            size=int(size or 0),
            instructions=instructions,
            truncated=len(instructions) >= MAX_INSTRUCTIONS_PER_BLOCK,
        )

    if len(transition_graph.nodes()) > MAX_BLOCKS_PER_FUNCTION:
        analyzed.has_unresolved_calls = True

    # 2. Walk the edges and classify them.
    for source, target, data in transition_graph.edges(data=True):
        source_address = getattr(source, "addr", None)
        target_address = getattr(target, "addr", None)
        if source_address is None or target_address is None:
            continue
        block = analyzed.blocks.get(source_address)
        if block is None:
            continue

        kind = _edge_kind_from_angr(dict(data))
        if kind == "CALL":
            # Call targets are handled by the call-graph builder, not the CFG.
            continue
        if target_address not in analyzed.blocks:
            # Jump leaving the function (tail call, shared block).
            continue

        block.successors.append((target_address, kind))
        analyzed.blocks[target_address].predecessors.append(source_address)

    # 3. Refine two-way branches into TRUE / FALSE.
    #    Convention: the successor at ``block.addr + block.size`` is the
    #    not-taken (FALSE) path; the other target is taken (TRUE).
    for block in analyzed.blocks.values():
        jump_successors = [item for item in block.successors if item[1] == "JUMP"]
        if len(jump_successors) != 2 or not block.instructions:
            continue
        if not _is_conditional_branch(block.instructions[-1].mnemonic):
            continue

        fallthrough = block.address + block.size
        refined: list[tuple[int, str]] = []
        for target_address, kind in block.successors:
            if kind != "JUMP":
                refined.append((target_address, kind))
            elif target_address == fallthrough:
                refined.append((target_address, "FALSE"))
            else:
                refined.append((target_address, "TRUE"))
        block.successors = refined


def _resolve_call_target(
    project: Any,
    function: Any,
    call_site: int,
) -> int | None:
    try:
        return function.get_call_target(call_site)
    except Exception:
        return None


def _scan_indirect_api_calls(
    analyzed: AnalyzedFunction,
    imports: ImportTable,
) -> None:
    """Catch ``call dword ptr [0x40xxxx]`` style imports.

    MSVC frequently emits a direct indirect call through the IAT rather than a
    thunk. angr records the call but cannot name the target statically, so we
    look for an IAT slot address appearing in the operand text of any call or
    jump instruction and attribute it ourselves.
    """
    if not imports.by_iat:
        return

    for block in analyzed.blocks.values():
        for insn in block.instructions:
            mnemonic = insn.mnemonic.lower()
            if not mnemonic.startswith(("call", "jmp", "bl")):
                continue

            operands = insn.operands.lower()
            if "0x" not in operands:
                continue

            # Pull every hex literal out of the operand text and test it against
            # the IAT. Operand forms vary a lot across syntaxes, so matching on
            # the literal is more robust than parsing the addressing mode.
            for token in operands.replace("[", " ").replace("]", " ").split():
                token = token.strip("*+,-() ")
                if not token.startswith("0x"):
                    continue
                try:
                    candidate = int(token, 16)
                except ValueError:
                    continue

                entry = imports.by_iat.get(candidate)
                if entry is None:
                    continue

                node_id = entry.node_id
                analyzed.api_calls.setdefault(node_id, [])
                if insn.address not in analyzed.api_calls[node_id]:
                    analyzed.api_calls[node_id].append(insn.address)
                if entry.name not in analyzed.api_names:
                    analyzed.api_names.append(entry.name)
                if node_id not in block.call_targets:
                    block.call_targets.append(node_id)


def _detect_packing(project: Any, artifacts: AnalysisArtifacts) -> bool:
    """Very rough packing heuristic.

    Signals: almost no recovered functions, almost no imports, or a section
    whose raw size is far smaller than its virtual size. Any of these makes
    static results unreliable, which is all we claim.
    """
    signals = 0

    if len(artifacts.functions) < 5:
        signals += 1
    if len(artifacts.imports) < 5:
        signals += 1

    try:
        sections = getattr(project.loader.main_object, "sections", []) or []
        suspicious_names = {".upx0", ".upx1", ".aspack", ".themida", ".vmp0", ".vmp1"}
        for section in sections:
            name = str(getattr(section, "name", "") or "").lower().rstrip("\x00")
            if name in suspicious_names:
                signals += 2
                break
            filesize = int(getattr(section, "filesize", 0) or 0)
            memsize = int(getattr(section, "memsize", 0) or 0)
            if memsize > 0x10000 and filesize * 4 < memsize:
                signals += 1
                break
    except Exception:  # pragma: no cover - loader shape varies
        pass

    return signals >= 2


def _select_decompile_candidates(artifacts: AnalysisArtifacts) -> list[AnalyzedFunction]:
    """Rank functions worth spending decompiler time on.

    Only functions with a recovered body are eligible - PLT thunks, syscall
    stubs and SimProcedure hooks have nothing for the decompiler to structure
    and are marked "not_applicable" by the caller instead. Eligible functions
    are ordered: entry point first, then functions with a real symbol name
    (more likely to interest an analyst than `sub_401000`), then highest risk
    score, then fewest blocks first - so a fixed time budget buys as much
    *count* of genuinely interesting output as possible instead of stalling on
    one large function.
    """
    eligible = [
        function
        for function in artifacts.functions.values()
        if not (function.is_plt or function.is_simprocedure or function.is_syscall)
        and function.blocks
    ]

    def sort_key(function: AnalyzedFunction) -> tuple[int, int, int, int]:
        is_named = not function.name.startswith(("sub_", "0x"))
        return (
            0 if function.address == artifacts.entry_point else 1,
            0 if is_named else 1,
            -function.risk_score,
            len(function.blocks),
        )

    eligible.sort(key=sort_key)
    return eligible


def decompile_one_function(project: Any, cfg_model: Any, function: AnalyzedFunction) -> None:
    """Decompile a single function right now, mutating its `pseudocode*` fields.

    Shared by the eager bounded pass (`_decompile_selected_functions`, run once
    at analysis time) and on-demand decompilation (triggered later by a user
    clicking a function that the eager pass skipped). Never raises - a
    function the decompiler chokes on gets `status="failed"` with a reason.
    """
    try:
        raw_function = project.kb.functions[function.address]
        decompiler = project.analyses.Decompiler(raw_function, cfg=cfg_model)
        text = decompiler.codegen.text if decompiler.codegen else None
    except Exception as exc:
        function.pseudocode_status = "failed"
        function.pseudocode_note = f"Decompiler lỗi: {type(exc).__name__}"
        logger.debug("Decompile lỗi ở 0x%x: %s", function.address, exc)
    else:
        if text:
            function.pseudocode = text
            function.pseudocode_status = "available"
            function.pseudocode_note = None
        else:
            function.pseudocode_status = "failed"
            function.pseudocode_note = "Decompiler không tạo được mã cho function này."


def _decompile_selected_functions(project: Any, cfg_model: Any, artifacts: AnalysisArtifacts) -> None:
    """Best-effort C-like pseudocode for a bounded, prioritised subset.

    Runs once, eagerly, while the project is freshly built. Functions this
    pass skips are not lost - see `decompile_one_function` for the on-demand
    path used when the user clicks one of them later.
    """
    for function in artifacts.functions.values():
        if function.is_plt or function.is_simprocedure or function.is_syscall or not function.blocks:
            function.pseudocode_status = "not_applicable"
            function.pseudocode_note = (
                "Import thunk / stub hoặc không có block, không có gì để decompile."
            )

    candidates = _select_decompile_candidates(artifacts)
    attempted = 0
    budget_start = time.perf_counter()
    budget_exceeded = False

    for function in candidates:
        if attempted >= MAX_DECOMPILE_FUNCTIONS:
            function.pseudocode_status = "not_attempted"
            function.pseudocode_note = (
                f"Nằm ngoài top {MAX_DECOMPILE_FUNCTIONS} function được ưu tiên decompile "
                "tự động (entry point, function có tên, risk cao được xét trước). "
                "Bấm \"Decompile hàm này\" để tạo pseudocode riêng cho function này."
            )
            continue

        if len(function.blocks) > MAX_DECOMPILE_BLOCK_COUNT:
            function.pseudocode_status = "not_attempted"
            function.pseudocode_note = (
                f"Function có {len(function.blocks)} block, vượt ngưỡng "
                f"{MAX_DECOMPILE_BLOCK_COUNT} nên bị bỏ qua tự động để tránh phân tích quá lâu. "
                "Vẫn có thể bấm \"Decompile hàm này\" để thử thủ công."
            )
            continue

        if budget_exceeded:
            function.pseudocode_status = "not_attempted"
            function.pseudocode_note = (
                "Hết ngân sách thời gian decompile tự động cho lần phân tích này. "
                "Vẫn có thể bấm \"Decompile hàm này\" để tạo pseudocode riêng."
            )
            continue

        decompile_one_function(project, cfg_model, function)
        attempted += 1
        if time.perf_counter() - budget_start > DECOMPILE_TIME_BUDGET_SECONDS:
            budget_exceeded = True


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def analyze_binary(path: Path, raw_data: bytes | None = None) -> AnalysisArtifacts:
    """Run the full static analysis pipeline for one PE file.

    ``raw_data`` is the file's bytes, passed in so the global string scan does
    not have to re-read from disk. Never executes the sample.
    """
    started = time.perf_counter()

    project = _load_project(path)
    architecture, bits = _architecture_name(project)
    if architecture == "unknown":
        # Not fatal - angr can still recover blocks - but the user should know.
        logger.warning("Không xác định được architecture")

    main_object = getattr(project.loader, "main_object", None)
    image_base = int(getattr(main_object, "mapped_base", 0) or 0)
    binary_format = type(main_object).__name__ if main_object is not None else "Unknown"

    try:
        entry_point = int(project.entry)
    except Exception:
        entry_point = image_base

    artifacts = AnalysisArtifacts(
        architecture=architecture,
        bits=bits,
        entry_point=entry_point,
        image_base=image_base,
        binary_format=binary_format,
    )

    if architecture == "unknown":
        artifacts.warnings.append(
            "angr không xác định chắc chắn kiến trúc CPU; kết quả có thể sai lệch."
        )

    import_table = extract_imports(path, project=None)

    cfg = _run_cfg(project)
    # `cfg` is kept alive (not deleted): CFGFast's function/block/edge results
    # already live on project.kb regardless, but the CFG *model* is also
    # needed later to drive best-effort decompilation, which must happen
    # before the project is discarded.

    # Thunk addresses can only be resolved once functions exist.
    import_table = extract_imports(path, project=project)
    artifacts.imports = list(import_table.entries)
    artifacts.warnings.extend(import_table.warnings)

    try:
        function_manager = project.kb.functions
        raw_functions = list(function_manager.values())
    except Exception as exc:
        raise AnalysisError(
            code="NO_FUNCTIONS",
            message="Không trích xuất được function nào từ binary",
            details=str(exc),
        ) from exc

    if not raw_functions:
        raise AnalysisError(
            code="NO_FUNCTIONS",
            message="Không trích xuất được function nào từ binary",
            details="project.kb.functions rỗng sau khi chạy CFGFast",
        )

    if len(raw_functions) > MAX_FUNCTIONS_WITH_DISASSEMBLY:
        artifacts.warnings.append(
            f"Binary có {len(raw_functions)} function; chỉ disassembly "
            f"{MAX_FUNCTIONS_WITH_DISASSEMBLY} function đầu tiên."
        )

    # --- Pass 1: per-function facts -------------------------------------
    for index, function in enumerate(raw_functions):
        try:
            address = int(function.addr)
        except Exception:
            continue

        is_plt = bool(getattr(function, "is_plt", False))
        is_simprocedure = bool(getattr(function, "is_simprocedure", False))
        is_syscall = bool(getattr(function, "is_syscall", False))

        analyzed = AnalyzedFunction(
            address=address,
            name=str(getattr(function, "name", "") or "") or format_address(address),
            size=int(getattr(function, "size", 0) or 0) or None,
            is_plt=is_plt,
            is_simprocedure=is_simprocedure,
            is_syscall=is_syscall,
            is_entry_point=address == entry_point,
            is_imported=bool(import_table.resolve(name=getattr(function, "name", "")))
            and (is_plt or is_simprocedure),
        )

        if index < MAX_FUNCTIONS_WITH_DISASSEMBLY:
            try:
                _extract_function_cfg(project, function, analyzed)
            except Exception as exc:
                # One broken function must never abort the analysis.
                logger.debug("CFG lỗi ở function 0x%x: %s", address, exc)
                analyzed.has_unresolved_calls = True

        try:
            analyzed.strings = collect_function_strings(function)
        except Exception:
            analyzed.strings = []

        artifacts.functions[address] = analyzed

    # --- Pass 2: call edges and API attribution -------------------------
    for function in raw_functions:
        try:
            caller_address = int(function.addr)
        except Exception:
            continue
        analyzed = artifacts.functions.get(caller_address)
        if analyzed is None:
            continue

        try:
            call_sites = list(function.get_call_sites())
        except Exception:
            call_sites = []

        for call_site in call_sites:
            target = _resolve_call_target(project, function, call_site)
            if target is None:
                analyzed.has_unresolved_calls = True
                continue

            target = int(target)
            target_function = artifacts.functions.get(target)
            entry = import_table.resolve(
                address=target,
                name=target_function.name if target_function else None,
            )

            if entry is not None and (
                target_function is None
                or target_function.is_plt
                or target_function.is_simprocedure
                or target_function.is_syscall
            ):
                # Call lands on an import thunk: record it as an API call.
                node_id = entry.node_id
                analyzed.api_calls.setdefault(node_id, [])
                analyzed.api_calls[node_id].append(int(call_site))
                if entry.name not in analyzed.api_names:
                    analyzed.api_names.append(entry.name)
                block = analyzed.blocks.get(int(call_site))
                if block is not None and node_id not in block.call_targets:
                    block.call_targets.append(node_id)
                continue

            if target_function is None:
                analyzed.has_unresolved_calls = True
                continue

            key = (caller_address, target)
            artifacts.call_edges[key] = artifacts.call_edges.get(key, 0) + 1
            artifacts.call_sites.setdefault(key, int(call_site))
            analyzed.callees.add(target)
            target_function.callers.add(caller_address)

    # Supplement with the kb call graph: it catches edges that
    # ``get_call_sites`` missed (tail calls recovered by other analyses).
    try:
        callgraph = project.kb.callgraph
        for source, target in callgraph.edges():
            source, target = int(source), int(target)
            if source == target:
                continue
            if source not in artifacts.functions or target not in artifacts.functions:
                continue
            target_function = artifacts.functions[target]
            entry = import_table.resolve(address=target, name=target_function.name)
            if entry is not None and (
                target_function.is_plt or target_function.is_simprocedure
            ):
                node_id = entry.node_id
                caller = artifacts.functions[source]
                caller.api_calls.setdefault(node_id, [])
                if entry.name not in caller.api_names:
                    caller.api_names.append(entry.name)
                continue

            key = (source, target)
            if key not in artifacts.call_edges:
                artifacts.call_edges[key] = 1
                artifacts.functions[source].callees.add(target)
                target_function.callers.add(source)
    except Exception as exc:
        logger.debug("Không đọc được kb.callgraph: %s", exc)

    # --- Pass 3: indirect IAT calls, risk scoring -----------------------
    for analyzed in artifacts.functions.values():
        try:
            _scan_indirect_api_calls(analyzed, import_table)
        except Exception as exc:  # pragma: no cover
            logger.debug("Quét indirect call lỗi ở 0x%x: %s", analyzed.address, exc)

        analyzed.risk_score, analyzed.risk_reasons = score_function(
            analyzed.api_names,
            [item.value for item in analyzed.strings],
        )

        for node_id, sites in analyzed.api_calls.items():
            artifacts.api_callers.setdefault(node_id, set()).add(analyzed.address)
            artifacts.api_references[node_id] = artifacts.api_references.get(
                node_id, 0
            ) + max(len(sites), 1)

    # --- Pass 4: best-effort pseudocode, bounded and prioritised ---------
    try:
        _decompile_selected_functions(project, cfg.model, artifacts)
    except Exception as exc:  # pragma: no cover - decompiler infra failure
        logger.warning("Toàn bộ decompile pass thất bại: %s", exc)
        artifacts.warnings.append("Không thể sinh pseudocode cho binary này.")

    # --- Global strings --------------------------------------------------
    if raw_data is not None:
        try:
            artifacts.strings = extract_strings(raw_data, image_base=None)
        except Exception as exc:  # pragma: no cover
            logger.debug("Quét string toàn file lỗi: %s", exc)

    artifacts.likely_packed = _detect_packing(project, artifacts)
    if artifacts.likely_packed:
        artifacts.warnings.append(
            "Binary có thể đã bị pack hoặc obfuscate; kết quả phân tích tĩnh "
            "có thể không đầy đủ."
        )

    # Retained for on-demand decompilation of functions the eager pass above
    # skipped. Deliberately kept alive past this function's return - see the
    # `AnalysisArtifacts.live_project` docstring for why that is safe.
    artifacts.live_project = project
    artifacts.live_cfg_model = cfg.model

    artifacts.duration_seconds = round(time.perf_counter() - started, 3)
    logger.info(
        "Phân tích xong: %d function, %d basic block, %d import trong %.2fs",
        len(artifacts.functions),
        artifacts.basic_block_count,
        len(artifacts.imports),
        artifacts.duration_seconds,
    )
    return artifacts


def iter_named_functions(artifacts: AnalysisArtifacts) -> Iterable[AnalyzedFunction]:
    """Functions angr gave a real symbol name (not a ``sub_xxx`` placeholder)."""
    for function in artifacts.functions.values():
        name = function.name
        if name and not name.startswith(("sub_", "0x")):
            yield function
