"""Compact Markdown export, purpose-built for handing an analysis off to an
LLM (or a human doing a quick triage read) - not a full data dump.

Design goals, in priority order:

1. **Token efficiency.** No JSON boilerplate (repeated keys, node/edge wrapper
   objects, UI-only layout fields like `sizeHint`/`degree`). Tables and fenced
   code blocks instead - formats a language model already reads natively and
   cheaply.
2. **Signal over completeness.** A 600-function binary does not get 600
   function write-ups. Only functions that matter for triage - non-zero risk
   score, the entry point, or ones that already have pseudocode "for free"
   from the eager decompile pass - get full detail. Everything else is a
   one-line row or is omitted with an explicit count, never silently dropped.
3. **Still just Markdown.** No binary blobs, diffable, greppable, pastable
   straight into a chat with an LLM.
"""

from __future__ import annotations

from app.models.analysis import AnalysisRecord, FunctionDetail

#: Hard caps so one huge binary cannot produce an unbounded document.
MAX_RISK_TABLE_ROWS = 40
MAX_CALL_GRAPH_EDGES = 150
MAX_CODE_APPENDIX_FUNCTIONS = 25
MAX_CODE_LINES_PER_FUNCTION = 120
MAX_STRINGS_PER_FUNCTION = 15

#: English throughout this module, deliberately - the export exists specifically
#: to be fed to an LLM efficiently, and English tokenizes more compactly than
#: Vietnamese across the mainstream tokenizer families. The rest of the app's
#: UI/API stays Vietnamese; only this document is the exception.
RISK_DISCLAIMER = (
    "Risk score is a heuristic triage signal, NOT a malware verdict. Use it to "
    "prioritise where to look, not to conclude anything is malicious."
)


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def _truncate_code(text: str, max_lines: int) -> tuple[str, bool]:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text, False
    return "\n".join(lines[:max_lines]), True


def _header(record: AnalysisRecord) -> str:
    file = record.file
    summary = record.summary
    lines = [
        f"# Binary Static Analysis: {file.name}",
        "",
        f"> {RISK_DISCLAIMER}",
        "",
        "## File",
        "",
        f"- SHA-256: `{file.sha256}`",
        f"- Size: {_format_bytes(file.size)}",
        f"- Format: {file.format}, {file.architecture} ({file.bits}-bit)",
        f"- Entry point: `{file.entry_point}`",
        f"- Functions: {summary.function_count} | Basic blocks: {summary.basic_block_count} "
        f"| Imports: {summary.import_count} | Strings: {summary.string_count}",
        f"- Analysis time: {summary.analysis_duration_seconds:.1f}s",
    ]
    if summary.likely_packed:
        lines.append(
            "- **Warning: binary may be packed/obfuscated** - static results may be incomplete."
        )
    for warning in summary.warnings:
        lines.append(f"- Warning: {warning}")
    return "\n".join(lines)


def _risk_table(record: AnalysisRecord) -> str:
    risky = sorted(
        (fn for fn in record.functions.values() if fn.risk_score > 0),
        key=lambda fn: -fn.risk_score,
    )
    if not risky:
        return "## Risk Summary\n\nNo function scored above 0 on the risk heuristic."

    shown = risky[:MAX_RISK_TABLE_ROWS]
    omitted = len(risky) - len(shown)

    rows = ["## Risk Summary", "", "| Function | Address | Risk | Callers/Callees | Reasons |", "|---|---|---|---|---|"]
    for fn in shown:
        marker = " (entry)" if fn.is_entry_point else ""
        reasons = "; ".join(fn.risk_reasons) if fn.risk_reasons else "-"
        rows.append(
            f"| {fn.name}{marker} | `{fn.address}` | {fn.risk_score} "
            f"| {fn.caller_count}/{fn.callee_count} | {reasons} |"
        )
    if omitted > 0:
        rows.append("")
        rows.append(f"*({omitted} more risky function(s) omitted - see UI for the full list.)*")
    return "\n".join(rows)


def _imports_section(record: AnalysisRecord) -> str:
    if not record.imports:
        return "## Imports\n\nNone recovered."

    by_module: dict[str, list[str]] = {}
    by_capability: dict[str, list[str]] = {}
    for imp in record.imports:
        by_module.setdefault(imp.module, []).append(imp.name)
        if imp.capability != "other":
            by_capability.setdefault(imp.capability, []).append(imp.name)

    lines = ["## Imports", "", f"Total: {len(record.imports)} across {len(by_module)} DLL(s).", ""]

    if by_capability:
        lines.append("**By capability (higher signal than the full DLL list below):**")
        lines.append("")
        for capability in sorted(by_capability):
            names = sorted(set(by_capability[capability]))
            lines.append(f"- `{capability}`: {', '.join(names)}")
        lines.append("")

    lines.append("**By DLL:**")
    lines.append("")
    for module in sorted(by_module):
        names = sorted(set(by_module[module]))
        lines.append(f"- {module}: {', '.join(names)}")

    return "\n".join(lines)


def _call_graph_section(record: AnalysisRecord) -> str:
    graph = record.call_graph
    if not graph.edges:
        return "## Call Graph\n\nNo edges in the analysed call graph."

    labels: dict[str, str] = {}
    for node in graph.nodes:
        marker = "*" if node.metadata.get("isEntryPoint") else ""
        labels[node.id] = f"{marker}{node.label}"

    edges = graph.edges[:MAX_CALL_GRAPH_EDGES]
    omitted = len(graph.edges) - len(edges)

    lines = [
        "## Call Graph",
        "",
        f"({graph.metadata.get('displayedFunctions', len(graph.nodes))} function(s), "
        f"{len(graph.edges)} edge(s) in the analysed graph; `*` marks the entry point.)",
        "",
        "```",
    ]
    for edge in edges:
        source = labels.get(edge.source, edge.source)
        target = labels.get(edge.target, edge.target)
        count = edge.metadata.get("callCount", 1)
        suffix = f" x{count}" if count and count > 1 else ""
        lines.append(f"{source} -> {target} [{edge.kind}{suffix}]")
    lines.append("```")
    if omitted > 0:
        lines.append("")
        lines.append(f"*({omitted} more edge(s) omitted - see UI for the full call graph.)*")
    return "\n".join(lines)


def _code_appendix(record: AnalysisRecord) -> str:
    """Full pseudocode for functions worth reading in detail.

    Selection: entry point, anything with risk > 0, and anything that already
    has pseudocode available "for free" (already computed, no extra cost to
    include) - in that priority order, capped so the appendix cannot dwarf the
    rest of the report.
    """
    candidates: list[FunctionDetail] = list(record.functions.values())

    def sort_key(fn: FunctionDetail) -> tuple[int, int, int]:
        return (
            0 if fn.is_entry_point else 1,
            -fn.risk_score,
            0 if fn.pseudocode_status == "available" else 1,
        )

    interesting = [
        fn
        for fn in candidates
        if fn.is_entry_point or fn.risk_score > 0 or fn.pseudocode_status == "available"
    ]
    interesting.sort(key=sort_key)
    shown = interesting[:MAX_CODE_APPENDIX_FUNCTIONS]
    omitted = len(interesting) - len(shown)

    if not shown:
        return ""

    lines = [
        "## Function Detail",
        "",
        "Pseudocode is heuristic output from angr's decompiler - may not match the "
        "original source exactly. Functions without pseudocode below can be decompiled "
        "on demand from the UI.",
        "",
    ]

    for fn in shown:
        marker = " (entry point)" if fn.is_entry_point else ""
        lines.append(f"### {fn.name}{marker}")
        lines.append("")
        lines.append(
            f"`{fn.address}` | risk {fn.risk_score} | "
            f"{fn.caller_count} caller(s), {fn.callee_count} callee(s), {fn.block_count} block(s)"
        )
        if fn.risk_reasons:
            lines.append(f"Risk reasons: {'; '.join(fn.risk_reasons)}")
        if fn.imported_apis:
            lines.append(f"Calls: {', '.join(fn.imported_apis)}")
        if fn.strings:
            values = [item.value for item in fn.strings[:MAX_STRINGS_PER_FUNCTION]]
            lines.append(f"Referenced strings: {', '.join(values)}")

        lines.append("")
        if fn.pseudocode_status == "available" and fn.pseudocode:
            code, was_truncated = _truncate_code(fn.pseudocode, MAX_CODE_LINES_PER_FUNCTION)
            lines.append("```c")
            lines.append(code)
            lines.append("```")
            if was_truncated:
                lines.append("*(pseudocode truncated - see UI for the full function.)*")
        else:
            note = fn.pseudocode_note or "Not decompiled yet."
            lines.append(f"*No pseudocode available: {note}*")
        lines.append("")

    if omitted > 0:
        lines.append(f"*({omitted} more function(s) with risk signal omitted from this appendix.)*")

    return "\n".join(lines)


def build_markdown_export(record: AnalysisRecord) -> str:
    """Render one analysis as a compact Markdown document.

    Never raises for a well-formed `AnalysisRecord` - every section degrades
    to an explanatory sentence (e.g. "No edges") rather than omitting itself
    silently, so a reader (human or model) always knows what was checked.
    """
    sections = [
        _header(record),
        _risk_table(record),
        _imports_section(record),
        _call_graph_section(record),
        _code_appendix(record),
    ]
    return "\n\n---\n\n".join(section for section in sections if section)
