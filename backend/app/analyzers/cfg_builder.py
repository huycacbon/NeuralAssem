"""Turn one function's basic blocks into the normalised graph envelope.

Emitted separately from the call graph because CFGs are only fetched when the
user opens a specific function - the first analysis response never carries
instruction listings.
"""

from __future__ import annotations

from app.analyzers.angr_analyzer import AnalysisArtifacts, AnalyzedFunction
from app.models.graph import EdgeKind, Graph, GraphEdge, GraphNode, NodeKind
from app.utils.address import block_node_id, format_address

_KIND_LOOKUP = {kind.value: kind for kind in EdgeKind}


def _edge_kind(value: str) -> EdgeKind:
    """Map a stored edge label to an ``EdgeKind``, defaulting to ``JUMP``.

    angr cannot always tell a conditional branch's polarity; the spec says to
    fall back to JUMP/FALLTHROUGH rather than guess.
    """
    return _KIND_LOOKUP.get(value.upper(), EdgeKind.JUMP)


def _block_node(
    function: AnalyzedFunction,
    address: int,
    include_instructions: bool,
) -> GraphNode:
    block = function.blocks[address]
    instructions = (
        [
            {
                "address": format_address(insn.address),
                "mnemonic": insn.mnemonic,
                "operands": insn.operands,
            }
            for insn in block.instructions
        ]
        if include_instructions
        else []
    )

    return GraphNode(
        id=block_node_id(address),
        label=format_address(address),
        kind=NodeKind.BASIC_BLOCK,
        address=format_address(address),
        metadata={
            "size": block.size,
            "instructionCount": len(block.instructions),
            "instructions": instructions,
            "truncated": block.truncated,
            "isFunctionStart": address == function.address,
            "callTargets": list(block.call_targets),
            "successorCount": len(block.successors),
            "predecessorCount": len(set(block.predecessors)),
        },
    )


def build_function_cfg(
    artifacts: AnalysisArtifacts,
    address: int,
    include_instructions: bool = True,
    max_blocks: int = 400,
) -> Graph | None:
    """Build the CFG for the function at ``address``.

    Returns ``None`` when no such function exists so the API layer can answer
    404. A block that failed to disassemble still appears as a node with an
    empty instruction list - a single bad block never voids the whole CFG.
    """
    function = artifacts.functions.get(address)
    if function is None:
        return None

    block_addresses = sorted(function.blocks)
    truncated = len(block_addresses) > max_blocks
    if truncated:
        block_addresses = block_addresses[:max_blocks]
    visible = set(block_addresses)

    nodes = [
        _block_node(function, block_address, include_instructions)
        for block_address in block_addresses
    ]

    edges: list[GraphEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for block_address in block_addresses:
        block = function.blocks[block_address]
        for target, kind_value in block.successors:
            if target not in visible:
                continue
            source_id = block_node_id(block_address)
            target_id = block_node_id(target)
            key = (source_id, target_id, kind_value)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                GraphEdge(
                    id=f"cfg_{block_address:x}_{target:x}_{kind_value.lower()}",
                    source=source_id,
                    target=target_id,
                    kind=_edge_kind(kind_value),
                    metadata={"fromBlock": format_address(block_address)},
                )
            )

    instruction_count = sum(len(function.blocks[a].instructions) for a in block_addresses)

    return Graph(
        nodes=nodes,
        edges=edges,
        metadata={
            "graphType": "cfg",
            "functionAddress": format_address(function.address),
            "functionName": function.display_name,
            "blockCount": len(function.blocks),
            "displayedBlocks": len(block_addresses),
            "instructionCount": instruction_count,
            "truncated": truncated,
            "riskScore": function.risk_score,
            "riskReasons": function.risk_reasons,
            "hasUnresolvedCalls": function.has_unresolved_calls,
            "isEntryPoint": function.is_entry_point,
        },
    )
