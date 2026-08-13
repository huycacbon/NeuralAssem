"""Build the call graph and the API graph from :mod:`angr_analyzer` artifacts.

Both graphs share one shaping pipeline:

    select nodes (BFS by depth from entry)
        -> cap the node count by priority
        -> emit deduplicated, directed edges

Duplicate ``caller -> callee`` pairs are collapsed into a single edge carrying
``callCount``. Traversal is iterative with a visited set, so recursive or
mutually-recursive functions cannot loop forever.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Iterable

from app.analyzers.angr_analyzer import AnalysisArtifacts, AnalyzedFunction
from app.analyzers.import_extractor import ImportEntry
from app.analyzers.risk_scorer import risk_level
from app.models.graph import EdgeKind, Graph, GraphEdge, GraphNode, NodeKind
from app.utils.address import format_address, function_node_id

DEFAULT_DEPTH = 2
MIN_DEPTH = 1
MAX_DEPTH = 5
DEFAULT_MAX_NODES = 500


def _node_size_hint(degree: int) -> float:
    """``baseSize + log(degree + 1)`` as specified, capped so hubs stay sane."""
    return round(min(20.0 + 8.0 * math.log(degree + 1), 70.0), 2)


def _function_node(function: AnalyzedFunction, entry_point: int) -> GraphNode:
    degree = len(function.callers) + len(function.callees) + len(function.api_calls)
    is_api = function.is_imported or function.is_plt or function.is_simprocedure

    return GraphNode(
        id=function_node_id(function.address),
        label=function.display_name,
        kind=NodeKind.API if is_api else NodeKind.FUNCTION,
        address=format_address(function.address),
        metadata={
            "size": function.size,
            "blockCount": function.block_count,
            "callerCount": len(function.callers),
            "calleeCount": len(function.callees),
            "riskScore": function.risk_score,
            "riskLevel": risk_level(function.risk_score),
            "isImported": is_api,
            "isEntryPoint": function.address == entry_point,
            "isPlt": function.is_plt,
            "isNamed": not function.name.startswith(("sub_", "0x")),
            "hasStrings": bool(function.strings),
            "apiCount": len(function.api_calls),
            "degree": degree,
            "sizeHint": _node_size_hint(degree),
        },
    )


def _api_node(
    entry: ImportEntry,
    reference_count: int,
    caller_count: int,
) -> GraphNode:
    from app.analyzers.risk_scorer import score_api

    weight = score_api(entry.name)
    return GraphNode(
        id=entry.node_id,
        label=entry.name,
        kind=NodeKind.API,
        address=format_address(entry.iat_address) if entry.iat_address else None,
        metadata={
            "module": entry.module,
            "capability": entry.capability,
            "referenceCount": reference_count,
            "callerCount": caller_count,
            "riskScore": weight,
            "riskLevel": risk_level(weight),
            "isImported": True,
            "isEntryPoint": False,
            "degree": caller_count,
            "sizeHint": _node_size_hint(caller_count),
        },
    )


def _bfs_within_depth(
    artifacts: AnalysisArtifacts,
    roots: Iterable[int],
    depth: int,
) -> dict[int, int]:
    """Return ``{function_address: hop_distance}`` for nodes within ``depth`` hops.

    Undirected traversal (callers *and* callees) so a function's context stays
    visible. The visited dict doubles as the loop guard.
    """
    distances: dict[int, int] = {}
    queue: deque[tuple[int, int]] = deque()

    for root in roots:
        if root in artifacts.functions and root not in distances:
            distances[root] = 0
            queue.append((root, 0))

    while queue:
        address, distance = queue.popleft()
        if distance >= depth:
            continue

        function = artifacts.functions.get(address)
        if function is None:
            continue

        for neighbour in (*function.callees, *function.callers):
            if neighbour in distances or neighbour not in artifacts.functions:
                continue
            distances[neighbour] = distance + 1
            queue.append((neighbour, distance + 1))

    return distances


def _prioritise(
    artifacts: AnalysisArtifacts,
    distances: dict[int, int],
    max_nodes: int,
) -> tuple[set[int], bool]:
    """Trim the candidate set to ``max_nodes`` using the documented priority.

    Priority order: entry point, then higher risk score, then closer to the
    entry point, then higher degree.
    """
    if len(distances) <= max_nodes:
        return set(distances), False

    def sort_key(address: int) -> tuple[int, int, int, int]:
        function = artifacts.functions[address]
        return (
            0 if function.address == artifacts.entry_point else 1,
            -function.risk_score,
            distances.get(address, 99),
            -(len(function.callers) + len(function.callees)),
        )

    ordered = sorted(distances, key=sort_key)
    return set(ordered[:max_nodes]), True


def build_call_graph(
    artifacts: AnalysisArtifacts,
    depth: int = DEFAULT_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    include_apis: bool = True,
) -> Graph:
    """Build the function-to-function call graph.

    ``depth`` limits the hop distance from the entry point (1-5). When the entry
    point is unknown or isolated, the highest-degree functions seed the search
    so the user still gets a useful view.
    """
    depth = max(MIN_DEPTH, min(MAX_DEPTH, depth))
    max_nodes = max(10, max_nodes)

    roots: list[int] = []
    if artifacts.entry_point in artifacts.functions:
        roots.append(artifacts.entry_point)
    if not roots:
        # No recognisable entry: seed with the best-connected functions instead.
        roots = sorted(
            artifacts.functions,
            key=lambda address: -(
                len(artifacts.functions[address].callers)
                + len(artifacts.functions[address].callees)
            ),
        )[:10]

    distances = _bfs_within_depth(artifacts, roots, depth)

    if not distances:
        distances = {address: 0 for address in artifacts.functions}

    selected, truncated_by_cap = _prioritise(artifacts, distances, max_nodes)
    omitted = len(artifacts.functions) - len(selected)

    nodes: list[GraphNode] = [
        _function_node(artifacts.functions[address], artifacts.entry_point)
        for address in sorted(selected)
    ]

    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str]] = set()
    for (source, target), count in artifacts.call_edges.items():
        if source not in selected or target not in selected:
            continue
        source_id = function_node_id(source)
        target_id = function_node_id(target)
        key = (source_id, target_id)
        if key in seen_edges:
            continue
        seen_edges.add(key)

        call_site = artifacts.call_sites.get((source, target))
        edges.append(
            GraphEdge(
                id=f"call_{source:x}_{target:x}",
                source=source_id,
                target=target_id,
                kind=EdgeKind.CALL,
                metadata={
                    "callCount": count,
                    "callSite": format_address(call_site) if call_site else None,
                },
            )
        )

    if include_apis:
        _append_api_nodes(artifacts, selected, nodes, edges, seen_edges)

    return Graph(
        nodes=nodes,
        edges=edges,
        metadata={
            "graphType": "call_graph",
            "depth": depth,
            "maxNodes": max_nodes,
            # Two distinct reasons a function can be missing, kept apart so the
            # UI can suggest the right fix: raise maxNodes, or raise depth.
            "truncated": truncated_by_cap,
            "depthLimited": omitted > 0 and not truncated_by_cap,
            "limited": truncated_by_cap or omitted > 0,
            "totalFunctions": len(artifacts.functions),
            "displayedFunctions": len(selected),
            "omittedFunctions": max(omitted, 0),
            "entryPoint": format_address(artifacts.entry_point),
        },
    )


def _append_api_nodes(
    artifacts: AnalysisArtifacts,
    selected: set[int],
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    seen_edges: set[tuple[str, str]],
) -> None:
    """Attach API nodes for the APIs called by the selected functions.

    One node per API, no matter how many functions call it.
    """
    imports_by_id = {entry.node_id: entry for entry in artifacts.imports}
    emitted: set[str] = set()

    for address in sorted(selected):
        function = artifacts.functions.get(address)
        if function is None:
            continue

        for node_id, call_sites in function.api_calls.items():
            entry = imports_by_id.get(node_id)
            if entry is None:
                continue

            if node_id not in emitted:
                emitted.add(node_id)
                nodes.append(
                    _api_node(
                        entry,
                        artifacts.api_references.get(node_id, len(call_sites)),
                        len(artifacts.api_callers.get(node_id, set())),
                    )
                )

            source_id = function_node_id(address)
            key = (source_id, node_id)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                GraphEdge(
                    id=f"apicall_{address:x}_{node_id}",
                    source=source_id,
                    target=node_id,
                    kind=EdgeKind.CALL,
                    metadata={
                        "callCount": len(call_sites),
                        "callSite": format_address(call_sites[0]) if call_sites else None,
                    },
                )
            )


def build_api_graph(
    artifacts: AnalysisArtifacts,
    max_nodes: int = DEFAULT_MAX_NODES,
    capability: str | None = None,
) -> Graph:
    """Build the ``Function -> Imported API`` bipartite graph.

    Only functions that actually call at least one import appear, which keeps
    this view far smaller than the full call graph.
    """
    imports_by_id = {entry.node_id: entry for entry in artifacts.imports}

    # Rank calling functions by risk so the cap keeps the interesting ones.
    callers = [
        function
        for function in artifacts.functions.values()
        if function.api_calls
    ]
    callers.sort(
        key=lambda function: (
            0 if function.address == artifacts.entry_point else 1,
            -function.risk_score,
            -len(function.api_calls),
        )
    )

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    emitted_apis: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    used_functions = 0
    truncated = False

    for function in callers:
        relevant = {
            node_id: sites
            for node_id, sites in function.api_calls.items()
            if node_id in imports_by_id
            and (capability is None or imports_by_id[node_id].capability == capability)
        }
        if not relevant:
            continue

        projected = len(nodes) + 1 + len(set(relevant) - emitted_apis)
        if projected > max_nodes:
            truncated = True
            break

        nodes.append(_function_node(function, artifacts.entry_point))
        used_functions += 1

        for node_id, sites in relevant.items():
            entry = imports_by_id[node_id]
            if node_id not in emitted_apis:
                emitted_apis.add(node_id)
                nodes.append(
                    _api_node(
                        entry,
                        artifacts.api_references.get(node_id, len(sites)),
                        len(artifacts.api_callers.get(node_id, set())),
                    )
                )

            source_id = function_node_id(function.address)
            key = (source_id, node_id)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                GraphEdge(
                    id=f"apiref_{function.address:x}_{node_id}",
                    source=source_id,
                    target=node_id,
                    kind=EdgeKind.CALL,
                    metadata={
                        "callCount": len(sites),
                        "callSite": format_address(sites[0]) if sites else None,
                    },
                )
            )

    return Graph(
        nodes=nodes,
        edges=edges,
        metadata={
            "graphType": "api_graph",
            "maxNodes": max_nodes,
            "truncated": truncated,
            "capability": capability,
            "totalImports": len(artifacts.imports),
            "displayedApis": len(emitted_apis),
            "displayedFunctions": used_functions,
        },
    )


def expand_node(
    artifacts: AnalysisArtifacts,
    address: int,
    max_nodes: int = 60,
) -> Graph:
    """One-hop neighbourhood of a function, used by the frontend's Expand action."""
    function = artifacts.functions.get(address)
    if function is None:
        return Graph(metadata={"graphType": "expansion", "found": False})

    neighbours = list(function.callers | function.callees)[: max_nodes - 1]
    selected = {address, *neighbours}

    nodes = [
        _function_node(artifacts.functions[item], artifacts.entry_point)
        for item in sorted(selected)
        if item in artifacts.functions
    ]

    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str]] = set()
    for (source, target), count in artifacts.call_edges.items():
        if source not in selected or target not in selected:
            continue
        source_id = function_node_id(source)
        target_id = function_node_id(target)
        if (source_id, target_id) in seen_edges:
            continue
        seen_edges.add((source_id, target_id))
        edges.append(
            GraphEdge(
                id=f"call_{source:x}_{target:x}",
                source=source_id,
                target=target_id,
                kind=EdgeKind.CALL,
                metadata={"callCount": count},
            )
        )

    _append_api_nodes(artifacts, {address}, nodes, edges, seen_edges)

    return Graph(
        nodes=nodes,
        edges=edges,
        metadata={
            "graphType": "expansion",
            "found": True,
            "root": format_address(address),
        },
    )
