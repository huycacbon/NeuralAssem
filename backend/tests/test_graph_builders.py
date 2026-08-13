"""Graph normalisation: JSON shape, edge dedup, depth limit, node cap."""

from __future__ import annotations

import pytest

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.analyzers.call_graph_builder import (
    build_api_graph,
    build_call_graph,
    expand_node,
)
from app.analyzers.cfg_builder import build_function_cfg
from app.models.graph import EdgeKind, NodeKind
from tests.conftest import make_function


class TestCallGraphSerialisation:
    def test_emits_normalised_envelope(self, sample_artifacts: AnalysisArtifacts) -> None:
        payload = build_call_graph(sample_artifacts, depth=5).model_dump(by_alias=True)
        assert set(payload) == {"nodes", "edges", "metadata"}
        assert isinstance(payload["nodes"], list)
        assert isinstance(payload["edges"], list)

    def test_node_matches_documented_shape(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        node = next(item for item in graph.nodes if item.label == "main")

        assert node.id == "func_401000"
        assert node.kind == NodeKind.FUNCTION
        assert node.address == "0x401000"
        assert node.metadata["isEntryPoint"] is True
        for key in ("size", "blockCount", "callerCount", "calleeCount", "riskScore", "isImported"):
            assert key in node.metadata

    def test_entry_point_flagged_on_exactly_one_node(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        flagged = [n for n in graph.nodes if n.metadata.get("isEntryPoint")]
        assert len(flagged) == 1
        assert flagged[0].address == "0x401000"

    def test_edges_are_directed_caller_to_callee(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        edge = next(
            e for e in graph.edges if e.source == "func_401000" and e.target == "func_401100"
        )
        assert edge.kind == EdgeKind.CALL
        # The reverse direction must not exist.
        assert not any(
            e.source == "func_401100" and e.target == "func_401000" for e in graph.edges
        )

    def test_repeated_calls_collapse_into_one_edge_with_count(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        matching = [
            e for e in graph.edges if e.source == "func_401100" and e.target == "func_401300"
        ]
        assert len(matching) == 1
        assert matching[0].metadata["callCount"] == 3

    def test_no_duplicate_edge_ids_or_node_ids(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        node_ids = [n.id for n in graph.nodes]
        edge_ids = [e.id for e in graph.edges]
        assert len(node_ids) == len(set(node_ids))
        assert len(edge_ids) == len(set(edge_ids))

    def test_every_edge_endpoint_exists_as_a_node(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        node_ids = {n.id for n in graph.nodes}
        for edge in graph.edges:
            assert edge.source in node_ids
            assert edge.target in node_ids

    def test_api_nodes_use_api_kind(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        api = next(n for n in graph.nodes if n.id == "api_kernel32!CreateRemoteThread")
        assert api.kind == NodeKind.API
        assert api.metadata["module"] == "KERNEL32.dll"
        assert api.metadata["capability"] == "process_injection"

    def test_api_node_emitted_once_for_multiple_callers(self) -> None:
        api_id = "api_kernel32!CreateRemoteThread"
        callers = {
            addr: make_function(
                addr,
                f"sub_{addr:x}",
                callers={0x401000},
                api_calls={api_id: [addr + 4]},
                api_names=["CreateRemoteThread"],
            )
            for addr in (0x401100, 0x401200, 0x401300)
        }
        root = make_function(0x401000, "main", callees=set(callers))
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: root, **callers},
            call_edges={(0x401000, addr): 1 for addr in callers},
            imports=[
                __import__(
                    "app.analyzers.import_extractor", fromlist=["ImportEntry"]
                ).ImportEntry(module="KERNEL32.dll", name="CreateRemoteThread")
            ],
        )

        graph = build_call_graph(artifacts, depth=5)
        assert sum(1 for n in graph.nodes if n.id == api_id) == 1
        assert sum(1 for e in graph.edges if e.target == api_id) == 3

    def test_can_exclude_apis(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_call_graph(sample_artifacts, depth=5, include_apis=False)
        assert all(not n.id.startswith("api_") for n in graph.nodes)


class TestDepthLimit:
    def test_depth_one_reaches_only_direct_neighbours(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=1, include_apis=False)
        addresses = {n.address for n in graph.nodes}
        assert addresses == {"0x401000", "0x401100"}

    def test_depth_two_reaches_grandchildren(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=2, include_apis=False)
        addresses = {n.address for n in graph.nodes}
        assert addresses == {"0x401000", "0x401100", "0x401200", "0x401300"}

    def test_unreachable_function_excluded_at_any_depth(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=5, include_apis=False)
        assert "0x409000" not in {n.address for n in graph.nodes}

    @pytest.mark.parametrize(("requested", "recorded"), [(0, 1), (-3, 1), (99, 5), (3, 3)])
    def test_depth_is_clamped_to_1_5(
        self, sample_artifacts: AnalysisArtifacts, requested: int, recorded: int
    ) -> None:
        graph = build_call_graph(sample_artifacts, depth=requested)
        assert graph.metadata["depth"] == recorded

    def test_cycles_terminate(self) -> None:
        # a -> b -> c -> a. A naive traversal would spin forever.
        a = make_function(0x401000, "a", callees={0x401100}, callers={0x401200})
        b = make_function(0x401100, "b", callees={0x401200}, callers={0x401000})
        c = make_function(0x401200, "c", callees={0x401000}, callers={0x401100})
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={f.address: f for f in (a, b, c)},
            call_edges={
                (0x401000, 0x401100): 1,
                (0x401100, 0x401200): 1,
                (0x401200, 0x401000): 1,
            },
        )
        graph = build_call_graph(artifacts, depth=5)
        assert len(graph.nodes) == 3

    def test_self_recursive_function_has_no_self_loop_from_kb_merge(self) -> None:
        f = make_function(0x401000, "recurse", callees={0x401000}, callers={0x401000})
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: f},
            call_edges={(0x401000, 0x401000): 2},
        )
        graph = build_call_graph(artifacts, depth=3)
        assert len(graph.nodes) == 1


class TestMaxNodesLimit:
    def _wide_artifacts(self, count: int) -> AnalysisArtifacts:
        """One entry function calling ``count`` leaves, with rising risk scores."""
        root = make_function(0x401000, "main")
        leaves = {}
        for index in range(count):
            address = 0x402000 + index * 0x10
            leaves[address] = make_function(
                address, f"sub_{address:x}", callers={0x401000}, risk_score=index
            )
            root.callees.add(address)

        return AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: root, **leaves},
            call_edges={(0x401000, addr): 1 for addr in leaves},
        )

    def test_respects_the_cap(self) -> None:
        graph = build_call_graph(
            self._wide_artifacts(300), depth=5, max_nodes=50, include_apis=False
        )
        assert len(graph.nodes) <= 50
        assert graph.metadata["truncated"] is True
        assert graph.metadata["omittedFunctions"] > 0

    def test_entry_point_always_survives_the_cap(self) -> None:
        graph = build_call_graph(
            self._wide_artifacts(300), depth=5, max_nodes=20, include_apis=False
        )
        assert any(n.metadata["isEntryPoint"] for n in graph.nodes)

    def test_highest_risk_functions_are_kept(self) -> None:
        graph = build_call_graph(
            self._wide_artifacts(300), depth=5, max_nodes=20, include_apis=False
        )
        scores = [n.metadata["riskScore"] for n in graph.nodes]
        # 299 is the top score in the fixture; the cap must not drop it.
        assert max(scores) == 299

    def test_not_truncated_when_it_fits(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_call_graph(sample_artifacts, depth=5, max_nodes=500)
        assert graph.metadata["truncated"] is False

    def test_depth_limiting_is_reported_separately_from_the_cap(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        # The fixture's `orphan` is unreachable from the entry point, so it is
        # excluded by traversal - not by the node cap. The UI needs to tell the
        # two apart to suggest the right remedy.
        graph = build_call_graph(sample_artifacts, depth=5, max_nodes=500)
        assert graph.metadata["truncated"] is False
        assert graph.metadata["depthLimited"] is True
        assert graph.metadata["limited"] is True
        assert graph.metadata["omittedFunctions"] == 1

    def test_metadata_reports_totals(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_call_graph(sample_artifacts, depth=5)
        assert graph.metadata["totalFunctions"] == 5
        assert graph.metadata["entryPoint"] == "0x401000"


class TestApiGraph:
    def test_is_bipartite_function_to_api(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_api_graph(sample_artifacts)
        by_id = {n.id: n for n in graph.nodes}
        for edge in graph.edges:
            assert by_id[edge.target].kind == NodeKind.API
            assert edge.kind == EdgeKind.CALL

    def test_only_includes_functions_that_call_imports(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_api_graph(sample_artifacts)
        addresses = {n.address for n in graph.nodes if n.kind == NodeKind.FUNCTION}
        # add/calculate/orphan call no imports.
        assert "0x401200" not in addresses
        assert "0x409000" not in addresses

    def test_capability_filter(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_api_graph(sample_artifacts, capability="process_injection")
        api_labels = {n.label for n in graph.nodes if n.kind == NodeKind.API}
        assert api_labels == {"CreateRemoteThread"}

    def test_respects_max_nodes(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_api_graph(sample_artifacts, max_nodes=10)
        assert len(graph.nodes) <= 10


class TestFunctionCfg:
    def test_blocks_become_nodes(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401100)
        assert graph is not None
        assert {n.id for n in graph.nodes} == {"block_401100", "block_401110", "block_401130"}
        assert all(n.kind == NodeKind.BASIC_BLOCK for n in graph.nodes)

    def test_node_carries_instructions(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401100)
        node = next(n for n in graph.nodes if n.id == "block_401100")
        assert node.metadata["instructionCount"] == 2
        assert node.metadata["instructions"][0] == {
            "address": "0x401100",
            "mnemonic": "cmp",
            "operands": "eax, 0xa",
        }

    def test_conditional_branch_labelled_true_and_false(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401100)
        kinds = {(e.source, e.target): e.kind for e in graph.edges}
        assert kinds[("block_401100", "block_401110")] == EdgeKind.TRUE
        assert kinds[("block_401100", "block_401130")] == EdgeKind.FALSE

    def test_can_omit_instructions(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401100, include_instructions=False)
        assert all(n.metadata["instructions"] == [] for n in graph.nodes)
        # The count is still reported so the UI can show block weight.
        assert any(n.metadata["instructionCount"] > 0 for n in graph.nodes)

    def test_unknown_function_returns_none(self, sample_artifacts: AnalysisArtifacts) -> None:
        assert build_function_cfg(sample_artifacts, 0xDEAD) is None

    def test_function_without_blocks_yields_empty_graph(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401200)
        assert graph is not None
        assert graph.nodes == []
        assert graph.metadata["blockCount"] == 0

    def test_metadata(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = build_function_cfg(sample_artifacts, 0x401100)
        assert graph.metadata["functionAddress"] == "0x401100"
        assert graph.metadata["functionName"] == "calculate"
        assert graph.metadata["graphType"] == "cfg"


class TestExpandNode:
    def test_returns_one_hop_neighbourhood(self, sample_artifacts: AnalysisArtifacts) -> None:
        graph = expand_node(sample_artifacts, 0x401100)
        addresses = {n.address for n in graph.nodes if n.kind == NodeKind.FUNCTION}
        assert addresses == {"0x401000", "0x401100", "0x401200", "0x401300"}

    def test_unknown_address_reports_not_found(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        graph = expand_node(sample_artifacts, 0xDEAD)
        assert graph.metadata["found"] is False
        assert graph.nodes == []
