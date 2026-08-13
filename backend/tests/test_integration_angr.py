"""End-to-end test against a real PE.

This is the only test that actually runs angr, so it is slow (10-30s) and is
skipped unless a PE is available. Resolution order for the sample:

1. ``BGA_TEST_PE`` env var - point it at the compiled ``fixtures/sample.c``.
2. ``tests/fixtures/sample.exe`` if it was compiled in place.
3. A benign Windows system binary, copied read-only to a temp path.

The sample is only ever read and disassembled - never executed.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"

#: Small, self-contained, benign system executables used as a last resort.
_SYSTEM_CANDIDATES = (
    r"C:\Windows\System32\where.exe",
    r"C:\Windows\System32\hostname.exe",
    r"C:\Windows\System32\whoami.exe",
)


def _locate_sample() -> Path | None:
    override = os.environ.get("BGA_TEST_PE")
    if override and Path(override).is_file():
        return Path(override)

    compiled = FIXTURE_DIR / "sample.exe"
    if compiled.is_file():
        return compiled

    if sys.platform == "win32":
        for candidate in _SYSTEM_CANDIDATES:
            if Path(candidate).is_file():
                return Path(candidate)

    return None


SAMPLE = _locate_sample()

pytestmark = pytest.mark.skipif(
    SAMPLE is None,
    reason=(
        "Không tìm thấy PE để test. Compile tests/fixtures/sample.c "
        "(gcc -O0 -o sample.exe sample.c) hoặc đặt biến môi trường BGA_TEST_PE."
    ),
)


@pytest.fixture(scope="module")
def analysis():
    """Run one analysis and share it across the assertions in this module."""
    from app.repositories import InMemoryAnalysisRepository
    from app.services.analysis_service import AnalysisService

    service = AnalysisService(InMemoryAnalysisRepository())
    with SAMPLE.open("rb") as handle:
        response = service.analyze_upload(handle, SAMPLE.name)
    return service, response


class TestAnalysisPipeline:
    def test_file_metadata_is_populated(self, analysis) -> None:
        _, response = analysis
        assert len(response.file.sha256) == 64
        assert response.file.size > 0
        assert response.file.architecture in {"x86", "x86-64"}
        assert response.file.entry_point.startswith("0x")

    def test_functions_and_blocks_recovered(self, analysis) -> None:
        _, response = analysis
        assert response.summary.function_count > 0
        assert response.summary.basic_block_count >= response.summary.function_count

    def test_imports_recovered(self, analysis) -> None:
        service, response = analysis
        assert response.summary.import_count > 0
        imports = service.get_imports(response.analysis_id)
        assert all(item.module for item in imports)
        assert all(item.name for item in imports)

    def test_call_graph_is_well_formed(self, analysis) -> None:
        _, response = analysis
        graph = response.call_graph
        assert graph.nodes

        node_ids = {node.id for node in graph.nodes}
        for edge in graph.edges:
            assert edge.source in node_ids
            assert edge.target in node_ids

        # Every node carries something an analyst can read.
        for node in graph.nodes:
            assert node.label
            assert node.address or node.kind == "api"

    def test_exactly_one_entry_point_node(self, analysis) -> None:
        _, response = analysis
        flagged = [
            node
            for node in response.call_graph.nodes
            if node.metadata.get("isEntryPoint")
        ]
        assert len(flagged) == 1
        assert flagged[0].address == response.file.entry_point

    def test_cfg_has_blocks_and_instructions(self, analysis) -> None:
        service, response = analysis

        listing = service.list_functions(response.analysis_id, limit=200)
        target = next((f for f in listing.items if f.block_count >= 2), None)
        assert target is not None, "Cần ít nhất một function có nhiều basic block"

        graph = service.get_function_cfg(response.analysis_id, target.address)
        assert graph is not None
        assert graph.nodes

        total_instructions = sum(
            node.metadata["instructionCount"] for node in graph.nodes
        )
        assert total_instructions > 0

        first = graph.nodes[0]
        assert first.kind == "basic_block"
        if first.metadata["instructions"]:
            instruction = first.metadata["instructions"][0]
            assert set(instruction) == {"address", "mnemonic", "operands"}

    def test_cfg_edge_kinds_are_from_the_documented_set(self, analysis) -> None:
        service, response = analysis
        allowed = {"TRUE", "FALSE", "JUMP", "FALLTHROUGH", "CALL", "RETURN"}

        for function in service.list_functions(response.analysis_id, limit=40).items:
            graph = service.get_function_cfg(response.analysis_id, function.address)
            if graph is None:
                continue
            for edge in graph.edges:
                assert edge.kind in allowed

    def test_api_graph_links_functions_to_apis(self, analysis) -> None:
        service, response = analysis
        graph = service.get_api_graph(response.analysis_id)
        by_id = {node.id: node for node in graph.nodes}

        assert any(node.kind == "api" for node in graph.nodes)
        for edge in graph.edges:
            assert by_id[edge.target].kind == "api"
            assert by_id[edge.source].kind in {"function", "api"}

    def test_api_nodes_are_deduplicated(self, analysis) -> None:
        service, response = analysis
        graph = service.get_api_graph(response.analysis_id)
        api_ids = [node.id for node in graph.nodes if node.kind == "api"]
        assert len(api_ids) == len(set(api_ids))

    def test_search_by_name_and_address(self, analysis) -> None:
        service, response = analysis
        listing = service.list_functions(response.analysis_id, limit=1)
        target = listing.items[0]

        by_address = service.list_functions(
            response.analysis_id, search=target.address, limit=10
        )
        assert target.address in {item.address for item in by_address.items}

        by_name = service.list_functions(
            response.analysis_id, search=target.name, limit=10
        )
        assert target.address in {item.address for item in by_name.items}

    def test_depth_limit_shrinks_the_graph(self, analysis) -> None:
        service, response = analysis
        shallow = service.get_call_graph(response.analysis_id, depth=1, include_apis=False)
        deep = service.get_call_graph(response.analysis_id, depth=5, include_apis=False)
        assert len(shallow.nodes) <= len(deep.nodes)

    def test_max_nodes_cap_is_enforced(self, analysis) -> None:
        service, response = analysis
        graph = service.get_call_graph(response.analysis_id, depth=5, max_nodes=15)
        function_nodes = [n for n in graph.nodes if n.kind == "function"]
        assert len(function_nodes) <= 15


class TestOnDemandDecompile:
    """The click-to-decompile path: works after the temp file is long gone,
    reusing the analysis's still-alive angr project (see
    AnalysisArtifacts.live_project)."""

    def test_decompiles_a_function_outside_the_eager_pass(self, analysis) -> None:
        service, response = analysis
        listing = service.list_functions(response.analysis_id, limit=1000)

        # Find a function the eager pass (capped at 60) left untouched.
        target = next(
            (
                item
                for item in listing.items
                if service.get_function(response.analysis_id, item.address).pseudocode_status
                != "available"
                and service.get_function(response.analysis_id, item.address).pseudocode_status
                != "not_applicable"
            ),
            None,
        )
        if target is None:
            pytest.skip("Every eligible function was already decompiled eagerly")

        before = service.get_function(response.analysis_id, target.address)
        assert before.pseudocode is None

        after = service.decompile_function(response.analysis_id, target.address)
        assert after is not None
        assert after.pseudocode_status in {"available", "failed"}
        if after.pseudocode_status == "available":
            assert after.pseudocode
            assert "{" in after.pseudocode  # looks like C

        # The refreshed detail must also be what a plain GET returns afterward.
        refetched = service.get_function(response.analysis_id, target.address)
        assert refetched.pseudocode_status == after.pseudocode_status
        assert refetched.pseudocode == after.pseudocode

    def test_second_call_is_a_cheap_no_op_once_available(self, analysis) -> None:
        service, response = analysis
        listing = service.list_functions(response.analysis_id, limit=1000)
        already_available = next(
            (
                item
                for item in listing.items
                if service.get_function(response.analysis_id, item.address).pseudocode_status
                == "available"
            ),
            None,
        )
        if already_available is None:
            pytest.skip("No eagerly-decompiled function available to test against")

        first = service.decompile_function(response.analysis_id, already_available.address)
        second = service.decompile_function(response.analysis_id, already_available.address)
        assert first.pseudocode == second.pseudocode

    def test_unknown_address_returns_none(self, analysis) -> None:
        service, response = analysis
        assert service.decompile_function(response.analysis_id, "0xdeadbeef") is None

    def test_works_after_temp_file_is_gone(self, analysis) -> None:
        """The whole point: decompiling on demand must not need the original
        upload, which is already deleted by the time `analysis` fixture runs."""
        from app.config import settings

        service, response = analysis
        assert list(settings.upload_dir.glob("*")) == [] or all(
            not p.is_file() for p in settings.upload_dir.glob("*")
        )

        listing = service.list_functions(response.analysis_id, limit=1)
        result = service.decompile_function(response.analysis_id, listing.items[0].address)
        assert result is not None


class TestTempFileHygiene:
    def test_no_uploads_left_behind(self, analysis) -> None:
        """The sample must be gone from the upload directory after analysis."""
        from app.config import settings

        _ = analysis  # ensure an analysis has run
        if not settings.upload_dir.exists():
            return
        leftovers = [item for item in settings.upload_dir.iterdir() if item.is_file()]
        assert leftovers == [], f"File tạm còn sót: {leftovers}"


class TestRejectsNonPe:
    def test_text_file_is_rejected_before_angr(self, tmp_path) -> None:
        from app.repositories import InMemoryAnalysisRepository
        from app.services.analysis_service import AnalysisService
        from app.utils.security import UploadValidationError

        fake = tmp_path / "fake.exe"
        fake.write_bytes(b"this is plainly not a PE file" * 10)

        service = AnalysisService(InMemoryAnalysisRepository())
        with fake.open("rb") as handle:
            with pytest.raises(UploadValidationError) as excinfo:
                service.analyze_upload(handle, "fake.exe")
        assert excinfo.value.code == "NOT_A_PE"


def test_sample_is_never_executed() -> None:
    """Guard rail: the analysis path must not reference process-spawning APIs.

    A source-level check, but it catches the mistake this project most needs to
    avoid - someone reaching for subprocess to "just run it quickly".

    Note: this scans the whole `app/` tree, which includes `app/dynamic/` -
    but it only catches Python-level process-spawning tokens (`subprocess`,
    `os.system`, etc). It does NOT catch and cannot catch
    `app.dynamic.debug_bridge.client.ComtypesDebugBridge.create_and_attach_local`,
    a deliberate, separate, user-confirmed exception that executes a binary
    via a raw `dbgeng.dll` COM call instead. This test passing is not proof
    the whole `app/` tree never executes anything - see
    `test_dynamic_security.py` (specifically
    `test_local_launch_is_isolated_to_one_method`) and
    `docs/dynamic-analysis-spec.md`'s local-launch addendum for what actually
    guards that capability, and why it exists at all. The static analyzer
    this test was originally written for (everything under `app/analyzers/`,
    `app/services/`) is unaffected - its own "sample is never executed"
    guarantee still holds exactly as before.
    """
    forbidden = ("subprocess", "os.system", "os.spawn", "os.exec", "ShellExecute")
    analyzer_dir = Path(__file__).parents[1] / "app"

    offenders: list[str] = []
    for source in analyzer_dir.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append(f"{source.name}: {token}")

    assert offenders == [], f"Phát hiện API thực thi tiến trình: {offenders}"
