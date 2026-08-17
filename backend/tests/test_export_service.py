"""Markdown export: content correctness and the "only what matters" cuts."""

from __future__ import annotations

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.services.analysis_service import _build_record
from app.services.export_service import (
    RISK_DISCLAIMER,
    build_full_markdown_export,
    build_markdown_export,
)
from tests.conftest import make_function


def _record(artifacts: AnalysisArtifacts, analysis_id: str = "export-test"):
    return _build_record(
        analysis_id=analysis_id,
        display_name="fixture.exe",
        sha256="ab" * 32,
        size=65536,
        artifacts=artifacts,
    )


class TestHeader:
    def test_includes_file_identity(self, sample_artifacts: AnalysisArtifacts) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        assert "fixture.exe" in markdown
        assert "ab" * 32 in markdown
        assert "0x401000" in markdown  # entry point

    def test_includes_disclaimer(self, sample_artifacts: AnalysisArtifacts) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        assert RISK_DISCLAIMER in markdown

    def test_flags_packed_binary(self, sample_artifacts: AnalysisArtifacts) -> None:
        sample_artifacts.likely_packed = True
        markdown = build_markdown_export(_record(sample_artifacts))
        assert "packed" in markdown.lower()


class TestRiskTable:
    def test_includes_risky_function_with_reasons(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        assert "multiply" in markdown
        assert "CreateRemoteThread" in markdown

    def test_excludes_zero_risk_non_entry_function_from_risk_table(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        risk_section = markdown.split("## Risk Summary")[1].split("## Imports")[0]
        # `add` (risk 0, not the entry point) must not appear in the risk table,
        # even though it does legitimately appear elsewhere (call graph).
        assert "add" not in risk_section

    def test_no_risky_functions_produces_explicit_fallback(self) -> None:
        only_benign = make_function(0x401000, "main")
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: only_benign},
        )
        markdown = build_markdown_export(_record(artifacts))
        assert "No function scored above 0" in markdown


class TestImportsSection:
    def test_grouped_by_dll_and_capability(self, sample_artifacts: AnalysisArtifacts) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        assert "KERNEL32.dll" in markdown
        assert "process_injection" in markdown

    def test_no_imports_produces_explicit_fallback(self) -> None:
        fn = make_function(0x401000, "main")
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: fn},
        )
        markdown = build_markdown_export(_record(artifacts))
        assert "None recovered" in markdown


class TestCallGraphSection:
    def test_marks_entry_point_and_shows_edges(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        call_graph_section = markdown.split("## Call Graph")[1].split("## Function Detail")[0]
        assert "*main" in call_graph_section
        assert "->" in call_graph_section
        assert "[CALL" in call_graph_section


class TestCodeAppendix:
    def test_includes_entry_point_and_risky_function(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        assert "### main (entry point)" in markdown
        assert "### multiply" in markdown

    def test_excludes_zero_risk_non_entry_function(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        # `add`: risk 0, not the entry point, no pseudocode -> not worth a write-up.
        assert "### add" not in markdown

    def test_missing_pseudocode_explains_why_instead_of_silently_omitting(
        self, sample_artifacts: AnalysisArtifacts
    ) -> None:
        markdown = build_markdown_export(_record(sample_artifacts))
        section = markdown.split("### multiply")[1].split("### ")[0]
        assert "No pseudocode available" in section

    def test_available_pseudocode_is_included_verbatim(self) -> None:
        fn = make_function(0x401000, "main", risk_score=5)
        fn.pseudocode = "int main(void) {\n    return 0;\n}"
        fn.pseudocode_status = "available"
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: fn},
        )
        markdown = build_markdown_export(_record(artifacts))
        assert "```c" in markdown
        assert "return 0;" in markdown


class TestFullCodeAppendix:
    """`build_full_markdown_export` - the uncapped "export everything"
    counterpart to `build_markdown_export`'s risk-curated top-25."""

    def test_every_function_with_pseudocode_is_included_not_just_risky_ones(self) -> None:
        # `add`: risk 0, not the entry point - `build_markdown_export` leaves
        # it out entirely (see TestCodeAppendix.test_excludes_zero_risk...
        # above). The full export must still include it once it has code.
        add = make_function(0x401200, "add", callers={0x401100})
        add.pseudocode = "int add(int a, int b) { return a + b; }"
        add.pseudocode_status = "available"
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: make_function(0x401000, "main"), 0x401200: add},
        )
        markdown = build_full_markdown_export(_record(artifacts))
        assert "### add" in markdown
        assert "return a + b;" in markdown

    def test_functions_without_pseudocode_are_listed_with_a_reason_not_silently_dropped(
        self,
    ) -> None:
        failed = make_function(0x401200, "sub_401200")
        failed.pseudocode_status = "failed"
        failed.pseudocode_note = "Decompiler lỗi: giả lập"
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: make_function(0x401000, "main"), 0x401200: failed},
        )
        markdown = build_full_markdown_export(_record(artifacts))
        table_section = markdown.split("### Functions without pseudocode")[1]
        assert "sub_401200" in table_section
        assert "Decompiler lỗi: giả lập" in table_section

    def test_no_curated_top_n_cap_on_a_wide_binary(self) -> None:
        root = make_function(0x401000, "main")
        leaves = {}
        for index in range(60):
            address = 0x402000 + index * 0x10
            fn = make_function(address, f"sub_{address:x}", callers={0x401000})
            fn.pseudocode = f"void sub_{address:x}(void) {{}}"
            fn.pseudocode_status = "available"
            leaves[address] = fn
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: root, **leaves},
        )
        markdown = build_full_markdown_export(_record(artifacts))
        # `build_markdown_export`'s MAX_CODE_APPENDIX_FUNCTIONS (25) would cap
        # this well below 60 - the full export must not.
        assert markdown.count("### sub_") == 60


class TestRobustness:
    def test_never_raises_on_minimal_binary(self) -> None:
        fn = make_function(0x401000, "sub_401000")
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: fn},
        )
        markdown = build_markdown_export(_record(artifacts))
        assert markdown  # produced *something*, no exception
        # Zero risk score -> not in the risk table, even though it's the entry point
        # (the risk table is purely risk-driven; the code appendix is where
        # entry-point status matters).
        risk_section = markdown.split("## Risk Summary")[1].split("## Imports")[0]
        assert "sub_401000" not in risk_section

    def test_caps_are_respected_on_a_wide_binary(self) -> None:
        root = make_function(0x401000, "main")
        leaves = {}
        for index in range(300):
            address = 0x402000 + index * 0x10
            leaves[address] = make_function(
                address, f"sub_{address:x}", callers={0x401000}, risk_score=1 + (index % 5)
            )
            root.callees.add(address)
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: root, **leaves},
            call_edges={(0x401000, addr): 1 for addr in leaves},
        )
        markdown = build_markdown_export(_record(artifacts))
        assert "more risky function(s) omitted" in markdown
        assert "more function(s) with risk signal omitted" in markdown
