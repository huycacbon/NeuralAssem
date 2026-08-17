"""AnalysisService.decompile_all_functions: bookkeeping (which functions get
attempted, which get skipped, and the returned counts).

The actual angr Decompiler call inside `decompile_one_function` is exercised
by `test_integration_angr.py` (needs a real PE) and indirectly by
`test_decompiler_selection.py`'s eager-pass tests - here it is monkeypatched
so this stays fast and angr-free, and only the logic this module itself is
responsible for gets checked: skip already-available/not-applicable
functions, attempt everything else with no count/time budget, refresh the
cached `FunctionDetail` after each attempt, and report accurate counts.
"""

from __future__ import annotations

import app.services.analysis_service as analysis_service_module
from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.repositories.memory import InMemoryAnalysisRepository
from app.services.analysis_service import AnalysisService, _build_record
from tests.conftest import make_function


def _service_with(artifacts: AnalysisArtifacts) -> tuple[AnalysisService, str]:
    record = _build_record(
        analysis_id="decompile-all-test",
        display_name="fixture.exe",
        sha256="cd" * 32,
        size=4096,
        artifacts=artifacts,
    )
    repository = InMemoryAnalysisRepository()
    repository.save(record)
    return AnalysisService(repository), record.analysis_id


class TestDecompileAllFunctions:
    def test_skips_functions_already_available(self, monkeypatch) -> None:
        already = make_function(0x401000, "main")
        already.pseudocode = "int main(void) { return 0; }"
        already.pseudocode_status = "available"
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: already},
            live_project=object(),
            live_cfg_model=object(),
        )
        service, analysis_id = _service_with(artifacts)

        calls: list[object] = []
        monkeypatch.setattr(
            analysis_service_module,
            "decompile_one_function",
            lambda *args, **kwargs: calls.append(args),
        )

        counts = service.decompile_all_functions(analysis_id)

        assert calls == []  # never called - already had pseudocode
        assert counts == {
            "total": 1,
            "alreadyAvailable": 1,
            "decompiled": 0,
            "failed": 0,
            "skippedNotApplicable": 0,
        }

    def test_skips_not_applicable_functions(self, monkeypatch) -> None:
        stub = make_function(0x401000, "CreateFileW", is_plt=True)
        stub.pseudocode_status = "not_applicable"
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: stub},
            live_project=object(),
            live_cfg_model=object(),
        )
        service, analysis_id = _service_with(artifacts)

        calls: list[object] = []
        monkeypatch.setattr(
            analysis_service_module,
            "decompile_one_function",
            lambda *args, **kwargs: calls.append(args),
        )

        counts = service.decompile_all_functions(analysis_id)

        assert calls == []  # nothing to decompile in an import thunk
        assert counts["skippedNotApplicable"] == 1
        assert counts["decompiled"] == 0
        assert counts["failed"] == 0

    def test_attempts_and_counts_remaining_functions(self, monkeypatch) -> None:
        pending_ok = make_function(0x401000, "sub_401000")
        pending_fail = make_function(0x402000, "sub_402000")
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: pending_ok, 0x402000: pending_fail},
            live_project=object(),
            live_cfg_model=object(),
        )
        service, analysis_id = _service_with(artifacts)

        def fake_decompile(project, cfg_model, function):
            if function.address == 0x401000:
                function.pseudocode = "void sub_401000(void) {}"
                function.pseudocode_status = "available"
            else:
                function.pseudocode_status = "failed"
                function.pseudocode_note = "Decompiler lỗi: giả lập"

        monkeypatch.setattr(analysis_service_module, "decompile_one_function", fake_decompile)

        counts = service.decompile_all_functions(analysis_id)

        assert counts == {
            "total": 2,
            "alreadyAvailable": 0,
            "decompiled": 1,
            "failed": 1,
            "skippedNotApplicable": 0,
        }
        # The cached FunctionDetail must reflect the just-computed pseudocode,
        # not the stale "not_attempted" snapshot taken at record-build time -
        # a caller building the full export right after this call needs to
        # see it without a separate re-fetch.
        refreshed = service.get_function(analysis_id, "0x401000")
        assert refreshed is not None
        assert refreshed.pseudocode_status == "available"
        assert refreshed.pseudocode == "void sub_401000(void) {}"

    def test_missing_live_project_marks_every_pending_function_failed(self) -> None:
        pending = make_function(0x401000, "sub_401000")
        artifacts = AnalysisArtifacts(
            architecture="x86",
            bits=32,
            entry_point=0x401000,
            image_base=0x400000,
            binary_format="PE",
            functions={0x401000: pending},
            # live_project/live_cfg_model default to None - simulates a cached
            # analysis record whose live angr project is somehow unavailable.
        )
        service, analysis_id = _service_with(artifacts)

        counts = service.decompile_all_functions(analysis_id)

        assert counts["decompiled"] == 0
        assert counts["failed"] == 1
        refreshed = service.get_function(analysis_id, "0x401000")
        assert refreshed is not None
        assert refreshed.pseudocode_status == "failed"
        assert "không còn khả dụng" in (refreshed.pseudocode_note or "")
