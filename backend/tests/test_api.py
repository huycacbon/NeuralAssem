"""HTTP layer: error envelope shape, validation, and query handling."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.dependencies import get_analysis_service, get_repository
from app.main import app
from app.models.analysis import AnalysisRecord, FileInfo
from app.services.analysis_service import _build_record


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def stored_analysis(sample_artifacts: AnalysisArtifacts) -> AnalysisRecord:
    """Insert a synthetic analysis so the read endpoints have data to serve."""
    record = _build_record(
        analysis_id="test-analysis",
        display_name="fixture.exe",
        sha256="0" * 64,
        size=4096,
        artifacts=sample_artifacts,
    )
    get_repository().save(record)
    yield record
    get_repository().delete("test-analysis")


class TestHealth:
    def test_reports_ok(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] in {"ok", "degraded"}


class TestErrorEnvelope:
    def test_unknown_analysis_returns_structured_error(self, client: TestClient) -> None:
        response = client.get("/api/analysis/does-not-exist")
        assert response.status_code == 404
        payload = response.json()
        assert set(payload) == {"error"}
        assert payload["error"]["code"] == "ANALYSIS_NOT_FOUND"
        assert payload["error"]["message"]

    def test_bad_extension_rejected_before_analysis(self, client: TestClient) -> None:
        response = client.post(
            "/api/analysis",
            files={"file": ("notes.txt", io.BytesIO(b"hello"), "text/plain")},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_EXTENSION"

    def test_non_pe_content_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/api/analysis",
            files={"file": ("fake.exe", io.BytesIO(b"not a pe at all" * 20), "application/octet-stream")},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "NOT_A_PE"

    def test_empty_file_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/api/analysis",
            files={"file": ("empty.exe", io.BytesIO(b""), "application/octet-stream")},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "EMPTY_FILE"

    def test_missing_file_field_uses_validation_envelope(self, client: TestClient) -> None:
        response = client.post("/api/analysis")
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_invalid_query_param_rejected(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/call-graph?depth=99")
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


class TestAnalysisReads:
    def test_get_analysis(self, client: TestClient, stored_analysis: AnalysisRecord) -> None:
        payload = client.get("/api/analysis/test-analysis").json()
        assert payload["analysisId"] == "test-analysis"
        assert payload["file"]["name"] == "fixture.exe"
        assert payload["file"]["entryPoint"] == "0x401000"
        # `imageBase` - what a user needs to compute a `module+RVA` expression
        # for x64dbg/WinDbg's own "go to", since a static address alone isn't
        # portable to a separately-launched (ASLR-randomised) debugger - see
        # `FileInfo.image_base`'s docstring.
        assert payload["file"]["imageBase"] == "0x400000"
        assert payload["summary"]["functionCount"] == 5
        assert set(payload["callGraph"]) == {"nodes", "edges", "metadata"}

    def test_function_list(self, client: TestClient, stored_analysis: AnalysisRecord) -> None:
        payload = client.get("/api/analysis/test-analysis/functions").json()
        assert payload["total"] == 5
        # Entry point sorts first regardless of risk.
        assert payload["items"][0]["name"] == "main"

    def test_function_list_search_by_name(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get("/api/analysis/test-analysis/functions?search=multi").json()
        assert [item["name"] for item in payload["items"]] == ["multiply"]

    def test_function_list_search_by_address(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        for query in ("0x401300", "401300"):
            payload = client.get(
                f"/api/analysis/test-analysis/functions?search={query}"
            ).json()
            assert [item["name"] for item in payload["items"]] == ["multiply"]

    def test_function_list_min_risk_filter(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get(
            "/api/analysis/test-analysis/functions?minRiskScore=5"
        ).json()
        assert payload["total"] == 1
        assert payload["items"][0]["name"] == "multiply"

    def test_function_list_pagination(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        first = client.get("/api/analysis/test-analysis/functions?limit=2&offset=0").json()
        second = client.get("/api/analysis/test-analysis/functions?limit=2&offset=2").json()
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2
        assert {i["address"] for i in first["items"]} & {
            i["address"] for i in second["items"]
        } == set()

    def test_function_cfg(self, client: TestClient, stored_analysis: AnalysisRecord) -> None:
        payload = client.get("/api/analysis/test-analysis/functions/0x401100/cfg").json()
        assert payload["metadata"]["functionName"] == "calculate"
        assert len(payload["nodes"]) == 3
        kinds = {edge["kind"] for edge in payload["edges"]}
        assert {"TRUE", "FALSE"} <= kinds

    def test_function_cfg_accepts_bare_hex(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/functions/401100/cfg")
        assert response.status_code == 200

    def test_function_cfg_unknown_address(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/functions/0xdead/cfg")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "FUNCTION_NOT_FOUND"

    def test_api_graph(self, client: TestClient, stored_analysis: AnalysisRecord) -> None:
        payload = client.get("/api/analysis/test-analysis/api-graph").json()
        api_labels = {n["label"] for n in payload["nodes"] if n["kind"] == "api"}
        assert api_labels == {"printf", "CreateRemoteThread"}

    def test_call_graph_depth_query(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get(
            "/api/analysis/test-analysis/call-graph?depth=1&includeApis=false"
        ).json()
        assert payload["metadata"]["depth"] == 1
        assert len(payload["nodes"]) == 2

    def test_imports_endpoint(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get("/api/analysis/test-analysis/imports").json()
        assert {item["name"] for item in payload} == {"printf", "CreateRemoteThread"}
        injection = next(i for i in payload if i["name"] == "CreateRemoteThread")
        assert injection["capability"] == "process_injection"
        assert injection["callers"] == ["0x401300"]

    def test_export_markdown_endpoint(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/export.md")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        assert "attachment" in response.headers["content-disposition"]
        assert "fixture.exe" in response.text
        assert "multiply" in response.text
        assert "CreateRemoteThread" in response.text

    def test_export_markdown_unknown_analysis(self, client: TestClient) -> None:
        response = client.get("/api/analysis/does-not-exist/export.md")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"

    def test_export_function_markdown_endpoint(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/functions/0x401300/export.md")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        assert "attachment" in response.headers["content-disposition"]
        assert "# Function: multiply" in response.text
        assert "0x401300" in response.text
        # Only this one function's write-up, not the whole binary's - a
        # sibling function's name should not leak in.
        assert "calculate" not in response.text

    def test_export_function_markdown_unknown_function(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get("/api/analysis/test-analysis/functions/0x999999/export.md")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "FUNCTION_NOT_FOUND"

    def test_export_function_markdown_unknown_analysis(self, client: TestClient) -> None:
        response = client.get("/api/analysis/does-not-exist/functions/0x401300/export.md")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"

    def test_strings_endpoint(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get("/api/analysis/test-analysis/strings").json()
        assert any("example.invalid" in item["value"] for item in payload)

    def test_expand_endpoint(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get("/api/analysis/test-analysis/expand/0x401100").json()
        assert payload["metadata"]["found"] is True
        assert len(payload["nodes"]) >= 4

    def test_delete(self, client: TestClient, stored_analysis: AnalysisRecord) -> None:
        assert client.delete("/api/analysis/test-analysis").json() == {"deleted": True}
        assert client.get("/api/analysis/test-analysis").status_code == 404


class TestRiskDisclaimerData:
    def test_summary_exposes_reasons_for_high_risk_functions(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        payload = client.get("/api/analysis/test-analysis").json()
        top = payload["summary"]["highestRiskFunctions"]
        assert top and top[0]["name"] == "multiply"
        assert top[0]["riskScore"] == 10
