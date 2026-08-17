"""HTTP layer for the dynamic analysis router.

A `FakeDebugBridge` (from `tests.test_dynamic_session`) stands in for
pykd/dbgsrv/a real VM everywhere here - these tests only exercise
connect/breakpoint/step/continue/disconnect wiring and the structured error
envelope, never a real debug engine.
"""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.dependencies import get_repository
from app.dynamic.dependencies import get_session_store
from app.dynamic.session_store import SessionStore
from app.main import app
from app.models.analysis import AnalysisRecord
from app.services.analysis_service import _build_record
from tests.test_dynamic_session import FakeDebugBridge


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def stored_analysis(sample_artifacts: AnalysisArtifacts) -> AnalysisRecord:
    """Insert a synthetic analysis, exactly like test_api.py's own fixture,
    so both the risk-check and connect endpoints have something to look up."""
    record = _build_record(
        analysis_id="dyn-api-test",
        display_name="fixture.exe",
        sha256="0" * 64,
        size=4096,
        artifacts=sample_artifacts,
    )
    get_repository().save(record)
    yield record
    get_repository().delete("dyn-api-test")


@pytest.fixture
def fake_store():
    store = SessionStore(
        repository=get_repository(),
        capacity=4,
        idle_timeout_seconds=1800,
        bridge_factory=FakeDebugBridge,
        start_reaper=False,
    )
    app.dependency_overrides[get_session_store] = lambda: store
    yield store
    app.dependency_overrides.pop(get_session_store, None)
    store.shutdown()


class TestRiskCheck:
    def test_unknown_analysis_returns_structured_error(self, client: TestClient) -> None:
        response = client.get("/api/dynamic/risk-check/does-not-exist")
        assert response.status_code == 404
        payload = response.json()
        assert set(payload) == {"error"}
        assert payload["error"]["code"] == "DYNAMIC_ANALYSIS_NOT_FOUND"

    def test_known_analysis_returns_risk_bucket(
        self, client: TestClient, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.get(f"/api/dynamic/risk-check/{stored_analysis.analysis_id}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["riskBucket"] in {"none", "low", "medium", "high"}
        assert payload["sampleName"] == "fixture.exe"


class TestBreakpointStepContinueFlow:
    """Breakpoint/step/continue/disconnect wiring, exercised over a
    local-launch session (`POST /dynamic/sessions/local`) - the only
    session-creation route left after the remote "Connect to dbgsrv" one
    (`POST /dynamic/sessions`) was removed. None of this is local-launch-
    specific itself; it's the same generic session lifecycle the old,
    now-removed `TestConnectFlow` exercised over the remote route."""

    def _launch(self, client: TestClient, analysis_id: str) -> str:
        response = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        assert response.status_code == 200
        state = response.json()
        assert state["status"] == "attached"
        return state["sessionId"]

    def test_full_happy_path(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        session_id = self._launch(client, stored_analysis.analysis_id)

        bp = client.post(
            f"/api/dynamic/sessions/{session_id}/breakpoints",
            json={"staticAddress": "0x401000"},
        )
        assert bp.status_code == 200
        bp_id = bp.json()["id"]

        stepped = client.post(f"/api/dynamic/sessions/{session_id}/step", json={"mode": "into"})
        assert stepped.status_code == 200

        continued = client.post(f"/api/dynamic/sessions/{session_id}/continue")
        assert continued.status_code == 200

        removed = client.delete(f"/api/dynamic/sessions/{session_id}/breakpoints/{bp_id}")
        assert removed.status_code == 200
        assert removed.json() == {"deleted": True}

        disconnected = client.delete(f"/api/dynamic/sessions/{session_id}")
        assert disconnected.status_code == 200
        assert disconnected.json() == {"deleted": True}

        gone = client.get(f"/api/dynamic/sessions/{session_id}/state")
        assert gone.status_code == 404
        assert gone.json()["error"]["code"] == "DYNAMIC_SESSION_NOT_FOUND"

    def test_invalid_breakpoint_address_rejected(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        session_id = self._launch(client, stored_analysis.analysis_id)

        response = client.post(
            f"/api/dynamic/sessions/{session_id}/breakpoints",
            json={"staticAddress": "not-an-address"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DYNAMIC_INVALID_ADDRESS"

    def test_runtime_breakpoint_sets_directly_no_rebase(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        """`/breakpoints/runtime` - for addresses outside the sample's own
        module (e.g. ntdll rows from the live-disassembly fallback) - see
        `DebugSession.set_runtime_breakpoint`'s docstring."""
        session_id = self._launch(client, stored_analysis.analysis_id)

        bp = client.post(
            f"/api/dynamic/sessions/{session_id}/breakpoints/runtime",
            json={"runtimeAddress": "0x7ffc20730aee"},
        )
        assert bp.status_code == 200
        body = bp.json()
        assert body["staticAddress"] is None
        assert body["runtimeAddress"] == "0x7ffc20730aee"

        state = client.get(f"/api/dynamic/sessions/{session_id}/state").json()
        matching = next(b for b in state["breakpoints"] if b["id"] == body["id"])
        assert matching["staticAddress"] is None

    def test_invalid_runtime_breakpoint_address_rejected(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        session_id = self._launch(client, stored_analysis.analysis_id)

        response = client.post(
            f"/api/dynamic/sessions/{session_id}/breakpoints/runtime",
            json={"runtimeAddress": "not-an-address"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DYNAMIC_INVALID_ADDRESS"

    def test_unknown_session_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.get("/api/dynamic/sessions/does-not-exist/state")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_SESSION_NOT_FOUND"


class TestRegisterWrite:
    """`POST /dynamic/sessions/{id}/registers/{name}` - the first real
    Phase 2 (patch-and-continue) hook. See
    `DebugSession.set_register`'s docstring."""

    def test_happy_path_updates_snapshot(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]

        response = client.post(
            f"/api/dynamic/sessions/{session_id}/registers/eax", json={"value": "0xdeadbeef"}
        )
        assert response.status_code == 200
        registers = {r["name"]: r["value"] for r in response.json()["registers"]}
        assert registers["eax"] == "0xdeadbeef"

    def test_invalid_value_rejected(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]

        response = client.post(
            f"/api/dynamic/sessions/{session_id}/registers/eax", json={"value": "not-a-number"}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DYNAMIC_INVALID_ADDRESS"

    def test_unknown_session_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/does-not-exist/registers/eax", json={"value": "0x1"}
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_SESSION_NOT_FOUND"


class TestMemoryDump:
    """`GET /dynamic/sessions/{id}/memory` - the "Dump"/`db` capability every
    other debugger has. See `DebugSession.dump_memory`'s docstring."""

    def test_happy_path(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]
        session = fake_store.get(session_id)
        session._bridge.memory[0x401000] = b"\x90\x90\xc3"  # noqa: SLF001

        response = client.get(
            f"/api/dynamic/sessions/{session_id}/memory?address=0x401000&size=3"
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["address"] == "0x401000"
        assert payload["size"] == 3
        assert payload["bytesHex"] == "9090c3"

    def test_invalid_address_rejected(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]

        response = client.get(f"/api/dynamic/sessions/{session_id}/memory?address=not-an-address")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DYNAMIC_INVALID_ADDRESS"

    def test_unknown_session_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.get("/api/dynamic/sessions/does-not-exist/memory?address=0x401000")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_SESSION_NOT_FOUND"

    def test_size_is_clamped(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]

        response = client.get(
            f"/api/dynamic/sessions/{session_id}/memory?address=0x401000&size=999999"
        )
        assert response.status_code == 200
        assert response.json()["size"] == 4096


class TestLiveDisassembly:
    """`GET /dynamic/sessions/{id}/disassembly` - the assembly view's
    fallback when the debugger's PC is outside the one module the static
    analyzer covers. See `DebugSession.disassemble_current`'s docstring."""

    def test_happy_path(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session_id = connect.json()["sessionId"]

        response = client.get(f"/api/dynamic/sessions/{session_id}/disassembly?count=5")
        assert response.status_code == 200
        payload = response.json()
        assert payload["runtimeAddress"]
        assert payload["moduleLabel"] == "sample.exe+0x1234"
        assert len(payload["instructions"]) == 5
        assert payload["instructions"][0]["mnemonic"] == "nop"

    def test_unknown_session_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.get("/api/dynamic/sessions/does-not-exist/disassembly")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_SESSION_NOT_FOUND"

    def test_unsupported_bridge_returns_409(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        connect = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": r"C:\tools\sample.exe"},
        )
        session = fake_store.get(connect.json()["sessionId"])
        session._bridge.disassemble_unsupported = True  # noqa: SLF001 - test-only reach-through

        response = client.get(f"/api/dynamic/sessions/{session.session_id}/disassembly")
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "DYNAMIC_DISASSEMBLE_UNSUPPORTED"


class TestLocalLaunch:
    """`POST /dynamic/sessions/local` - the one endpoint that makes the app
    execute a binary directly. See client.py's `create_and_attach_local`
    docstring for the full rationale."""

    def test_happy_path(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/local",
            json={
                "analysisId": stored_analysis.analysis_id,
                "commandLine": r"C:\tools\sample.exe",
            },
        )
        assert response.status_code == 200
        state = response.json()
        assert state["status"] == "attached"
        assert state["sessionId"]

    def test_unknown_analysis_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": "does-not-exist", "commandLine": "sample.exe"},
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_ANALYSIS_NOT_FOUND"

    def test_launch_failure_has_no_fallback(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        original_factory = fake_store._bridge_factory  # noqa: SLF001 - test-only reach-through

        def failing_factory() -> FakeDebugBridge:
            bridge = original_factory()
            bridge.fail_local_launch = True
            return bridge

        fake_store._bridge_factory = failing_factory  # noqa: SLF001

        response = client.post(
            "/api/dynamic/sessions/local",
            json={"analysisId": stored_analysis.analysis_id, "commandLine": "bad.exe"},
        )
        assert response.status_code == 502
        assert response.json()["error"]["code"] == "DYNAMIC_CONNECT_FAILED"


def _minimal_pe_bytes() -> bytes:
    """Same minimal MZ/PE byte pattern `test_security.py` uses."""
    header = bytearray(b"\x00" * 0x100)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\x00\x00"
    return bytes(header)


class TestLocalLaunchFromUpload:
    """`POST /dynamic/sessions/local/upload` - re-uploads the exact bytes the
    frontend still holds from the original static-analysis upload (which is
    already deleted by this point) and stages+executes a fresh copy. See
    `app/dynamic/local_upload.py` and `api.py`'s docstring for the rationale.
    """

    def test_happy_path(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/local/upload",
            data={"analysis_id": stored_analysis.analysis_id},
            files={"file": ("sample.exe", io.BytesIO(_minimal_pe_bytes()), "application/octet-stream")},
        )
        assert response.status_code == 200
        state = response.json()
        assert state["status"] == "attached"
        assert state["sessionId"]

    def test_non_pe_upload_rejected(
        self, client: TestClient, fake_store: SessionStore, stored_analysis: AnalysisRecord
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/local/upload",
            data={"analysis_id": stored_analysis.analysis_id},
            files={"file": ("fake.exe", io.BytesIO(b"not a pe" * 10), "application/octet-stream")},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "NOT_A_PE"

    def test_unknown_analysis_returns_404(
        self, client: TestClient, fake_store: SessionStore
    ) -> None:
        response = client.post(
            "/api/dynamic/sessions/local/upload",
            data={"analysis_id": "does-not-exist"},
            files={"file": ("sample.exe", io.BytesIO(_minimal_pe_bytes()), "application/octet-stream")},
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "DYNAMIC_ANALYSIS_NOT_FOUND"
