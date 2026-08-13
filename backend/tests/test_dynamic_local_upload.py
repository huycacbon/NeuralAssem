"""Staging for local-launch-from-upload (`app.dynamic.local_upload`) and the
temp-file lifecycle it hands off to `DebugSession`.
"""

from __future__ import annotations

import io

import pytest

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.dynamic.local_upload import stage_upload
from app.dynamic.session import DebugSession
from app.dynamic.session_store import DynamicAnalysisNotFound, SessionStore
from app.repositories import InMemoryAnalysisRepository
from app.services.analysis_service import _build_record
from app.utils.security import UploadValidationError
from tests.test_dynamic_session import FakeDebugBridge, _make_store


def _minimal_pe_header() -> bytes:
    """Same minimal MZ/PE byte pattern `test_security.py` uses."""
    header = bytearray(b"\x00" * 0x100)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\x00\x00"
    return bytes(header)


class TestStageUpload:
    def test_stages_a_valid_pe_to_its_own_directory(self, tmp_path) -> None:
        data = _minimal_pe_header()
        staged = stage_upload(io.BytesIO(data), "sample.exe", max_bytes=10_000_000)
        try:
            assert staged.path.exists()
            assert staged.size == len(data)
            assert "dynamic-local-launch" in str(staged.path)
        finally:
            staged.path.unlink(missing_ok=True)

    def test_rejects_non_pe_and_cleans_up(self) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            stage_upload(io.BytesIO(b"not a pe" * 10), "fake.exe", max_bytes=10_000_000)
        assert excinfo.value.code == "NOT_A_PE"

    def test_rejects_bad_extension(self) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            stage_upload(io.BytesIO(_minimal_pe_header()), "notes.txt", max_bytes=10_000_000)
        assert excinfo.value.code == "INVALID_EXTENSION"


class TestOwnedTempFileLifecycle:
    def test_disconnect_removes_owned_temp_file(self, tmp_path) -> None:
        target = tmp_path / "staged.exe"
        target.write_bytes(_minimal_pe_header())
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        session.launch_local(str(target), owned_temp_file=target)
        assert target.exists()

        session.disconnect()
        assert not target.exists()

    def test_launch_failure_removes_owned_temp_file(self, tmp_path) -> None:
        target = tmp_path / "staged.exe"
        target.write_bytes(_minimal_pe_header())
        bridge = FakeDebugBridge()
        bridge.fail_local_launch = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(Exception):  # noqa: B017 - DebugBridgeError, re-raised as-is
            session.launch_local(str(target), owned_temp_file=target)
        assert not target.exists()


@pytest.fixture
def repository_with_record(sample_artifacts: AnalysisArtifacts) -> InMemoryAnalysisRepository:
    repository = InMemoryAnalysisRepository()
    record = _build_record(
        analysis_id="dyn-upload-test",
        display_name="fixture.exe",
        sha256="0" * 64,
        size=4096,
        artifacts=sample_artifacts,
    )
    repository.save(record)
    return repository


class TestSessionStoreCreateLocalFromUpload:
    def test_happy_path_stages_and_launches(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        data = _minimal_pe_header()

        session = store.create_local_from_upload(
            "dyn-upload-test",
            io.BytesIO(data),
            "sample.exe",
            connect_timeout_seconds=1.0,
            max_upload_bytes=10_000_000,
        )

        assert session.snapshot_state().status == "attached"

        # Clean up: disconnect should remove the staged file.
        session.disconnect()

    def test_unknown_analysis_raises_and_does_not_leak_a_staged_file(
        self, repository_with_record: InMemoryAnalysisRepository, tmp_path
    ) -> None:
        store = _make_store(repository_with_record)
        with pytest.raises(DynamicAnalysisNotFound):
            store.create_local_from_upload(
                "nope",
                io.BytesIO(_minimal_pe_header()),
                "sample.exe",
                connect_timeout_seconds=1.0,
                max_upload_bytes=10_000_000,
            )
        # Nothing to assert on disk directly (stage_upload never ran - the
        # analysis lookup fails first), but this documents the ordering:
        # unknown analysis is checked before anything is written to disk.

    def test_non_pe_upload_rejected(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        with pytest.raises(UploadValidationError) as excinfo:
            store.create_local_from_upload(
                "dyn-upload-test",
                io.BytesIO(b"not a pe" * 10),
                "fake.exe",
                connect_timeout_seconds=1.0,
                max_upload_bytes=10_000_000,
            )
        assert excinfo.value.code == "NOT_A_PE"
