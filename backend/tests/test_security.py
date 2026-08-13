"""Upload validation, hashing, and path-traversal defence."""

from __future__ import annotations

import hashlib
import io

import pytest

from app.utils.security import (
    DEFAULT_MAX_UPLOAD_BYTES,
    UploadValidationError,
    compute_sha256,
    looks_like_pe,
    make_temp_path,
    sanitize_display_name,
    sha256_bytes,
    stream_to_temp_file,
    validate_extension,
    validate_size,
)


class TestValidateExtension:
    @pytest.mark.parametrize("name", ["sample.exe", "SAMPLE.EXE", "lib.dll", "a.DlL"])
    def test_accepts_pe_extensions(self, name: str) -> None:
        assert validate_extension(name) in {".exe", ".dll"}

    @pytest.mark.parametrize(
        "name", ["sample.txt", "sample", "sample.exe.txt", "script.ps1", "a.sys", ""]
    )
    def test_rejects_everything_else(self, name: str) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            validate_extension(name)
        assert excinfo.value.code == "INVALID_EXTENSION"

    def test_rejects_none(self) -> None:
        with pytest.raises(UploadValidationError):
            validate_extension(None)


class TestSanitizeDisplayName:
    @pytest.mark.parametrize(
        "raw",
        [
            "../../../../etc/passwd.exe",
            "..\\..\\Windows\\System32\\evil.exe",
            "C:\\Windows\\System32\\evil.exe",
            "/absolute/path/evil.exe",
        ],
    )
    def test_strips_every_directory_component(self, raw: str) -> None:
        cleaned = sanitize_display_name(raw)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert ".." not in cleaned
        assert cleaned.endswith("evil.exe") or cleaned == "passwd.exe"

    def test_replaces_unsafe_characters(self) -> None:
        assert sanitize_display_name('we"ird<>|.exe') == "we_ird___.exe"

    def test_empty_name_gets_placeholder(self) -> None:
        assert sanitize_display_name(None) == "unnamed"
        assert sanitize_display_name("...") == "unnamed"

    def test_temp_path_never_contains_user_name(self, tmp_path) -> None:
        path = make_temp_path(".exe", tmp_path)
        assert "evil" not in path.name
        assert path.suffix == ".exe"
        assert path.parent == tmp_path


class TestValidateSize:
    def test_accepts_normal_size(self) -> None:
        validate_size(1024)

    def test_rejects_zero(self) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            validate_size(0)
        assert excinfo.value.code == "EMPTY_FILE"

    def test_rejects_oversize(self) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            validate_size(DEFAULT_MAX_UPLOAD_BYTES + 1)
        assert excinfo.value.code == "FILE_TOO_LARGE"

    def test_respects_custom_limit(self) -> None:
        validate_size(100, max_bytes=100)
        with pytest.raises(UploadValidationError):
            validate_size(101, max_bytes=100)


class TestSha256:
    def test_matches_hashlib(self, tmp_path) -> None:
        data = b"binary graph analyzer" * 1000
        path = tmp_path / "sample.bin"
        path.write_bytes(data)
        assert compute_sha256(path) == hashlib.sha256(data).hexdigest()
        assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()

    def test_empty_file(self, tmp_path) -> None:
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")
        assert compute_sha256(path) == hashlib.sha256(b"").hexdigest()


def _minimal_pe_header() -> bytes:
    """Smallest byte pattern that satisfies the MZ/PE magic check."""
    header = bytearray(b"\x00" * 0x100)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\x00\x00"
    return bytes(header)


class TestLooksLikePe:
    def test_accepts_valid_header(self) -> None:
        assert looks_like_pe(_minimal_pe_header())

    def test_rejects_elf(self) -> None:
        assert not looks_like_pe(b"\x7fELF" + b"\x00" * 0x100)

    def test_rejects_text(self) -> None:
        assert not looks_like_pe(b"hello world" * 20)

    def test_rejects_truncated(self) -> None:
        assert not looks_like_pe(b"MZ")


class TestStreamToTempFile:
    def test_writes_and_hashes(self, tmp_path) -> None:
        data = _minimal_pe_header()
        path, size, digest, header = stream_to_temp_file(
            io.BytesIO(data), ".exe", directory=tmp_path
        )
        try:
            assert path.exists()
            assert size == len(data)
            assert digest == hashlib.sha256(data).hexdigest()
            assert header.startswith(b"MZ")
        finally:
            path.unlink(missing_ok=True)

    def test_enforces_cap_and_removes_partial_file(self, tmp_path) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            stream_to_temp_file(
                io.BytesIO(b"A" * 5000), ".exe", max_bytes=1000, directory=tmp_path
            )
        assert excinfo.value.code == "FILE_TOO_LARGE"
        # The partially written file must not survive the failure.
        assert list(tmp_path.glob("*.exe")) == []

    def test_rejects_empty_stream(self, tmp_path) -> None:
        with pytest.raises(UploadValidationError) as excinfo:
            stream_to_temp_file(io.BytesIO(b""), ".exe", directory=tmp_path)
        assert excinfo.value.code == "EMPTY_FILE"
        assert list(tmp_path.glob("*.exe")) == []
