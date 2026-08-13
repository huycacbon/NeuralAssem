"""Upload validation and safe temp-file handling.

Hard rules enforced here (see README "Safety"):
  * only ``.exe`` / ``.dll`` extensions are accepted;
  * the user-supplied filename is NEVER used to build a path - a UUID is;
  * uploads are size-capped while streaming, so a huge body cannot fill the disk;
  * the temp file is always removed by the caller's ``finally`` block.

Nothing in this module (or anywhere else in the backend) executes the sample.
The binary is only ever opened for reading as data.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import BinaryIO, Final

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset({".exe", ".dll"})
DEFAULT_MAX_UPLOAD_BYTES: Final[int] = 100 * 1024 * 1024  # 100 MB
_CHUNK_SIZE: Final[int] = 1024 * 1024

# PE files start with "MZ" and contain a PE signature at the offset stored at 0x3C.
_MZ_MAGIC: Final[bytes] = b"MZ"
_PE_MAGIC: Final[bytes] = b"PE\x00\x00"

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._\- ]")


class UploadValidationError(ValueError):
    """Raised when an upload fails a validation rule.

    ``code`` is surfaced to the frontend inside the structured error envelope.
    """

    def __init__(self, code: str, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def sanitize_display_name(filename: str | None) -> str:
    """Reduce a user-supplied filename to something safe to echo back in JSON.

    The result is display-only - it is never joined onto a filesystem path.
    Any directory component is dropped, which neutralises ``../`` traversal and
    Windows drive-absolute names such as ``C:\\Windows\\System32\\x.dll``.
    """
    if not filename:
        return "unnamed"

    # Strip both separators explicitly: a POSIX server still receives Windows
    # paths from the browser, and PurePath alone would not split on "\\".
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    base = base.split(":")[-1]  # drop "C:" style drive prefixes
    base = _UNSAFE_NAME_CHARS.sub("_", base).strip()
    base = base.lstrip(".") or "unnamed"
    return base[:255]


def validate_extension(filename: str | None) -> str:
    """Validate the file extension and return it (lowercased, with the dot)."""
    safe_name = sanitize_display_name(filename)
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise UploadValidationError(
            code="INVALID_EXTENSION",
            message=f"Chỉ chấp nhận file {allowed}",
            details=f"Nhận được phần mở rộng: {extension or '(không có)'}",
        )
    return extension


def validate_size(size: int, max_bytes: int = DEFAULT_MAX_UPLOAD_BYTES) -> None:
    """Validate a known content length against the cap."""
    if size <= 0:
        raise UploadValidationError(
            code="EMPTY_FILE",
            message="File rỗng hoặc không đọc được",
            details=f"size={size}",
        )
    if size > max_bytes:
        raise UploadValidationError(
            code="FILE_TOO_LARGE",
            message=f"File vượt quá giới hạn {max_bytes // (1024 * 1024)} MB",
            details=f"size={size} bytes",
        )


def looks_like_pe(header: bytes) -> bool:
    """Cheap magic-byte check performed before angr is even loaded.

    Only reads the DOS header and the e_lfanew pointer - no code is interpreted.
    """
    if len(header) < 0x40 or not header.startswith(_MZ_MAGIC):
        return False

    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 4 > len(header):
        # Header truncated in our sample window; the MZ magic is still a decent
        # signal, so let angr make the final call rather than rejecting outright.
        return True
    return header[pe_offset : pe_offset + 4] == _PE_MAGIC


def compute_sha256(path: Path) -> str:
    """Stream a file through SHA-256 without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_temp_path(extension: str, directory: Path | None = None) -> Path:
    """Build a UUID-based temp path. The upload's own name is never used."""
    base = directory or Path(tempfile.gettempdir()) / "binary-graph-analyzer"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{uuid.uuid4().hex}{extension}"


def stream_to_temp_file(
    source: BinaryIO,
    extension: str,
    max_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    directory: Path | None = None,
) -> tuple[Path, int, str, bytes]:
    """Copy an upload stream to a UUID-named temp file with a hard size cap.

    Returns ``(path, size, sha256, header_bytes)``. The caller owns the returned
    path and must delete it in a ``finally`` block - see ``file_service``.
    On any failure the partial file is removed before the error propagates.
    """
    target = make_temp_path(extension, directory)
    digest = hashlib.sha256()
    total = 0
    header = b""

    try:
        with target.open("wb") as handle:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break

                total += len(chunk)
                if total > max_bytes:
                    raise UploadValidationError(
                        code="FILE_TOO_LARGE",
                        message=(
                            f"File vượt quá giới hạn {max_bytes // (1024 * 1024)} MB"
                        ),
                        details="Quá trình upload đã bị hủy giữa chừng",
                    )

                if len(header) < 0x1000:
                    header += chunk[: 0x1000 - len(header)]

                digest.update(chunk)
                handle.write(chunk)
    except BaseException:
        safe_unlink(target)
        raise

    if total == 0:
        safe_unlink(target)
        raise UploadValidationError(
            code="EMPTY_FILE",
            message="File rỗng hoặc không đọc được",
            details="Đã nhận 0 byte",
        )

    return target, total, digest.hexdigest(), header


def safe_unlink(path: Path | None) -> None:
    """Delete a temp file, never raising. Called from ``finally`` blocks."""
    if path is None:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:  # pragma: no cover - platform/permission dependent
        # Deliberately logs only the path, never the binary's content.
        logger.warning("Không xóa được file tạm %s: %s", path.name, exc)
