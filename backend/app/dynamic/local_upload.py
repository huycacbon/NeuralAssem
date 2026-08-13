"""Staging for local-launch-from-upload: writes a freshly re-uploaded file to
its own temp location so `ComtypesDebugBridge.create_and_attach_local` has a
real path to point at.

This exists because the static analyzer's own upload (`file_service.py`)
deletes its temp file immediately after analysis - by the time the Debug
button is clickable, nothing is left on disk to reuse. The frontend still
holds the original `File` object in memory from the initial upload, though,
and re-sends those same bytes here.

Deliberately reuses `app.utils.security`'s existing, already-reviewed
validation/streaming helpers (a leaf utils module, not on the
one-directional-import forbidden list) rather than reimplementing upload
handling - same extension check, same streamed size cap, same PE magic-byte
check, same UUID-named temp path convention as the static analyzer's own
upload path. The only difference is the destination directory, kept
separate so the two upload flows never share files on disk.

See `app.dynamic.debug_bridge.client.DebugBridge.create_and_attach_local`'s
docstring and `docs/dynamic-analysis-spec.md`'s local-launch addenda for why
this capability exists at all - this module only prepares a file, it never
executes anything itself.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import BinaryIO, NamedTuple

from app.utils.security import (
    UploadValidationError,
    looks_like_pe,
    safe_unlink,
    stream_to_temp_file,
    validate_extension,
)


class StagedUpload(NamedTuple):
    path: Path
    size: int
    sha256: str


def _local_launch_dir() -> Path:
    # Deliberately a different directory from the static analyzer's own
    # `settings.upload_dir` - keeps the two upload flows physically separate
    # on disk, easier to audit/clean up independently.
    return Path(tempfile.gettempdir()) / "binary-graph-analyzer" / "dynamic-local-launch"


def stage_upload(stream: BinaryIO, filename: str | None, max_bytes: int) -> StagedUpload:
    """Validate and stream `stream` to a fresh temp file, returning where it
    landed. Raises `UploadValidationError` (same type/error-code shape the
    static analyzer's own upload path already uses) on a bad extension,
    oversized body, or a file that doesn't look like a PE.

    The caller owns the returned path - it is not deleted here. See
    `DebugSession`'s `_owned_temp_file` cleanup (on launch failure and on
    `disconnect()`) for the deletion side.
    """
    extension = validate_extension(filename)
    path, size, sha256, header = stream_to_temp_file(
        stream, extension, max_bytes=max_bytes, directory=_local_launch_dir()
    )

    if not looks_like_pe(header):
        safe_unlink(path)
        raise UploadValidationError(
            code="NOT_A_PE",
            message="File không phải PE hợp lệ",
            details="Kiểm tra DOS/PE header thất bại",
        )

    return StagedUpload(path=path, size=size, sha256=sha256)
