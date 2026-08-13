"""Upload handling: validate, persist to a UUID temp path, hash, clean up.

The temp file's lifetime is scoped by :func:`received_upload`, which deletes it
in a ``finally`` block - on success, on analysis failure, and on cancellation.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from app.config import settings
from app.utils.security import (
    UploadValidationError,
    compute_sha256,
    looks_like_pe,
    safe_unlink,
    sanitize_display_name,
    stream_to_temp_file,
    validate_extension,
    validate_size,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class StoredUpload:
    """A validated upload sitting in a temp file, ready to be analysed."""

    path: Path
    display_name: str
    size: int
    sha256: str
    extension: str
    header: bytes

    def read_bytes(self) -> bytes:
        return self.path.read_bytes()


@contextmanager
def received_upload(
    stream: BinaryIO,
    filename: str | None,
    declared_size: int | None = None,
) -> Iterator[StoredUpload]:
    """Validate and store an upload, guaranteeing temp-file cleanup.

    Raises :class:`UploadValidationError` for anything the caller should turn
    into a 400. The uploaded name is only used for display; the on-disk path is
    always ``<tempdir>/<uuid><ext>``.
    """
    extension = validate_extension(filename)
    display_name = sanitize_display_name(filename)

    if declared_size is not None:
        validate_size(declared_size, settings.max_upload_bytes)

    path: Path | None = None
    try:
        path, size, sha256, header = stream_to_temp_file(
            stream,
            extension=extension,
            max_bytes=settings.max_upload_bytes,
            directory=settings.upload_dir,
        )

        if not looks_like_pe(header):
            raise UploadValidationError(
                code="NOT_A_PE",
                message="File không phải định dạng PE hợp lệ",
                details="Thiếu chữ ký MZ/PE ở header",
            )

        # Deliberately logs the hash and size only - never any file content.
        logger.info("Nhận upload %s (%d bytes, sha256=%s)", display_name, size, sha256[:16])

        yield StoredUpload(
            path=path,
            display_name=display_name,
            size=size,
            sha256=sha256,
            extension=extension,
            header=header,
        )
    finally:
        safe_unlink(path)


def hash_file(path: Path) -> str:
    """Public wrapper so tests and callers do not import ``utils.security``."""
    return compute_sha256(path)
