"""Health and capability probe."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.config import settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, Any]:
    """Liveness probe. Also reports whether angr imported successfully so the
    frontend can show a clear message instead of failing on the first upload."""
    try:
        import angr  # noqa: F401

        angr_available = True
        angr_error: str | None = None
    except Exception as exc:  # pragma: no cover - only on a broken install
        angr_available = False
        angr_error = str(exc)

    return {
        "status": "ok" if angr_available else "degraded",
        "angrAvailable": angr_available,
        "angrError": angr_error,
        "maxUploadMb": settings.max_upload_mb,
        "analysisTimeoutSeconds": settings.analysis_timeout_seconds,
        "environment": settings.environment,
    }
