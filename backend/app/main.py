"""FastAPI application factory.

Kept thin on purpose: routing lives in ``app.api``, analysis in ``app.analyzers``
and ``app.services``. This module only wires middleware and error handling.

Nothing here (or anywhere else) executes an uploaded sample, and no analysis
runs at startup.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import analysis, health
from app.config import settings
from app.dynamic.api import router as dynamic_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
# angr is extremely chatty at INFO and would drown out our own logs.
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

def _resolve_frontend_dist() -> Path | None:
    """Find the built frontend (`frontend/dist`), if there is one to serve.

    Tried in order:
    1. `BGA_FRONTEND_DIST_DIR` - set explicitly by the desktop launcher, which
       knows exactly where it unpacked the bundled frontend.
    2. The dev-repo-relative path (`main.py` -> `app/` -> `backend/` ->
       `frontend/dist`), so `npm run build` output is picked up automatically
       without any configuration during local development.

    Returns `None` (never raises) when nothing is found - the API still works
    standalone, e.g. against a separately-run `npm run dev` frontend.
    """
    if settings.frontend_dist_dir is not None:
        candidate = settings.frontend_dist_dir
        if (candidate / "index.html").is_file():
            return candidate
        logger.warning(
            "BGA_FRONTEND_DIST_DIR=%s không chứa index.html, bỏ qua", candidate
        )

    dev_candidate = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if (dev_candidate / "index.html").is_file():
        return dev_candidate

    return None


DESCRIPTION = """
Phân tích **tĩnh** file PE (.exe/.dll) bằng angr và trực quan hóa kết quả
dưới dạng đồ thị tương tác.

Công cụ **không bao giờ thực thi** file mẫu: binary chỉ được đọc như dữ liệu
và disassembly. Không có dữ liệu nào được gửi ra Internet.
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown. Note what is deliberately absent: no sample is loaded
    and no analysis is run at startup."""
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    logger.info(
        "Binary Graph Analyzer sẵn sàng (env=%s, upload tối đa %d MB)",
        settings.environment,
        settings.max_upload_mb,
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Binary Graph Analyzer",
        description=DESCRIPTION,
        version="0.1.0",
        docs_url="/docs",
        lifespan=lifespan,
    )

    # Local frontend only. The backend is not meant to be exposed to a network.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(analysis.router, prefix="/api")
    # Dynamic analysis (Phase 1, debug client only - see app/dynamic/__init__.py
    # for the safety constraints this router upholds).
    app.include_router(dynamic_router, prefix="/api")

    # Serve the built frontend, if present, from the same origin as the API -
    # this is what lets the desktop build be one process on one port with no
    # CORS to configure. Mounted *last*: Starlette checks routes in
    # registration order, so the `/api/*` routes above always win over this
    # catch-all, and only unmatched paths (the SPA's own assets, or `/` for
    # index.html) fall through to it.
    frontend_dist = _resolve_frontend_dist()
    if frontend_dist is not None:
        logger.info("Phục vụ frontend đã build từ %s", frontend_dist)
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
    else:
        logger.info("Không tìm thấy frontend đã build - chỉ chạy API (chế độ dev)")

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Normalise every HTTP error into ``{"error": {...}}``."""
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": f"HTTP_{exc.status_code}",
                    "message": str(detail),
                    "details": None,
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Tham số request không hợp lệ",
                    "details": None if settings.is_production else str(exc.errors()),
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # A malformed binary must never take the server down.
        logger.exception("Lỗi không xử lý được tại %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Lỗi nội bộ của server",
                    "details": None
                    if settings.is_production
                    else f"{type(exc).__name__}: {exc}",
                }
            },
        )

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )
