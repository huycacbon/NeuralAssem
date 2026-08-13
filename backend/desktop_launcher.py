"""Desktop entry point.

Opens the built frontend (`frontend_dist/`) in a native window (pywebview /
WebView2 on Windows - no visible browser chrome, no tabs, no address bar) and
wires it up to `app.desktop_bridge.DesktopApi` as the JS<->Python bridge
(`window.pywebview.api.*`). Closing the window ends the process.

Unlike the old version of this file, **no FastAPI/uvicorn server runs here
and no port is opened for the API**: every analysis operation is an
in-process Python call reached through pywebview's `js_api`, not an HTTP
request. The only local server involved is pywebview's own built-in static
file server (`http_server=True`, a small bundled Bottle app), used purely to
serve the pre-built `frontend_dist/` assets to the window - it carries no API
routes and never touches the uploaded sample. That is needed because Chromium
(and so WebView2) blocks ES module scripts - which is what a Vite build
emits - from loading over a bare `file://` URL; pywebview's own local static
server is the standard, documented way around that restriction.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# The packaged desktop build runs this script under a Python "embeddable"
# distribution, which uses a `._pth` file to fully control `sys.path` - unlike
# a normal install, it does NOT auto-add the running script's own directory,
# and it ignores PYTHONPATH too. Add it explicitly so `app` (this file's
# sibling package) is importable regardless of how this script was launched.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import webview  # noqa: E402

from app.desktop_bridge import DesktopApi  # noqa: E402

logger = logging.getLogger(__name__)

WINDOW_TITLE = "Binary Graph Analyzer"


def _frontend_index() -> Path:
    """Locate the built frontend's `index.html`.

    Layout produced by `scripts/build_desktop_app.ps1`:
    `BinaryGraphAnalyzer/{backend/desktop_launcher.py, frontend_dist/}` - this
    file's parent is `backend/`, so `frontend_dist/` is a sibling of that.
    """
    candidate = Path(__file__).resolve().parent.parent / "frontend_dist" / "index.html"
    if not candidate.is_file():
        raise RuntimeError(
            f"Không tìm thấy frontend đã build tại {candidate} - "
            "bạn đã giải nén đầy đủ bộ cài đặt chưa?"
        )
    return candidate


def main() -> None:
    logging.basicConfig(level=logging.WARNING)

    index_html = _frontend_index()

    webview.create_window(
        WINDOW_TITLE,
        url=str(index_html),
        js_api=DesktopApi(),
        width=1440,
        height=900,
        min_size=(1024, 640),
    )
    # `http_server=True`: serve `index_html`'s directory through pywebview's
    # own bundled static server instead of a bare `file://` URL (see module
    # docstring for why). This is the only local server in the desktop build,
    # it is not our FastAPI backend, and it has no `/api/*` routes at all.
    webview.start(http_server=True)


if __name__ == "__main__":
    main()
