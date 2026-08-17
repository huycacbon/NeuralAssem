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

#: Microsoft's own documented client id for detecting the WebView2 Runtime
#: (Evergreen distribution) via the registry - see
#: https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution#detect-if-a-suitable-webview2-runtime-is-already-installed
_WEBVIEW2_CLIENT_ID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
_WEBVIEW2_DOWNLOAD_URL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"


def _webview2_runtime_installed() -> bool:
    """Best-effort check for the WebView2 Runtime on Windows.

    Why this exists: pywebview's default/`edgechromium` backend does NOT
    raise when the runtime is missing - it silently falls back to the
    decades-old MSHTML/Trident (IE) engine instead (the "MSHTML is
    deprecated" warning this app's users have hit). That engine cannot run
    this app at all: Vite emits `<script type="module">`, which MSHTML has
    never supported, so the window opens blank/broken with no error anywhere
    - exactly the confusing failure mode this check exists to turn into a
    clear message instead. Checked before `webview.start()` so the user
    never even sees the broken window.

    Registry-based, not a WebView2 API call, so it needs no extra dependency
    beyond the stdlib `winreg` - the same detection method Microsoft's own
    docs recommend for exactly this purpose. Per-machine and per-user
    install locations both count; false-negatives are possible in principle
    (e.g. a future distribution channel Microsoft's docs don't cover yet),
    which is why `main()` still passes `gui="edgechromium"` explicitly on
    top of this check, turning any such gap into a loud failure instead of
    a silent MSHTML fallback.
    """
    import winreg

    for hive, subkey in (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                version, _ = winreg.QueryValueEx(key, "pv")
                if version and version != "0.0.0.0":
                    return True
        except OSError:
            continue
    return False


def _fatal_message_box(text: str) -> None:
    """Native message box for failures that happen before (or instead of)
    the webview window - the only UI surface available at that point, since
    logging alone is invisible to a user who launched this by double-clicking
    the .exe (no attached console)."""
    import ctypes

    MB_ICONERROR = 0x10
    ctypes.windll.user32.MessageBoxW(0, text, WINDOW_TITLE, MB_ICONERROR)


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

    if sys.platform == "win32" and not _webview2_runtime_installed():
        _fatal_message_box(
            "Không tìm thấy Microsoft Edge WebView2 Runtime trên máy này.\n\n"
            f"{WINDOW_TITLE} cần WebView2 để hiển thị giao diện - phần lớn Windows 10/11 đã có "
            "sẵn, nhưng một số máy/máy ảo (ví dụ Windows 10 22H2 cài tối giản) thì chưa. Không có "
            "nó, cửa sổ sẽ mở ra trắng/hỏng vì tự động rớt xuống engine MSHTML đã bị khai tử thay "
            "vì báo lỗi rõ ràng.\n\n"
            f"Cài Evergreen Bootstrapper (nhỏ, cần internet lúc cài) rồi mở lại ứng dụng:\n"
            f"{_WEBVIEW2_DOWNLOAD_URL}"
        )
        sys.exit(1)

    # pywebview blocks all downloads by default (ALLOW_DOWNLOADS=False) on
    # every backend (EdgeChromium/Windows, Cocoa, GTK, Qt alike) - a download
    # triggered from JS (like the "Xuất Markdown" button's Blob + <a download>
    # click) is silently cancelled with zero UI feedback: no dialog, no file,
    # no error. Must be set before create_window()/start(). With this on,
    # EdgeChromium shows a native Save-As dialog pre-filled with the
    # suggested filename instead of dropping the file on the floor.
    webview.settings['ALLOW_DOWNLOADS'] = True

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
    #
    # `gui="edgechromium"` is explicit, not the default, so that any gap in
    # `_webview2_runtime_installed()`'s registry check (or the runtime being
    # present but broken) turns into a loud `WebViewException` here instead
    # of pywebview quietly falling back to the deprecated MSHTML engine this
    # app cannot run under (see that function's docstring for why).
    try:
        webview.start(http_server=True, gui="edgechromium")
    except Exception as exc:  # pywebview raises plain/WebViewException, both catch here
        logger.exception("Không khởi động được cửa sổ EdgeChromium")
        _fatal_message_box(
            f"Không khởi động được giao diện EdgeChromium ({exc}).\n\n"
            "Kiểm tra Microsoft Edge WebView2 Runtime đã được cài đúng cách:\n"
            f"{_WEBVIEW2_DOWNLOAD_URL}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
