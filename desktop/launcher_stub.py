"""Thin native entry point for the packaged desktop app.

This is the ONLY thing PyInstaller ever freezes. It does nothing but locate
the sibling `python_embed/` folder (the portable Python interpreter with angr
and every other backend dependency already pip-installed into it) and run
`backend/desktop_launcher.py` inside it as a child process, then exit with
that process's exit code.

Why not just PyInstaller-freeze the whole backend? angr's plugin/SimProcedure
system does a lot of dynamic, introspection-based importing that PyInstaller's
static import analysis does not reliably discover, which is a well-known
source of "works from source, breaks when frozen" failures for angr-based
tools specifically. Keeping angr on a real, unfrozen interpreter (the
embeddable distribution, with a completely normal `site-packages`) sidesteps
that class of bug entirely - PyInstaller only ever has to understand this
~30-line script, which it can do reliably.

Also: the sample being analysed is data read by angr inside that child
process. Nothing here or in desktop_launcher.py/app.main ever executes it -
the subprocess call below launches our OWN bundled interpreter, never
anything the user uploaded.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _app_root() -> Path:
    """Folder the running .exe lives in (siblings: python_embed/, backend/)."""
    return Path(sys.executable).resolve().parent


def main() -> int:
    root = _app_root()
    python_exe = root / "python_embed" / "python.exe"
    launcher_script = root / "backend" / "desktop_launcher.py"

    if not python_exe.is_file():
        print(f"Khong tim thay {python_exe} - ban da giai nen day du bo cai dat chua?")
        return 1
    if not launcher_script.is_file():
        print(f"Khong tim thay {launcher_script} - ban da giai nen day du bo cai dat chua?")
        return 1

    # desktop_launcher.py finds frontend_dist/ itself (a fixed sibling path,
    # see its own _frontend_index()) - no env var to pass, and no HTTP server
    # for it to configure either way.
    # Runs to completion (i.e. until the user closes the app window); this
    # process's whole job is to wait for that and relay the exit code.
    result = subprocess.run(
        [str(python_exe), str(launcher_script)],
        cwd=str(root / "backend"),
        env=dict(os.environ),
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
