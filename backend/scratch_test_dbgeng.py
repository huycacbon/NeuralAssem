"""Standalone smoke test for `ComtypesDebugBridge`, bypassing FastAPI,
pywebview, and the frontend entirely - the fastest possible loop for
iterating on dbgeng-bridge bugs (attach -> breakpoint -> continue), since it
skips the whole PyInstaller repackage-and-copy-to-VM cycle.

Run directly in the VM (needs Windows + dbgeng.dll, same as the real app) -
or on a real host machine, for a *known-benign* sample only (e.g. one of
this repo's own `samples/*.exe` fixtures - see `samples/README.md`, they are
built for exactly this kind of testing and do nothing harmful). Never point
this at a sample you don't already trust - see the safety paragraph below:

    cd backend
    .venv\\Scripts\\activate      (or: python -m venv .venv && .venv\\Scripts\\activate && pip install -r requirements.txt)
    python scratch_test_dbgeng.py ..\\samples\\05_multithread.exe

First argument: full path to the sample to launch (same safety caveat as the
app's own "Local-launch" - this executes it directly, unsandboxed; only
point it at something you already trust, e.g. this repo's own `samples/`
fixtures, or run it inside an isolated VM for anything else). Second
argument (optional): a *static* breakpoint address in hex (e.g. a function's
address as shown in the app's UI) - defaults to the sample's own entry point
(`_start`), read straight from the PE header via `pefile` (already a backend
dependency), so the common "break at start, Continue" case needs no extra
lookup step at all. Third argument (optional): override the preferred image
base pefile already read from the same header - only needed to test a
mismatch deliberately.

Not part of the test suite (`scratch_` prefix, not `test_`) - a disposable
debugging aid, not a regression test; delete once the bug is resolved.
"""

from __future__ import annotations

import sys

import pefile

from app.dynamic.debug_bridge.address_map import static_to_runtime
from app.dynamic.debug_bridge.client import ComtypesDebugBridge, DebugBridgeError


def _entry_point_and_image_base(path: str) -> tuple[int, int]:
    """Reads `(preferred_image_base + AddressOfEntryPoint, preferred_image_base)`
    straight from the PE header - the same two values the static analyzer's
    own `file.entry_point`/`ImageBase` come from, so this needs no running
    app/UI to look them up."""
    pe = pefile.PE(path, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return image_base + entry_rva, image_base


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <path-to-sample.exe> [static-breakpoint-hex] [preferred-image-base-hex]")
        sys.exit(1)

    command_line = sys.argv[1]
    default_static_address, default_image_base = _entry_point_and_image_base(command_line)
    static_address = int(sys.argv[2], 16) if len(sys.argv) > 2 else default_static_address
    preferred_image_base = int(sys.argv[3], 16) if len(sys.argv) > 3 else default_image_base

    bridge = ComtypesDebugBridge()

    print(f"[*] Launching + attaching: {command_line}")
    module = bridge.create_and_attach_local(command_line)
    print(f"    load_base=0x{module.load_base:x} name={module.module_name!r} size={module.size}")

    current = bridge.current_instruction_address()
    print(f"[*] Stopped at runtime address: 0x{current:x}")

    # Mirrors session.py's set_breakpoint: needs the *preferred* image base
    # (the static analyzer's PE-header value) to compute the delta against
    # the real load_base above.
    runtime_address = static_to_runtime(static_address, module.load_base, preferred_image_base)
    print(
        f"[*] Setting breakpoint: static=0x{static_address:x} "
        f"preferred_base=0x{preferred_image_base:x} -> runtime=0x{runtime_address:x}"
    )

    # Isolates the "size=1 vs size=256" hypothesis directly: `_plant_breakpoint`
    # (called internally by `go()` below) reads exactly 1 byte at this exact
    # address; the app's "Dump Memory" panel (which read successfully against
    # a real, unmapped-looking address earlier) always used 256. Comparing
    # both reads here, at the exact same point in the exact same session,
    # settles whether the read size itself is what matters.
    for probe_size in (256, 1):
        try:
            data = bridge.read_memory(runtime_address, probe_size)
            print(f"[*] Probe read_memory(size={probe_size}): OK, got {len(data)} byte(s): {data[:16].hex()}")
        except DebugBridgeError as exc:
            print(f"[*] Probe read_memory(size={probe_size}): FAILED - {exc}")

    try:
        bridge.set_breakpoint(runtime_address)
        print("[*] Continuing...")
        reason = bridge.go(30.0, frozenset({runtime_address}))
        print(f"[*] StopReason: {reason}")
        stopped_at = bridge.current_instruction_address()
        print(f"[*] Now stopped at runtime address: 0x{stopped_at:x}")
        if stopped_at == runtime_address:
            print("[+] SUCCESS: stopped exactly at the requested breakpoint.")
        else:
            print("[!] Did NOT stop at the requested breakpoint address.")
    except DebugBridgeError as exc:
        print(f"[!] DebugBridgeError: {exc}")
        raise


if __name__ == "__main__":
    main()
