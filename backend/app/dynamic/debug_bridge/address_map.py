"""Runtime <-> static address translation (spec's "address sync" requirement).

The VM loads the binary at its real runtime base, which can differ from the
preferred ``ImageBase`` recorded by the static analyzer (ASLR, a rebase
forced by the OS loader because the preferred base was taken, etc). Once we
know both bases, translating one address space into the other is a single
constant offset - no disassembly or symbol lookup needed.

Pure functions only: no pykd, no sockets, no state. Every address that
crosses this module's boundary is a plain ``int``; callers are responsible
for going through ``app.utils.address.format_address``/``parse_address`` at
the API/session boundary, exactly like every other address in this app.
"""

from __future__ import annotations


def rebase_delta(actual_load_base: int, preferred_image_base: int) -> int:
    """How far the loader shifted the module from its preferred base.

    Zero when the module loaded exactly where the static analysis expected
    (no rebase happened).
    """
    return actual_load_base - preferred_image_base


def runtime_to_static(
    runtime_address: int, actual_load_base: int, preferred_image_base: int
) -> int:
    """Translate a live debugger address into the address space the static
    graph (built from ``preferred_image_base``) already uses."""
    return runtime_address - rebase_delta(actual_load_base, preferred_image_base)


def static_to_runtime(
    static_address: int, actual_load_base: int, preferred_image_base: int
) -> int:
    """Inverse of :func:`runtime_to_static` - e.g. to place a breakpoint at
    a static-graph address the user picked before connecting."""
    return static_address + rebase_delta(actual_load_base, preferred_image_base)
