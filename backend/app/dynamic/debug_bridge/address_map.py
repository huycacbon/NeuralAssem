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


def is_canonical_x64_address(address: int) -> bool:
    """Whether `address` is a structurally valid x86-64 virtual address -
    bits 48-63 must all equal bit 47 (the "canonical form" the CPU itself
    enforces; a non-canonical address faults before any OS/driver even gets
    a chance to say "not mapped").

    Exists as a fast, purely-arithmetic sanity check callers do *before*
    asking dbgeng to read/write an address at all - confirmed live: feeding
    an already-*runtime* address into `static_to_runtime` a second time
    (double-applying the rebase delta) produces exactly this kind of
    non-canonical garbage, which then surfaces many calls later as an opaque
    `ReadVirtual`/`ERROR_READ_FAULT` deep inside a breakpoint plant - by the
    time that happens, the real mistake (wrong address space, not a
    memory/engine problem) is hard to distinguish from a dozen other
    possible causes. Catching it right where the address is computed, with
    a message that says what's actually wrong, is much cheaper for
    everyone - the user included - than diagnosing the eventual symptom.

    Not Windows-specific and not related to whether the address happens to
    be *mapped* - a canonical address can still be unmapped (a separate,
    legitimate `ReadVirtual` failure); this only rejects addresses the CPU
    itself would never accept in the first place.
    """
    # `address` is always treated as an unsigned 64-bit value in this app
    # (see `format_address`) - bits 47-63 (17 bits) are either all 0 (user
    # space) or all 1 (`0x1FFFF` - kernel space) for a canonical address,
    # anything else falls in the forbidden non-canonical gap between them.
    top17 = address >> 47
    return top17 == 0 or top17 == 0x1FFFF
