"""Win32DebugBridge module tracking: registration bookkeeping, the DLL-unload
safety cleanup that prevents a stale planted breakpoint from corrupting
whatever gets mapped into a freed address range next, and `list_modules`'s
lazy name re-resolution.

None of this needs a real attached process - `_register_module`/
`_unregister_module`/`list_modules` only touch this bridge's own bookkeeping
dicts once a `ModuleInfo`/base address is already known, so a bare
`Win32DebugBridge()` instance (never actually launched) is enough; the parts
that *do* need a live process (`_module_name`/`_module_size` themselves,
reading real PE headers and calling `K32GetModuleFileNameExW`) were verified
live against real samples during development - see the module's own
docstring references to that.
"""

from __future__ import annotations

from app.dynamic.debug_bridge.client import ModuleInfo
from app.dynamic.debug_bridge.win32_debug import Win32DebugBridge


def _bridge() -> Win32DebugBridge:
    return Win32DebugBridge()


class TestModuleRegistration:
    def test_register_module_is_a_noop_for_base_zero(self) -> None:
        bridge = _bridge()
        bridge._modules[0x401000] = ModuleInfo(load_base=0x401000, module_name="x", size=0x1000)
        # A `LOAD_DLL_DEBUG_EVENT`/`CREATE_PROCESS_DEBUG_EVENT` can in theory
        # report a null base (never seen live, but the field is optional
        # per MSDN) - must not register a bogus 0x0 "module".
        monkeypatched_size_calls: list[int] = []
        bridge._module_size = lambda base: monkeypatched_size_calls.append(base) or 0  # type: ignore[method-assign]
        bridge._register_module(0)
        assert 0 not in bridge._modules
        assert monkeypatched_size_calls == []

    def test_register_module_does_not_overwrite_an_existing_entry(self) -> None:
        bridge = _bridge()
        original = ModuleInfo(load_base=0x401000, module_name="already-resolved.dll", size=0x2000)
        bridge._modules[0x401000] = original
        calls: list[int] = []
        bridge._module_name = lambda base: calls.append(base) or "should-not-be-used"  # type: ignore[method-assign]

        bridge._register_module(0x401000)

        assert bridge._modules[0x401000] is original
        assert calls == []  # never re-resolved - registration is idempotent


class TestUnregisterModuleSafetyCleanup:
    """`_unregister_module` - the fix for the live "stuck at an unexpected
    address" report: a `0xCC` planted inside a module that then unloads must
    not linger to corrupt whatever the OS maps into that recycled address
    range next."""

    def test_drops_planted_breakpoints_inside_the_unloading_modules_range(self) -> None:
        bridge = _bridge()
        base, size = 0x7FFD00000000, 0x10000
        bridge._modules[base] = ModuleInfo(load_base=base, module_name="evil.dll", size=size)
        inside = base + 0x100
        outside = base + size + 0x10
        bridge._planted[inside] = b"\x90"
        bridge._planted[outside] = b"\x90"

        bridge._unregister_module(base)

        assert inside not in bridge._planted
        assert outside in bridge._planted  # untouched - belongs to a different module
        assert base not in bridge._modules

    def test_clears_pending_rearm_if_it_pointed_inside_the_unloading_module(self) -> None:
        bridge = _bridge()
        base, size = 0x7FFD00000000, 0x10000
        bridge._modules[base] = ModuleInfo(load_base=base, module_name="evil.dll", size=size)
        bridge._pending_rearm = base + 0x50

        bridge._unregister_module(base)

        assert bridge._pending_rearm is None

    def test_leaves_pending_rearm_alone_if_it_points_elsewhere(self) -> None:
        bridge = _bridge()
        base, size = 0x7FFD00000000, 0x10000
        bridge._modules[base] = ModuleInfo(load_base=base, module_name="evil.dll", size=size)
        elsewhere = 0x140001000
        bridge._pending_rearm = elsewhere

        bridge._unregister_module(base)

        assert bridge._pending_rearm == elsewhere

    def test_unknown_base_is_a_noop(self) -> None:
        bridge = _bridge()
        bridge._planted[0x401000] = b"\x90"
        bridge._unregister_module(0x999999)
        assert bridge._planted == {0x401000: b"\x90"}

    def test_zero_size_module_skips_cleanup_but_still_forgets_the_module(self) -> None:
        """`size == 0` means `_module_size` itself failed at registration
        time (unreadable/corrupt header) - there is no known range to clean
        up, so this must not raise or touch `_planted`, just drop the
        now-stale module entry itself."""
        bridge = _bridge()
        base = 0x7FFD00000000
        bridge._modules[base] = ModuleInfo(load_base=base, module_name="mystery.dll", size=0)
        bridge._planted[base + 0x10] = b"\x90"

        bridge._unregister_module(base)

        assert base not in bridge._modules
        assert base + 0x10 in bridge._planted  # nothing to clean up - size unknown


class TestListModules:
    def test_sorted_by_load_base(self) -> None:
        bridge = _bridge()
        bridge._modules = {
            0x7FFD00000000: ModuleInfo(load_base=0x7FFD00000000, module_name="c.dll", size=0x1000),
            0x140000000: ModuleInfo(load_base=0x140000000, module_name="a.exe", size=0x1000),
            0x7FF700000000: ModuleInfo(load_base=0x7FF700000000, module_name="b.dll", size=0x1000),
        }

        modules = bridge.list_modules()

        assert [m.module_name for m in modules] == ["a.exe", "b.dll", "c.dll"]

    def test_lazily_re_resolves_a_module_still_on_its_hex_fallback_name(self) -> None:
        """Confirmed live: `K32GetModuleFileNameExW` reliably fails for a
        module registered *during* the initial debug-event pump (the loader
        hasn't settled it into the process's own module list yet at that
        exact instant) - `_module_name` falls back to the bare hex address
        in that case. `list_modules` must retry it on every call until it
        resolves, rather than permanently showing the fallback."""
        bridge = _bridge()
        base = 0x7FFD00000000
        fallback_name = bridge._fallback_module_name(base)
        bridge._modules[base] = ModuleInfo(load_base=base, module_name=fallback_name, size=0x1000)
        bridge._module_name = lambda b: "C:\\Windows\\System32\\real-name.dll"  # type: ignore[method-assign]

        modules = bridge.list_modules()

        assert modules[0].module_name == "C:\\Windows\\System32\\real-name.dll"

    def test_does_not_re_resolve_a_module_that_already_has_a_real_name(self) -> None:
        bridge = _bridge()
        base = 0x7FFD00000000
        bridge._modules[base] = ModuleInfo(load_base=base, module_name="already-fine.dll", size=0x1000)
        calls: list[int] = []
        bridge._module_name = lambda b: calls.append(b) or "should-not-be-called"  # type: ignore[method-assign]

        modules = bridge.list_modules()

        assert modules[0].module_name == "already-fine.dll"
        assert calls == []

    def test_empty_when_nothing_registered(self) -> None:
        assert _bridge().list_modules() == []


class TestIsBreakpointPlanted:
    def test_true_only_while_physically_planted(self) -> None:
        bridge = _bridge()
        address = 0x401000
        assert bridge.is_breakpoint_planted(address) is False
        bridge._planted[address] = b"\x90"
        assert bridge.is_breakpoint_planted(address) is True
        del bridge._planted[address]
        assert bridge.is_breakpoint_planted(address) is False
