"""Guard rail for the dynamic analysis module, symmetric to
`test_sample_is_never_executed` in `test_integration_angr.py`.

That existing test already scans the whole `backend/app/` tree (which
includes `app/dynamic/`), so `test_dynamic_module_never_executes_or_automates_a_vm`
below is intentionally redundant defense-in-depth: it is scoped narrowly to
`app/dynamic/` and additionally forbids hypervisor-CLI tokens, since safety
constraint #1 (docs/dynamic-analysis-spec.md) bans any VM automation, not
just sample execution.

**Important, honest caveat** (added alongside the local-launch feature):
both of these substring-scanning tests can only ever catch Python-level
process-spawning APIs (`subprocess`, `os.system`, etc.). They cannot and do
not catch
`app.dynamic.debug_bridge.win32_debug.Win32DebugBridge.create_and_attach_local`,
which executes a binary via the plain Win32 `CreateProcessW` API, not via
any of those tokens. That capability is a deliberate, separate,
user-confirmed exception - see its own docstring and
`docs/dynamic-analysis-spec.md`'s local-launch addendum for the full
rationale. `test_local_launch_is_isolated_to_one_method` below is what
actually guards *that* capability: not "does it exist" (it does, on
purpose), but "is it still confined to exactly the one method it was added
to, with no other path in this package able to reach it".
"""

from __future__ import annotations

import ast
from pathlib import Path


def test_dynamic_module_never_executes_or_automates_a_vm() -> None:
    """Catches Python-level process-spawning APIs anywhere in app/dynamic/.

    Does NOT and cannot cover `Win32DebugBridge.create_and_attach_local`'s
    `CreateProcessW` call - see module docstring above.
    """
    forbidden = (
        # Same execution guard as test_sample_is_never_executed.
        "subprocess",
        "os.system",
        "os.spawn",
        "os.exec",
        "ShellExecute",
        # Extra, dynamic-specific: no hypervisor CLI automation of any kind
        # (safety constraint #1 - this app never starts/stops/snapshots a VM).
        "vmrun",
        "VBoxManage",
        "hyperv",
        "qemu-system",
    )
    dynamic_dir = Path(__file__).parents[1] / "app" / "dynamic"

    offenders: list[str] = []
    for source in dynamic_dir.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append(f"{source.relative_to(dynamic_dir)}: {token}")

    assert offenders == [], f"Phát hiện thực thi tiến trình hoặc tự động hoá VM: {offenders}"


def test_local_launch_is_isolated_to_one_method() -> None:
    """The local-launch exception (see module docstring) must stay confined
    to exactly one method in one file - `Win32DebugBridge.create_and_attach_local`
    in `debug_bridge/win32_debug.py` (plus that same file's
    `_configure_kernel32_signatures`, which only *declares the calling
    convention* for `CreateProcessW` - the same class-level-constant-style
    exception the old dbgeng-era version of this test made for COM
    vtable-slot constants, not a second call site). Nothing else in
    `app/dynamic/` should reference process creation at all, so a future
    change can't quietly add a second, unaudited path to process execution.
    """
    process_creation_tokens = ("CreateProcessW",)
    dynamic_dir = Path(__file__).parents[1] / "app" / "dynamic"
    bridge_path = dynamic_dir / "debug_bridge" / "win32_debug.py"
    assert bridge_path.is_file(), "win32_debug.py không tồn tại - cập nhật lại test này"

    offenders: list[str] = []
    for source in dynamic_dir.rglob("*.py"):
        if source == bridge_path:
            continue
        text = source.read_text(encoding="utf-8")
        for token in process_creation_tokens:
            if token in text:
                offenders.append(f"{source.relative_to(dynamic_dir)}: {token}")
    assert offenders == [], (
        f"Khả năng tạo tiến trình bị rò rỉ ra ngoài win32_debug.py: {offenders}"
    )

    # Within win32_debug.py itself, every occurrence must be inside one of
    # the two allowed functions - parsed via `ast`, not a string/line
    # heuristic, so nesting or reformatting can't quietly widen the net.
    allowed_functions = {"create_and_attach_local", "_configure_kernel32_signatures"}
    bridge_text = bridge_path.read_text(encoding="utf-8")
    tree = ast.parse(bridge_text, filename=str(bridge_path))

    class _FunctionScopeVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.offending_calls: list[str] = []
            self._function_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 - ast API name
            self._function_stack.append(node.name)
            self.generic_visit(node)
            self._function_stack.pop()

        def visit_Name(self, node: ast.Name) -> None:
            if node.id in process_creation_tokens:
                current_function = self._function_stack[-1] if self._function_stack else None
                if current_function not in allowed_functions:
                    self.offending_calls.append(
                        f"line {node.lineno}: '{node.id}' outside {sorted(allowed_functions)} "
                        f"(in {current_function or 'module scope'})"
                    )
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if node.attr in process_creation_tokens:
                current_function = self._function_stack[-1] if self._function_stack else None
                if current_function not in allowed_functions:
                    self.offending_calls.append(
                        f"line {node.lineno}: '.{node.attr}' outside {sorted(allowed_functions)} "
                        f"(in {current_function or 'module scope'})"
                    )
            self.generic_visit(node)

    visitor = _FunctionScopeVisitor()
    visitor.visit(tree)
    assert visitor.offending_calls == [], (
        f"'{process_creation_tokens}' xuất hiện ngoài "
        f"{sorted(allowed_functions)} trong win32_debug.py: {visitor.offending_calls}"
    )
