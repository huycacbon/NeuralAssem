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
not catch `app.dynamic.debug_bridge.client.ComtypesDebugBridge.create_and_attach_local`,
which executes a binary via a raw `dbgeng.dll` COM call
(`IDebugClient::CreateProcessAndAttach`), not via any of those tokens. That
capability is a deliberate, separate, user-confirmed exception - see its own
docstring and `docs/dynamic-analysis-spec.md`'s local-launch addendum for the
full rationale. `test_local_launch_is_isolated_to_one_method` below is what
actually guards *that* capability: not "does it exist" (it does, on
purpose), but "is it still confined to exactly the one method it was added
to, with no other path in this package able to reach it".
"""

from __future__ import annotations

from pathlib import Path


def test_dynamic_module_never_executes_or_automates_a_vm() -> None:
    """Catches Python-level process-spawning APIs anywhere in app/dynamic/.

    Does NOT and cannot cover `ComtypesDebugBridge.create_and_attach_local`'s
    `CreateProcessAndAttach` COM call - see module docstring above.
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
    to exactly one method in one file - `ComtypesDebugBridge.create_and_attach_local`
    in `debug_bridge/client.py`. Nothing else in `app/dynamic/` should
    reference the process-creation vtable slots at all, so a future change
    can't quietly add a second, unaudited path to process execution.
    """
    process_creation_tokens = (
        "CreateProcessAndAttach",
        "_SLOT_CREATE_PROCESS_AND_ATTACH",
        "_SLOT_CREATE_PROCESS",
    )
    dynamic_dir = Path(__file__).parents[1] / "app" / "dynamic"
    client_path = dynamic_dir / "debug_bridge" / "client.py"
    assert client_path.is_file(), "client.py không tồn tại - cập nhật lại test này"

    offenders: list[str] = []
    for source in dynamic_dir.rglob("*.py"):
        if source == client_path:
            continue
        text = source.read_text(encoding="utf-8")
        for token in process_creation_tokens:
            if token in text:
                offenders.append(f"{source.relative_to(dynamic_dir)}: {token}")
    assert offenders == [], (
        f"Khả năng tạo tiến trình bị rò rỉ ra ngoài client.py: {offenders}"
    )

    # Within client.py itself, every occurrence must be inside
    # `create_and_attach_local` (or its `_finish_attach` helper, which the
    # method shares with the read-only `attach()` - GetModuleByIndex only,
    # never process creation itself) or the class-level slot-constant
    # declarations - never inside PykdDebugBridge or any free function.
    client_text = client_path.read_text(encoding="utf-8")
    comtypes_class_start = client_text.index("class ComtypesDebugBridge")
    pykd_class_text = client_text[:comtypes_class_start]
    for token in process_creation_tokens:
        assert token not in pykd_class_text, (
            f"'{token}' xuất hiện trước class ComtypesDebugBridge (vd. trong "
            "PykdDebugBridge) - khả năng tạo tiến trình phải chỉ nằm trong "
            "ComtypesDebugBridge.create_and_attach_local"
        )
