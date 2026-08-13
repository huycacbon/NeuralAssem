"""DebugSession and SessionStore behaviour against a fake DebugBridge - no
pykd, dbgsrv, or VM needed. See `FakeDebugBridge` below, which is the test
double every case here drives through the real `DebugBridge` interface.
"""

from __future__ import annotations

import pytest

from app.analyzers.angr_analyzer import AnalysisArtifacts
from app.dynamic.debug_bridge.client import (
    DebugBridge,
    DebugBridgeError,
    LiveInstruction,
    ModuleInfo,
    StackFrameInfo,
    StopReason,
)
from app.dynamic.session import DebugSession, DynamicSessionError, SessionStatus
from app.dynamic.session_store import (
    DynamicAnalysisNotFound,
    DynamicSessionNotFound,
    SessionStore,
)
from app.repositories import InMemoryAnalysisRepository
from app.services.analysis_service import _build_record


class _FakeClock:
    """Deterministic, manually-advanced clock so idle-timeout tests never
    depend on a real sleep."""

    def __init__(self) -> None:
        self.now = 0.0

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


class FakeDebugBridge(DebugBridge):
    """Scripted double implementing the real `DebugBridge` interface."""

    def __init__(self, load_base: int = 0x7FF600000000, module_name: str = "sample.exe") -> None:
        self.load_base = load_base
        self.module_name = module_name
        self.connected = False
        self.attached = False
        self.disconnected = False
        self.fail_connect = False
        self.fail_go = False
        self.fail_local_launch = False
        self.local_launch_command_line: str | None = None
        self.eip = load_base + 0x1234
        self._next_bp_id = 1
        self.breakpoints: dict[int, int] = {}
        self.registers = {
            "eax": 1,
            "ebx": 2,
            "ecx": 3,
            "edx": 4,
            "esi": 5,
            "edi": 6,
            "esp": load_base + 0x2000,
            "ebp": load_base + 0x2010,
            "eip": self.eip,
        }
        self.stack = [StackFrameInfo(index=0, return_address=load_base + 0x5000)]
        self.fail_disassemble = False
        self.disassemble_unsupported = False
        self.module_label = "sample.exe+0x1234"
        self.write_register_unsupported = False
        self.fail_write_register = False
        self.written_registers: dict[str, int] = {}
        self.read_memory_unsupported = False
        self.fail_read_memory = False
        self.memory: dict[int, bytes] = {}

    def connect(self, host: str, port: int, timeout_seconds: float) -> None:
        if self.fail_connect:
            raise DebugBridgeError("kết nối giả lập thất bại")
        self.connected = True

    def attach(self, process_id: int | None, process_name: str | None) -> ModuleInfo:
        self.attached = True
        return ModuleInfo(load_base=self.load_base, module_name=self.module_name, size=0x10000)

    def create_and_attach_local(self, command_line: str) -> ModuleInfo:
        self.local_launch_command_line = command_line
        if self.fail_local_launch:
            raise DebugBridgeError("local launch giả lập thất bại")
        self.attached = True
        return ModuleInfo(load_base=self.load_base, module_name=command_line, size=0x10000)

    def set_breakpoint(self, runtime_address: int) -> int:
        bp_id = self._next_bp_id
        self._next_bp_id += 1
        self.breakpoints[bp_id] = runtime_address
        return bp_id

    def clear_breakpoint(self, breakpoint_id: int) -> None:
        self.breakpoints.pop(breakpoint_id, None)

    def step_into(self) -> StopReason:
        self.eip += 1
        self.registers["eip"] = self.eip
        return StopReason(kind="step")

    def step_over(self) -> StopReason:
        return self.step_into()

    def go(self, timeout_seconds: float) -> StopReason:
        if self.fail_go:
            raise DebugBridgeError("timeout giả lập")
        return StopReason(kind="breakpoint")

    def read_registers(self) -> dict[str, int]:
        return dict(self.registers)

    def read_stack(self, max_frames: int) -> list[StackFrameInfo]:
        return list(self.stack[:max_frames])

    def current_instruction_address(self) -> int:
        return self.eip

    def disassemble_range(self, address: int, instruction_count: int) -> list[LiveInstruction]:
        if self.disassemble_unsupported:
            raise NotImplementedError("disassemble giả lập không hỗ trợ")
        if self.fail_disassemble:
            raise DebugBridgeError("disassemble giả lập thất bại")
        return [
            LiveInstruction(address=address + i, mnemonic="nop", operands="")
            for i in range(instruction_count)
        ]

    def module_label_at(self, address: int) -> str | None:
        return self.module_label

    def write_register(self, name: str, value: int) -> None:
        if self.write_register_unsupported:
            raise NotImplementedError("write_register giả lập không hỗ trợ")
        if self.fail_write_register:
            raise DebugBridgeError("write_register giả lập thất bại")
        self.written_registers[name] = value
        self.registers[name] = value

    def read_memory(self, address: int, size: int) -> bytes:
        if self.read_memory_unsupported:
            raise NotImplementedError("read_memory giả lập không hỗ trợ")
        if self.fail_read_memory:
            raise DebugBridgeError("read_memory giả lập thất bại")
        data = self.memory.get(address, bytes(range(256)) * 16)
        return data[:size]

    def disconnect(self) -> None:
        self.disconnected = True


class TestDebugSession:
    def test_connect_and_attach_sets_status_and_load_base(self) -> None:
        bridge = FakeDebugBridge(load_base=0x7FF600000000)
        session = DebugSession("sess1", "an1", bridge, preferred_image_base=0x400000)

        session.connect_and_attach("127.0.0.1", 5005, None, None, timeout_seconds=1.0)

        assert bridge.connected and bridge.attached
        assert session.status == SessionStatus.ATTACHED
        state = session.snapshot_state()
        assert state.status == "attached"
        assert state.module_load_base == "0x7ff600000000"

    def test_connect_failure_sets_error_status_and_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_connect = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DebugBridgeError):
            session.connect_and_attach("h", 1, None, None, 1.0)
        assert session.status == SessionStatus.ERROR

    def test_set_and_clear_breakpoint_translates_address(self) -> None:
        bridge = FakeDebugBridge(load_base=0x500000)
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        bp = session.set_breakpoint(0x401000)

        assert bp.static_address == "0x401000"
        assert bp.runtime_address == "0x501000"  # 0x401000 + (0x500000 - 0x400000)
        assert bridge.breakpoints[bp.id] == 0x501000

        session.clear_breakpoint(bp.id)
        assert bp.id not in bridge.breakpoints

    def test_clear_unknown_breakpoint_raises_dynamic_session_error(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.clear_breakpoint(999)
        assert excinfo.value.code == "DYNAMIC_BREAKPOINT_NOT_FOUND"

    def test_breakpoint_before_attach_raises(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.set_breakpoint(0x401000)
        assert excinfo.value.code == "DYNAMIC_NOT_ATTACHED"

    def test_snapshot_state_maps_current_address_to_static(self) -> None:
        bridge = FakeDebugBridge(load_base=0x7FF600000000)
        bridge.eip = 0x7FF600001234
        bridge.registers["eip"] = bridge.eip
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        state = session.snapshot_state()

        assert state.runtime_address == "0x7ff600001234"
        assert state.static_address == "0x401234"
        assert state.module_load_base == "0x7ff600000000"
        assert state.preferred_image_base == "0x400000"
        assert len(state.registers) == 9
        assert len(state.stack) == 1
        assert state.stack[0].static_return_address is not None

    def test_step_and_go_update_status(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        session.step("into")
        assert session.status == SessionStatus.BREAK

        session.go(5.0)
        assert session.status == SessionStatus.BREAK

    def test_go_failure_sets_error_status_and_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_go = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DebugBridgeError):
            session.go(1.0)
        assert session.status == SessionStatus.ERROR

    def test_idle_tracking_with_fake_clock(self) -> None:
        clock = _FakeClock()
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000, clock=clock)

        assert not session.is_idle(100)
        clock.advance(150)
        assert session.is_idle(100)

        session.touch()
        assert not session.is_idle(100)

    def test_launch_local_sets_status_and_records_command_line(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        session.launch_local(r"C:\tools\sample.exe --flag")

        assert bridge.local_launch_command_line == r"C:\tools\sample.exe --flag"
        assert session.status == SessionStatus.ATTACHED
        assert session.snapshot_state().status == "attached"

    def test_launch_local_failure_sets_error_status_and_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_local_launch = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DebugBridgeError):
            session.launch_local("bad.exe")
        assert session.status == SessionStatus.ERROR

    def test_disassemble_current_uses_live_pc_and_module_label(self) -> None:
        bridge = FakeDebugBridge(load_base=0x7FF600000000)
        bridge.eip = 0x7FF600001234
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        result = session.disassemble_current(3)

        assert result.runtime_address == "0x7ff600001234"
        assert result.module_label == "sample.exe+0x1234"
        assert len(result.instructions) == 3
        assert result.instructions[0].address == "0x7ff600001234"
        assert result.instructions[0].mnemonic == "nop"

    def test_disassemble_current_before_attach_raises(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.disassemble_current(10)
        assert excinfo.value.code == "DYNAMIC_NOT_STOPPED"

    def test_disassemble_current_unsupported_bridge_raises_dynamic_session_error(self) -> None:
        bridge = FakeDebugBridge()
        bridge.disassemble_unsupported = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.disassemble_current(10)
        assert excinfo.value.code == "DYNAMIC_DISASSEMBLE_UNSUPPORTED"

    def test_disassemble_current_bridge_failure_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_disassemble = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DebugBridgeError):
            session.disassemble_current(10)

    def test_set_register_writes_through_bridge_and_snapshot_reflects_it(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        session.set_register("eax", 0xDEADBEEF)

        assert bridge.written_registers["eax"] == 0xDEADBEEF
        state = session.snapshot_state()
        eax = next(reg for reg in state.registers if reg.name == "eax")
        assert eax.value == "0xdeadbeef"

    def test_set_register_before_attach_raises(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.set_register("eax", 1)
        assert excinfo.value.code == "DYNAMIC_NOT_STOPPED"

    def test_set_register_unsupported_bridge_raises_dynamic_session_error(self) -> None:
        bridge = FakeDebugBridge()
        bridge.write_register_unsupported = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.set_register("eax", 1)
        assert excinfo.value.code == "DYNAMIC_REGISTER_WRITE_UNSUPPORTED"

    def test_set_register_and_snapshot_work_for_flag_registers_too(self) -> None:
        """Flags (cf/zf/sf/...) round-trip through the exact same
        name-agnostic session/API mechanism as any GPR - session.py has no
        register-name-specific logic at all, so this mostly locks in that
        nothing *adds* such filtering later. The real new behaviour (writing
        flags as DEBUG_VALUE_INT8 instead of INT32) lives entirely in
        ComtypesDebugBridge, not exercised by this fake."""
        bridge = FakeDebugBridge()
        bridge.registers["zf"] = 1
        bridge.registers["cf"] = 0
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        state = session.snapshot_state()
        assert {reg.name for reg in state.registers} >= {"zf", "cf"}

        session.set_register("zf", 1)
        assert bridge.written_registers["zf"] == 1
        updated = {reg.name: reg.value for reg in session.snapshot_state().registers}
        assert updated["zf"] == "0x1"

    def test_set_register_bridge_failure_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_write_register = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DebugBridgeError):
            session.set_register("eax", 1)

    def test_dump_memory_returns_hex_and_size(self) -> None:
        bridge = FakeDebugBridge()
        bridge.memory[0x401000] = b"\x90\x90\xc3\x00"
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        result = session.dump_memory(0x401000, 4)

        assert result.address == "0x401000"
        assert result.size == 4
        assert result.bytes_hex == "9090c300"

    def test_dump_memory_before_attach_raises(self) -> None:
        bridge = FakeDebugBridge()
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.dump_memory(0x401000, 16)
        assert excinfo.value.code == "DYNAMIC_NOT_STOPPED"

    def test_dump_memory_unsupported_bridge_raises_dynamic_session_error(self) -> None:
        bridge = FakeDebugBridge()
        bridge.read_memory_unsupported = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DynamicSessionError) as excinfo:
            session.dump_memory(0x401000, 16)
        assert excinfo.value.code == "DYNAMIC_MEMORY_READ_UNSUPPORTED"

    def test_dump_memory_bridge_failure_reraises(self) -> None:
        bridge = FakeDebugBridge()
        bridge.fail_read_memory = True
        session = DebugSession("s", "a", bridge, preferred_image_base=0x400000)
        session.connect_and_attach("h", 1, None, None, 1.0)

        with pytest.raises(DebugBridgeError):
            session.dump_memory(0x401000, 16)


@pytest.fixture
def repository_with_record(sample_artifacts: AnalysisArtifacts) -> InMemoryAnalysisRepository:
    repository = InMemoryAnalysisRepository()
    record = _build_record(
        analysis_id="dyn-test",
        display_name="fixture.exe",
        sha256="0" * 64,
        size=4096,
        artifacts=sample_artifacts,
    )
    repository.save(record)
    return repository


def _make_store(
    repository: InMemoryAnalysisRepository, *, capacity: int = 4, idle_timeout_seconds: int = 1800, clock=None
) -> SessionStore:
    kwargs = {}
    if clock is not None:
        kwargs["clock"] = clock
    return SessionStore(
        repository=repository,
        capacity=capacity,
        idle_timeout_seconds=idle_timeout_seconds,
        bridge_factory=FakeDebugBridge,
        start_reaper=False,  # deterministic tests drive reap_idle() themselves
        **kwargs,
    )


class TestSessionStore:
    def test_create_looks_up_image_base_from_repository(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        session = store.create("dyn-test", "127.0.0.1", 5005, None, None, connect_timeout_seconds=1.0)

        assert session.analysis_id == "dyn-test"
        # sample_artifacts.image_base == 0x400000 (backend/tests/conftest.py)
        assert session.snapshot_state().status == "attached"

    def test_create_unknown_analysis_raises(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        with pytest.raises(DynamicAnalysisNotFound):
            store.create("nope", "h", 1, None, None, 1.0)

    def test_get_unknown_session_raises(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        with pytest.raises(DynamicSessionNotFound):
            store.get("nope")

    def test_delete_disconnects_bridge_and_forgets_session(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        session = store.create("dyn-test", "h", 1, None, None, 1.0)

        assert store.delete(session.session_id) is True
        assert store.delete(session.session_id) is False  # already gone
        with pytest.raises(DynamicSessionNotFound):
            store.get(session.session_id)

    def test_idle_reaper_disconnects_and_evicts(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        clock = _FakeClock()
        store = _make_store(repository_with_record, idle_timeout_seconds=100, clock=clock)
        session = store.create("dyn-test", "h", 1, None, None, 1.0)

        clock.advance(150)
        evicted = store.reap_idle()

        assert evicted == [session.session_id]
        with pytest.raises(DynamicSessionNotFound):
            store.get(session.session_id)

    def test_activity_resets_idle_timer(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        clock = _FakeClock()
        store = _make_store(repository_with_record, idle_timeout_seconds=100, clock=clock)
        session = store.create("dyn-test", "h", 1, None, None, 1.0)

        clock.advance(60)
        store.get(session.session_id)  # counts as activity, per get()'s touch()
        clock.advance(60)  # 120s since create, but only 60s since last touch

        assert store.reap_idle() == []

    def test_capacity_eviction_disconnects_oldest(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record, capacity=1)
        first = store.create("dyn-test", "h", 1, None, None, 1.0)
        second = store.create("dyn-test", "h", 1, None, None, 1.0)

        with pytest.raises(DynamicSessionNotFound):
            store.get(first.session_id)
        assert store.get(second.session_id).session_id == second.session_id

    def test_create_local_launches_and_registers_session(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        session = store.create_local(
            "dyn-test", r"C:\tools\sample.exe", connect_timeout_seconds=1.0
        )

        assert session.analysis_id == "dyn-test"
        assert session.snapshot_state().status == "attached"
        assert store.get(session.session_id).session_id == session.session_id

    def test_create_local_unknown_analysis_raises(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record)
        with pytest.raises(DynamicAnalysisNotFound):
            store.create_local("nope", "sample.exe", connect_timeout_seconds=1.0)

    def test_create_local_capacity_eviction_disconnects_oldest(
        self, repository_with_record: InMemoryAnalysisRepository
    ) -> None:
        store = _make_store(repository_with_record, capacity=1)
        first = store.create_local("dyn-test", "a.exe", connect_timeout_seconds=1.0)
        second = store.create_local("dyn-test", "b.exe", connect_timeout_seconds=1.0)

        with pytest.raises(DynamicSessionNotFound):
            store.get(first.session_id)
        assert store.get(second.session_id).session_id == second.session_id
