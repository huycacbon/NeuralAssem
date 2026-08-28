"""Win32DebugBridge.step_into/step_over must propagate whatever
`_resume_and_wait` actually observed, not a hardcoded `StopReason(kind="step")`.

Regression tests for a real bug found alongside the session-level
`SessionStatus.EXITED` fix (see `test_dynamic_session.py`'s equivalent
tests): a previous version of both methods discarded `_resume_and_wait`'s
return value entirely, so single-stepping the process's *own last
instruction* (not unusual - a `ret` immediately followed by process exit)
reported `"step"` instead of `"exited"`, which meant `DebugSession.step`
never had a chance to notice the process had ended.

`_resume_and_wait` itself needs a live attached process to run for real
(thread handles, `WaitForDebugEvent`, ...) - these tests instead verify the
narrow contract this fix is actually about: whatever `_resume_and_wait`
returns is what the public method returns, unchanged. Mocking it directly
keeps this fast and Windows-process-free, the same tradeoff
`test_win32_module_tracking.py` already makes for `_unregister_module`'s
pure bookkeeping.
"""

from __future__ import annotations

from app.dynamic.debug_bridge.client import StopReason
from app.dynamic.debug_bridge.win32_debug import Win32DebugBridge


def _bridge_with_mocked_resume(stop_reason: StopReason) -> tuple[Win32DebugBridge, list[bool]]:
    bridge = Win32DebugBridge()
    single_step_calls: list[bool] = []

    def fake_resume_and_wait(timeout_seconds: float, single_step: bool) -> StopReason:
        single_step_calls.append(single_step)
        return stop_reason

    bridge._resume_and_wait = fake_resume_and_wait  # type: ignore[method-assign]
    bridge._rearm_if_pending = lambda: None  # type: ignore[method-assign]
    return bridge, single_step_calls


class TestStepIntoPropagatesStopReason:
    def test_ordinary_step_returns_step(self) -> None:
        bridge, calls = _bridge_with_mocked_resume(StopReason(kind="step"))
        assert bridge.step_into() == StopReason(kind="step")
        assert calls == [True]  # single-stepped, as step_into always does

    def test_process_exit_mid_step_returns_exited_not_step(self) -> None:
        bridge, _ = _bridge_with_mocked_resume(StopReason(kind="exited"))
        assert bridge.step_into() == StopReason(kind="exited")

    def test_timeout_mid_step_returns_timeout_not_step(self) -> None:
        bridge, _ = _bridge_with_mocked_resume(StopReason(kind="timeout"))
        assert bridge.step_into() == StopReason(kind="timeout")


class TestStepOverPropagatesStopReason:
    """Only the non-CALL branch (`_call_instruction_length` returns `None`) is
    exercised here - the CALL-instruction branch already passed the real
    `reason` through correctly before this fix; only the plain-single-step
    fallback (every non-CALL instruction) hardcoded `"step"`."""

    def _bridge_for_non_call_instruction(self, stop_reason: StopReason) -> Win32DebugBridge:
        bridge, _ = _bridge_with_mocked_resume(stop_reason)
        bridge.current_instruction_address = lambda: 0x7FFD00000000  # type: ignore[method-assign]
        bridge._call_instruction_length = lambda address: None  # type: ignore[method-assign]
        return bridge

    def test_ordinary_step_over_returns_step(self) -> None:
        bridge = self._bridge_for_non_call_instruction(StopReason(kind="step"))
        assert bridge.step_over() == StopReason(kind="step")

    def test_process_exit_mid_step_over_returns_exited_not_step(self) -> None:
        """The exact live scenario this fix targets: stepping over the
        process's own final (non-CALL) instruction, e.g. a `ret` right
        before the process terminates."""
        bridge = self._bridge_for_non_call_instruction(StopReason(kind="exited"))
        assert bridge.step_over() == StopReason(kind="exited")
