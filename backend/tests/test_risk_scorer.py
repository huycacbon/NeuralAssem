"""Risk heuristic behaviour."""

from __future__ import annotations

import pytest

from app.analyzers.risk_scorer import (
    classify_capability,
    risk_level,
    score_api,
    score_function,
    score_strings,
)


class TestScoreApi:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("CreateRemoteThread", 10),
            ("VirtualAllocEx", 8),
            ("WriteProcessMemory", 8),
            ("NtWriteVirtualMemory", 8),
            ("DeviceIoControl", 7),
            ("SetWindowsHookExW", 6),
            ("CheckRemoteDebuggerPresent", 5),
            ("RegSetValueExW", 5),
            ("IsDebuggerPresent", 4),
            ("WriteFile", 2),
            ("CreateFileW", 1),
        ],
    )
    def test_known_weights(self, name: str, expected: int) -> None:
        assert score_api(name) == expected

    def test_unknown_api_scores_zero(self) -> None:
        assert score_api("SomeHarmlessHelper") == 0

    def test_ansi_and_wide_variants_match(self) -> None:
        assert score_api("CreateFileA") == score_api("CreateFileW") == 1

    def test_handles_decorated_names(self) -> None:
        # stdcall decoration and import-thunk prefixes must still resolve.
        assert score_api("_CreateRemoteThread@28") == 10
        assert score_api("__imp_WriteProcessMemory") == 8

    def test_is_case_insensitive(self) -> None:
        assert score_api("createremotethread") == 10


class TestScoreStrings:
    def test_raw_disk_path(self) -> None:
        score, reasons = score_strings([r"\\.\PhysicalDrive0"])
        assert score == 10
        assert reasons

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("powershell -enc AAAA", 5),
            (r"Software\Microsoft\Windows\CurrentVersion\Run", 5),
            ("cmd.exe /c whoami", 3),
            ("http://example.invalid", 2),
            ("abcdef3onion.onion", 5),
        ],
    )
    def test_individual_patterns(self, value: str, expected: int) -> None:
        score, _ = score_strings([value])
        assert score == expected

    def test_pattern_counted_once_across_many_strings(self) -> None:
        score, reasons = score_strings(["cmd.exe", "cmd.exe /c", "run cmd.exe now"])
        assert score == 3
        assert len(reasons) == 1

    def test_benign_strings_score_zero(self) -> None:
        score, reasons = score_strings(["Hello world", "%d\n", "usage: app"])
        assert score == 0
        assert reasons == []


class TestScoreFunction:
    def test_sums_api_and_string_contributions(self) -> None:
        score, reasons = score_function(
            ["CreateRemoteThread", "WriteProcessMemory"],
            ["powershell.exe -nop"],
        )
        assert score == 10 + 8 + 5
        assert len(reasons) == 3

    def test_repeated_api_counted_once(self) -> None:
        # A loop calling WriteFile must not outrank a single CreateRemoteThread.
        looping, _ = score_function(["WriteFile"] * 20)
        injecting, _ = score_function(["CreateRemoteThread"])
        assert looping == 2
        assert injecting > looping

    def test_ansi_wide_pair_counted_once(self) -> None:
        score, _ = score_function(["CreateFileA", "CreateFileW"])
        assert score == 1

    def test_empty_input(self) -> None:
        assert score_function([], []) == (0, [])

    def test_reasons_are_human_readable(self) -> None:
        _, reasons = score_function(["DeviceIoControl"], [r"\\.\PhysicalDrive0"])
        assert any("DeviceIoControl" in reason for reason in reasons)
        assert any("disk" in reason.lower() for reason in reasons)


class TestCapability:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("CreateRemoteThread", "process_injection"),
            ("WriteProcessMemory", "process_injection"),
            ("InternetOpenUrlW", "network"),
            ("BCryptEncrypt", "crypto"),
            ("RegSetValueExW", "persistence"),
            ("IsDebuggerPresent", "anti_analysis"),
            ("GetAsyncKeyState", "keylogging"),
            ("CreateFileW", "filesystem"),
            ("SomeUnknownThing", "other"),
        ],
    )
    def test_buckets(self, name: str, expected: str) -> None:
        assert classify_capability(name) == expected


class TestRiskLevel:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [(0, "none"), (1, "low"), (9, "low"), (10, "medium"), (19, "medium"), (20, "high"), (99, "high")],
    )
    def test_thresholds(self, score: int, expected: str) -> None:
        assert risk_level(score) == expected
