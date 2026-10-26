from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from toolrank import runner
from toolrank import process_deadline
from toolrank.process_deadline import DeadlineProcessResult
from toolrank.process_deadline import run_process_with_deadline


def _write_report(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"findings": []}), encoding="utf-8")


@pytest.mark.parametrize(
    "tool_id",
    ["gptscan", "securify2", "slither", "sailfish", "smartian", "vandal", "mythril"],
)
def test_every_runner_adapter_uses_the_shared_outer_deadline(
    tool_id: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Token.sol"
    target.write_text("pragma solidity ^0.8.20;\ncontract Token {}\n", encoding="utf-8")
    calls: list[dict] = []

    def fake_deadline(called_tool, contract_path, out_dir, **kwargs):
        calls.append({"tool": called_tool, **kwargs})
        _write_report(out_dir / "result.json")
        return 0

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_deadline)

    _tool, status = runner._run_one_tool_for_contract(
        tool_id,
        target,
        target_root=target,
        results_root=tmp_path / "results",
        mapping={},
        smartbugs_dir=tmp_path / "smartbugs",
        timeout=13,
        gptscan_timeout=7,
        openai_api_key="secret-not-for-logs",
        openai_api_base="https://example.invalid",
        quarantine_root=tmp_path / ".quarantine",
    )

    assert status.return_code == 0
    assert calls[0]["tool"] == tool_id
    assert calls[0]["timeout"] == 13
    assert calls[0]["gptscan_timeout"] == 7


def test_gptscan_keeps_distinct_inner_request_and_outer_tool_timeouts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured: dict = {}

    def fake_process(command, **kwargs):
        captured.update(kwargs)
        request = json.loads(kwargs["input_text"])
        _write_report(Path(request["out_dir"]) / "result.json")
        return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

    monkeypatch.setattr(runner, "run_process_with_deadline", fake_process)
    target = tmp_path / "Token.sol"
    target.write_text("pragma solidity ^0.8.20;\ncontract Token {}\n", encoding="utf-8")

    rc = runner._run_adapter_with_deadline(
        "gptscan",
        target,
        tmp_path / "result",
        target_root=target,
        smartbugs_dir=None,
        timeout=11,
        gptscan_timeout=7,
        openai_api_key="secret-not-for-logs",
        openai_api_base="https://example.invalid",
        gptscan_model="private-request-model",
        quarantine_root=tmp_path / ".quarantine",
    )

    request = json.loads(captured["input_text"])
    assert rc == 0
    assert captured["timeout_seconds"] == 11
    assert request["timeout"] == 11
    assert request["gptscan_timeout"] == 7
    assert request["openai_api_key"] == "secret-not-for-logs"
    assert request["gptscan_model"] == "private-request-model"
    assert "OPENAI_API_KEY" not in captured["env"]
    assert "secret-not-for-logs" not in " ".join(captured.get("display_command", []))


def test_non_gptscan_worker_receives_no_openai_secret_in_env_or_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured: dict = {}

    def fake_process(command, **kwargs):
        captured.update(kwargs)
        request = json.loads(kwargs["input_text"])
        _write_report(Path(request["out_dir"]) / "result.json")
        return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

    monkeypatch.setenv("OPENAI_API_KEY", "sk-environment-secret")
    monkeypatch.setenv("OPENAI_API_TOKEN", "token-environment-secret")
    monkeypatch.setenv("OPENAI_API_BASE", "https://secret.invalid")
    monkeypatch.setattr(runner, "run_process_with_deadline", fake_process)
    target = tmp_path / "Token.sol"
    target.write_text("pragma solidity ^0.4.25; contract Token {}", encoding="utf-8")

    rc = runner._run_adapter_with_deadline(
        "mythril",
        target,
        tmp_path / "result",
        target_root=target,
        smartbugs_dir=tmp_path / "smartbugs",
        timeout=11,
        gptscan_timeout=7,
        openai_api_key="sk-private-request-secret",
        openai_api_base="https://private.invalid",
        mapping={},
        quarantine_root=tmp_path / ".quarantine",
    )

    request = json.loads(captured["input_text"])
    assert rc == 0
    assert "openai_api_key" not in request
    assert "openai_api_base" not in request
    assert all("OPENAI" not in key.upper() for key in captured["env"])


def test_hanging_adapter_is_killed_and_cannot_write_a_late_result(
    tmp_path: Path,
) -> None:
    target = tmp_path / "Token.sol"
    target.write_text("pragma solidity ^0.4.25;\ncontract Token {}\n", encoding="utf-8")
    out_dir = tmp_path / "results" / "mythril"
    marker = tmp_path / "adapter_started"
    smartbugs_dir = tmp_path / "smartbugs"
    smartbugs_dir.mkdir()
    executable = smartbugs_dir / "smartbugs"
    executable.write_text(
        "#!/bin/sh\n"
        f"touch '{marker}'\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--results\" ]; then shift; OUT=$1; fi\n"
        "  shift\n"
        "done\n"
        "sleep 2.5\n"
        "mkdir -p \"$OUT\"\n"
        "printf '{\"findings\": []}' > \"$OUT/result.json\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    diagnostics = []
    rc = runner._run_adapter_with_deadline(
        "mythril",
        target,
        out_dir,
        target_root=target,
        smartbugs_dir=smartbugs_dir,
        timeout=2.0,
        gptscan_timeout=7,
        openai_api_key="",
        openai_api_base="",
        quarantine_root=tmp_path / ".quarantine",
        diagnostics=diagnostics,
    )

    assert rc == 124
    assert diagnostics[0].failure_code == "TOOL_TIMEOUT"
    evidence = out_dir.parent / diagnostics[0].directory
    assert (evidence / "worker.stdout.log").is_file()
    assert marker.exists()
    time.sleep(0.7)
    assert not (out_dir / "result.json").exists()


def test_ready_handshake_and_execution_share_one_absolute_deadline(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "ready"
    script = (
        "import pathlib,sys,time; "
        "sys.stdin.read(); time.sleep(0.15); "
        "pathlib.Path(sys.argv[1]).touch(); time.sleep(2)"
    )

    result = run_process_with_deadline(
        [sys.executable, "-c", script, str(ready)],
        timeout_seconds=0.3,
        input_text="request",
        ready_file=ready,
        startup_timeout_seconds=1.0,
    )

    assert result.timed_out
    assert result.returncode == 124
    assert result.elapsed_seconds < 0.5


def test_startup_wait_is_capped_by_outer_deadline(tmp_path: Path) -> None:
    result = run_process_with_deadline(
        [sys.executable, "-c", "import sys,time; sys.stdin.read(); time.sleep(2)"],
        timeout_seconds=0.2,
        input_text="request",
        ready_file=tmp_path / "never-ready",
        startup_timeout_seconds=10.0,
    )

    assert result.timed_out
    assert result.returncode == 124
    assert result.elapsed_seconds < 0.5


def test_early_worker_exit_during_ready_handshake_returns_typed_code(
    tmp_path: Path,
) -> None:
    result = run_process_with_deadline(
        [sys.executable, "-c", "import os; os._exit(7)"],
        timeout_seconds=1.0,
        input_text="x" * 10_000_000,
        ready_file=tmp_path / "never-ready",
    )

    assert not result.timed_out
    assert result.returncode == 7


def test_permission_error_during_group_kill_returns_bounded_typed_timeout(
    monkeypatch,
) -> None:
    class FakeProcess:
        pid = 4321
        stdin = None
        stdout = None
        stderr = None
        returncode = None

        def __init__(self) -> None:
            self.killed = False
            self.wait_timeouts: list[float | None] = []
            self.communicate_calls = 0

        def communicate(self, input=None, timeout=None):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            assert timeout is not None
            return "", ""

        def wait(self, timeout=None):
            self.wait_timeouts.append(timeout)
            if not self.killed:
                raise subprocess.TimeoutExpired(["fixture"], timeout)
            self.returncode = -signal.SIGKILL
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.killed = True

    proc = FakeProcess()
    signals: list[signal.Signals] = []

    def fake_killpg(_pid: int, sig: signal.Signals) -> None:
        signals.append(sig)
        if sig == signal.SIGKILL:
            raise PermissionError("macOS process-group race")

    monkeypatch.setattr(process_deadline.subprocess, "Popen", lambda *_a, **_k: proc)
    monkeypatch.setattr(process_deadline.os, "killpg", fake_killpg)

    result = run_process_with_deadline(["fixture"], timeout_seconds=0.01)

    assert result.returncode == 124
    assert result.timed_out is True
    assert proc.killed is True
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert proc.wait_timeouts
    assert all(timeout is not None for timeout in proc.wait_timeouts)


def _load_smartian_module():
    path = Path(__file__).resolve().parents[1] / "docker" / "runners" / "run_smartian.py"
    spec = importlib.util.spec_from_file_location("lakes_timeout_smartian_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("outer_seconds", "expected_fuzz_seconds"),
    [(0.25, 1), (5, 1), (7, 1), (30, 24), (30.5, 24)],
)
def test_smartian_fuzz_budget_reserves_bounded_report_shutdown_time(
    outer_seconds: float,
    expected_fuzz_seconds: int,
) -> None:
    module = _load_smartian_module()

    assert module._smartian_fuzz_timeout_seconds(outer_seconds) == expected_fuzz_seconds
    assert module.SMARTIAN_LIFECYCLE_RESERVE_SECONDS == 6


def test_smartian_engine_uses_reserved_fuzz_budget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_smartian_module()
    contract = tmp_path / "Main.sol"
    abi = tmp_path / "Main.abi.json"
    bytecode = tmp_path / "Main.bin"
    contract.write_text("contract Main {}", encoding="utf-8")
    abi.write_text("[]", encoding="utf-8")
    bytecode.write_text("6000", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_stream(command, cwd=None):
        commands.append(command)
        return 0

    monkeypatch.setattr(module, "_stream_process", fake_stream)

    rc = module._run_one_contract(
        contract,
        tmp_path,
        tmp_path / "out",
        tmp_path / "Smartian.dll",
        "dotnet",
        30,
        {},
        "solc",
        "bin",
        shared_abi=abi,
        shared_bytecode=bytecode,
        shared_contract_key="Main.sol:Main",
        shared_bundle_id="bundle-1",
    )

    assert rc == 0
    assert commands[0][commands[0].index("-t") + 1] == "24"


def test_smartian_worker_keeps_fractional_outer_deadline_exact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Token.sol"
    target.write_text("contract Token {}", encoding="utf-8")
    captured: dict = {}

    def fake_process(command, **kwargs):
        captured.update(kwargs)
        request = json.loads(kwargs["input_text"])
        _write_report(Path(request["out_dir"]) / "result.json")
        return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

    monkeypatch.setattr(runner, "run_process_with_deadline", fake_process)
    rc = runner._run_adapter_with_deadline(
        "smartian",
        target,
        tmp_path / "result",
        target_root=target,
        smartbugs_dir=None,
        timeout=30.5,
        gptscan_timeout=7,
        openai_api_key="",
        openai_api_base="",
        mapping={},
        quarantine_root=tmp_path / ".quarantine",
    )

    request = json.loads(captured["input_text"])
    assert rc == 0
    assert captured["timeout_seconds"] == 30.5
    assert request["timeout"] == 30.5
