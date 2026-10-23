"""Report contracts from SmartBugs 89c16bb and LAKES' bundled wrappers.

These fixtures exercise report ingestion and fusion without launching analyzers.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
from types import ModuleType

import pytest

from toolrank import engine, execution, runner
from toolrank.process_deadline import DeadlineProcessResult
from toolrank.fusion import compact_fused_report_payload, fuse_reports
from toolrank.report_parser import (
    REPORT_INPUT_FILENAME_KEY,
    load_per_tool_findings,
    load_per_tool_findings_from_run_dir,
)
from toolrank.runner_adapter import (
    PAPER_TOOL_IDS,
    _enrich_report_with_categories,
    _load_mapping,
)
from toolrank.schemas import CompositionPlan, ExecutionResult, ExecutionSchedule, FusedReport


# The upstream aliases resolve to slither-0.11.3, mythril-0.24.8,
# solhint-6.0.0, manticore-0.3.7, and the local vulhunter-0.2 overlay.
_TOOL_REPORTS = [
    ("slither", "tx-origin", {"impact": "High", "confidence": "Medium"}, "access_control", "High"),
    ("gptscan", "MWE-207: Unauthorized Transfer", {"severity": "HIGH"}, "access_control", "HIGH"),
    ("vulhunter", "reentrancy-eth", {"severity": "High"}, "reentrancy", "High"),
    ("mando-hgt", "reentrancy", {}, "reentrancy", None),
    ("mythril", "Dependence on tx.origin (SWC 115)", {"severity": "Low"}, "access_control", "Low"),
    ("oyente", "Integer Overflow", {}, "arithmetic", None),
    ("osiris", "Overflow bugs", {}, "arithmetic", None),
    ("securify", "DAO", {}, "reentrancy", None),
    ("securify2", "Gas_dependent_Reentrancy", {"severity": "High", "type": "Violation"}, "reentrancy", "High"),
    ("smartcheck", "SOLIDITY_TX_ORIGIN", {"severity": 1}, "access_control", 1),
    ("solhint", "avoid-tx-origin", {"level": "warning"}, "access_control", "warning"),
    ("maian", "Ether leak (verified)", {"contract": "Vault"}, "access_control", None),
    ("vandal", "OriginUsed", {"address": 0}, "access_control", None),
    ("manticore", "Potential reentrancy vulnerability", {"code": "17 target.call();"}, "reentrancy", None),
    ("sfuzz", "Reentrancy", {"contract": "Vault", "function": "withdraw"}, "reentrancy", None),
    ("confuzzius", "Integer Overflow", {"severity": "High"}, "arithmetic", "High"),
    ("conkas", "Reentrancy", {"address": 16}, "reentrancy", None),
    ("honeybadger", "Type overflow", {}, "arithmetic", None),
    ("sailfish", "dao", {}, "reentrancy", None),
    ("smartian", "reentrancy", {}, "reentrancy", None),
]


def _single_tool_plan(tool: str, category: str) -> CompositionPlan:
    return CompositionPlan(
        selected_tool_ids=[tool],
        primary_tool_id=tool,
        category_owners={category: [tool]},
    )


def test_report_contracts_cover_every_registered_tool() -> None:
    assert {case[0] for case in _TOOL_REPORTS} == PAPER_TOOL_IDS


@pytest.mark.parametrize(
    ("tool", "name", "fields", "category", "severity"),
    _TOOL_REPORTS,
    ids=[case[0] for case in _TOOL_REPORTS],
)
def test_each_tool_report_survives_ingestion_fusion_and_json_round_trip(
    tool, name, fields, category, severity, tmp_path,
) -> None:
    original = {"name": name, "filename": "Vault.sol", **fields}
    if "address" not in fields and tool not in {"maian", "securify", "sfuzz", "smartian", "sailfish"}:
        original["line"] = 17
    enriched = _enrich_report_with_categories(
        {"findings": [original]}, tool, _load_mapping(),
    )["findings"][0]
    tool_dir = tmp_path / tool
    tool_dir.mkdir()
    (tool_dir / "result.json").write_text(
        json.dumps({"findings": [enriched]}), encoding="utf-8",
    )
    parsed = load_per_tool_findings_from_run_dir(tmp_path, {tool})
    findings = engine._normalize_raw_findings(tool, parsed.get(tool, []))

    assert len(findings) == 1
    assert findings[0].category == category
    assert findings[0].severity == severity
    assert type(findings[0].severity) is type(severity)
    assert findings[0].raw == enriched
    report = fuse_reports({tool: findings}, _single_tool_plan(tool, category))
    payload = json.loads(json.dumps(compact_fused_report_payload(report)))
    assert payload["category_results"][0]["tools"][tool]["findings"] == [enriched]
    assert len(payload["findings"]) == 1


@pytest.mark.parametrize("tool", ["vandal", "mythril", "conkas"])
@pytest.mark.parametrize("projected", [False, True])
def test_bytecode_instruction_addresses_do_not_collapse_during_fusion(
    tool, projected, tmp_path,
) -> None:
    original = [
        {"category": "reentrancy", "filename": "Vault.rt.hex", "address": address}
        for address in (0, 16)
    ]
    raw_findings = original
    if projected:
        tool_dir = tmp_path / tool
        tool_dir.mkdir()
        (tool_dir / "result.json").write_text(
            json.dumps({"findings": original}), encoding="utf-8",
        )
        raw_findings = load_per_tool_findings_from_run_dir(tmp_path, {tool})[tool]
    findings = engine._normalize_raw_findings(tool, raw_findings)
    report = fuse_reports({tool: findings}, _single_tool_plan(tool, "reentrancy"))

    assert [finding.location for finding in findings] == [
        "Vault.rt.hex:pc:0", "Vault.rt.hex:pc:16",
    ]
    assert len(report.findings) == 2
    assert report.deduplicated_count == 0


@pytest.mark.parametrize("address", [0, 16])
@pytest.mark.parametrize("source", ["raw", "run_dir", "generic"])
def test_pc_fusion_keeps_contract_identity_and_same_contract_cross_tool_matches(
    address, source, tmp_path,
) -> None:
    tools = ["mythril", "conkas"]
    originals = {
        "mythril": [
            {
                "category": "reentrancy", "filename": "Bundle.sol",
                "contract": contract, "address": address, "severity": "High",
            }
            for contract in ("VaultA", "VaultB")
        ],
        "conkas": [{
            "category": "reentrancy", "filename": "Bundle.sol",
            "contract": "VaultA", "address": address, "severity": "High",
        }],
    }
    raw_by_tool = originals
    if source != "raw":
        for tool in tools:
            # Exercise restoration of the logical input without changing the
            # analyzer-owned contract or staged filename in raw provenance.
            for finding in originals[tool]:
                finding["filename"] = f"staged/{tool}/Bundle.rt.hex"
            path = tmp_path / tool / "result.json" if source == "run_dir" else tmp_path / f"{tool}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                REPORT_INPUT_FILENAME_KEY: "Bundle.sol",
                "findings": originals[tool],
            }), encoding="utf-8")
        loader = load_per_tool_findings_from_run_dir if source == "run_dir" else load_per_tool_findings
        raw_by_tool = loader(tmp_path, set(tools))
    findings_by_tool = {
        tool: engine._normalize_raw_findings(tool, raw_by_tool[tool])
        for tool in tools
    }
    composition = CompositionPlan(
        selected_tool_ids=tools, primary_tool_id="mythril",
        complementary_tool_ids=["conkas"],
        category_owners={"reentrancy": tools},
    )
    report = fuse_reports(findings_by_tool, composition)
    restored = FusedReport.model_validate_json(report.model_dump_json())

    assert len(restored.findings) == 2
    assert restored.deduplicated_count == 1
    by_location = {finding.location: finding for finding in restored.findings}
    vault_a = by_location[f"Bundle.sol:contract:VaultA:pc:{address}"]
    vault_b = by_location[f"Bundle.sol:contract:VaultB:pc:{address}"]
    assert vault_a.source_tools == tools
    assert vault_b.source_tools == ["mythril"]
    assert [finding.raw for finding in vault_a.raw_findings] == [
        originals["mythril"][0], originals["conkas"][0],
    ]
    assert [finding.raw for finding in vault_b.raw_findings] == [originals["mythril"][1]]


def test_source_line_takes_priority_over_instruction_address() -> None:
    finding = engine._normalize_raw_findings(
        "mythril",
        [{"category": "reentrancy", "filename": "Vault.sol", "contract": "Vault", "line": 17, "address": 0}],
    )[0]
    assert finding.location == "Vault.sol:17"


@pytest.mark.parametrize("execution_path", ["runner", "native"])
def test_staged_bytecode_filenames_do_not_prevent_cross_tool_fusion(
    execution_path, tmp_path, monkeypatch,
) -> None:
    target = tmp_path / "Vault.rt.hex"
    target.write_text("6000", encoding="utf-8")
    results = tmp_path / "reports"
    names = {"mythril": "Dependence on tx.origin", "vandal": "OriginUsed"}

    def write_report(tool, staged, output):
        output.mkdir(parents=True, exist_ok=True)
        (output / "result.json").write_text(json.dumps({
            "findings": [{"name": names[tool], "filename": str(staged), "address": 0}],
        }), encoding="utf-8")

    if execution_path == "runner":
        def fake_process(_command, **kwargs):
            request = json.loads(kwargs["input_text"])
            tool = request["tool_id"]
            write_report(tool, tmp_path / f"{tool}-staged" / target.name, Path(request["out_dir"]))
            return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

        monkeypatch.setattr(runner, "run_process_with_deadline", fake_process)
        for tool in names:
            assert runner._run_adapter_with_deadline(
                tool, target, results / tool,
                target_root=target, smartbugs_dir=None, timeout=10,
                gptscan_timeout=10, openai_api_key="", openai_api_base="",
                mapping=_load_mapping(), quarantine_root=tmp_path / "quarantine",
                input_kind="runtime",
            ) == 0
        raw_by_tool = load_per_tool_findings_from_run_dir(results, set(names))
    else:
        smartbugs = tmp_path / "smartbugs"
        smartbugs.mkdir()
        monkeypatch.setattr(execution, "DEFAULT_SMARTBUGS_DIR", smartbugs)

        def fake_process(command, **_kwargs):
            tool = command[command.index("-t") + 1]
            staged = Path(command[command.index("-f") + 1])
            output = Path(command[command.index("--results") + 1])
            write_report(tool, staged, output)
            return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

        monkeypatch.setattr(execution, "run_process_with_deadline", fake_process)
        completed = execution._native_smartbugs_execute(ExecutionResult(
            status="planned", target_path=str(target), results_root=str(results),
            selected_tool_ids=list(names), primary_tool_id="mythril",
            execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        ))
        assert completed.status == "executed"
        raw_by_tool = completed.per_tool_findings

    findings = {
        tool: engine._normalize_raw_findings(tool, raw_by_tool[tool])
        for tool in names
    }
    composition = CompositionPlan(
        selected_tool_ids=list(names), primary_tool_id="mythril",
        complementary_tool_ids=["vandal"],
        category_owners={"access_control": list(names)},
    )
    report = fuse_reports(findings, composition)
    assert len(report.findings) == 1
    assert report.findings[0].location == f"{target}:pc:0"
    assert report.findings[0].source_tools == list(names)
    assert all(finding.raw["filename"] != str(target) for finding in report.findings[0].raw_findings)


@pytest.mark.parametrize("confidence", ["NaN", "Infinity", -1, 1000])
def test_invalid_confidence_is_consistent_between_raw_and_json_ingestion(
    confidence, tmp_path,
) -> None:
    original = {"category": "reentrancy", "confidence": confidence}
    direct = engine._normalize_raw_findings("slither", [original])[0]
    tool_dir = tmp_path / "slither"
    tool_dir.mkdir()
    (tool_dir / "result.json").write_text(
        json.dumps({"findings": [original]}), encoding="utf-8",
    )
    parsed = load_per_tool_findings_from_run_dir(tmp_path, {"slither"})
    projected = engine._normalize_raw_findings("slither", parsed["slither"])[0]

    assert direct.confidence is None
    assert projected.confidence is None
    assert direct.raw == projected.raw == original


def test_maian_verified_leak_is_not_confused_with_unverified_leak() -> None:
    report = _enrich_report_with_categories(
        {"findings": [{"name": "Ether leak (verified)"}, {"name": "Ether leak"}]},
        "maian", _load_mapping(),
    )
    accepted, ignored = report["findings"]
    assert accepted["category"] == "access_control"
    assert not accepted.get("ignored")
    assert ignored["ignored"] is True


def test_gptscan_keeps_severity_and_original_metadata_for_every_location() -> None:
    item = {
        "code": "MWE-207: Unauthorized Transfer",
        "severity": "HIGH",
        "title": "Unauthorized transfer",
        "description": "A transfer lacks authorization",
        "recommendation": "Check the caller",
        "affectedFiles": [
            {"filePath": filename, "range": {"start": {"line": line}, "end": {"line": line}}}
            for filename, line in (("Vault.sol", 17), ("Token.sol", 23))
        ],
    }
    report = runner._normalize_gptscan_report({"success": True, "results": [item]})

    assert len(report["findings"]) == 2
    for finding in report["findings"]:
        assert finding["severity"] == "HIGH"
        assert finding["recommendation"] == item["recommendation"]
        assert finding["affectedFiles"] == item["affectedFiles"]
    normalized = engine._normalize_raw_findings("gptscan", report["findings"])
    assert "Recommendation: Check the caller" in normalized[0].explanation


def test_gptscan_restores_original_paths_after_temporary_source_staging(tmp_path, monkeypatch) -> None:
    main = tmp_path / "gptscan" / "main.py"
    main.parent.mkdir()
    main.write_text("# parser test", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    target = project / "Vault.sol"
    target.write_text("contract Vault {}", encoding="utf-8")
    monkeypatch.setattr(runner, "GPTSCAN_MAIN", main)
    monkeypatch.setattr(runner, "GPTSCAN_PY", Path(sys.executable))
    monkeypatch.setattr(runner, "_run_solc_select", lambda *_args, **_kwargs: True)

    def fake_stream(_command, **kwargs):
        env = kwargs["env"]
        staged = Path(env["LAKES_GPTSCAN_SOURCE"]) / "Vault.sol"
        Path(env["LAKES_GPTSCAN_OUTPUT"]).write_text(json.dumps({
            "success": True,
            "results": [{
                "code": "MWE-207: Unauthorized Transfer",
                "severity": "HIGH",
                "affectedFiles": [{"filePath": str(staged), "range": {"start": {"line": 17}}}],
            }],
        }), encoding="utf-8")
        return 0

    monkeypatch.setattr(runner, "_stream_process", fake_stream)
    out = tmp_path / "out"
    assert runner._run_gptscan(target, out, "", 10, "https://example.invalid", target_root=project) == 0
    report = json.loads((out / "result.json").read_text(encoding="utf-8"))
    assert report["findings"][0]["filename"] == str(target)
    finding = engine._normalize_raw_findings("gptscan", report["findings"])[0]
    assert finding.location == f"{target}:17"


@pytest.mark.parametrize("affected_files", [[], [None]])
def test_gptscan_retains_findings_without_valid_locations(affected_files) -> None:
    report = runner._normalize_gptscan_report({
        "success": True,
        "results": [{"code": "MWE-207", "severity": "HIGH", "affectedFiles": affected_files}],
    })
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "HIGH"


def _load_overlay_parser(tool: str, monkeypatch):
    # SmartBugs supplies these dependencies in Docker; parser tests only need
    # its error hook and no optional manticore.yml metadata.
    sb = ModuleType("sb")
    parse_utils = ModuleType("sb.parse_utils")
    parse_utils.errors_fails = lambda *_args, **_kwargs: (set(), set())
    sb.parse_utils = parse_utils
    monkeypatch.setitem(sys.modules, "sb", sb)
    monkeypatch.setitem(sys.modules, "sb.parse_utils", parse_utils)
    yaml = ModuleType("yaml")
    yaml.safe_load = json.loads
    monkeypatch.setitem(sys.modules, "yaml", yaml)
    path = Path(__file__).resolve().parents[1] / "docker" / "smartbugs-tools" / tool / "parser.py"
    spec = importlib.util.spec_from_file_location(f"audit_{tool}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archive(filename: str, payload: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        entry = tarfile.TarInfo(filename)
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


@pytest.mark.parametrize("version", ["vulhunter-0.1", "vulhunter-0.2"])
def test_vulhunter_positionless_fallback_is_applied_per_vulnerability(version, monkeypatch) -> None:
    parser = _load_overlay_parser(version, monkeypatch)
    issues = [
        {"title": "reentrancy-eth", "severity": "High", "description": "Reentrancy", "positions": []},
        {"title": "integer-overflow", "severity": "Medium", "description": "Overflow", "positions": [[0, []]]},
    ]
    findings, _, errors, fails = parser.parse(
        0, ["analysis complete"], _archive("output.json", json.dumps(issues).encode()),
    )

    assert not errors and not fails
    assert [finding["name"] for finding in findings] == ["reentrancy-eth", "integer-overflow"]
    assert [finding["severity"] for finding in findings] == ["High", "Medium"]


def test_manticore_source_snippet_report_is_json_serializable(monkeypatch) -> None:
    parser = _load_overlay_parser("manticore-0.3.7", monkeypatch)
    findings, _, errors, fails = parser.parse(
        0,
        ["analysis complete"],
        _archive("mcore/global.findings", b"- Potential reentrancy vulnerability -\n  Solidity snippet:\n    17 target.call();\n"),
    )

    assert not errors and not fails
    restored = json.loads(json.dumps({"findings": findings}))["findings"]
    assert restored[0]["line"] == 17
    assert restored[0]["code"] == "    17 target.call();"


def test_sailfish_single_record_with_nested_metadata_keeps_its_bug_type(tmp_path) -> None:
    path = Path(__file__).resolve().parents[1] / "docker" / "runners" / "run_sailfish.py"
    spec = importlib.util.spec_from_file_location("audit_sailfish", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "sailfish_out"
    output.mkdir()
    (output / "dao_path_info.json").write_text(json.dumps({
        "bug_type": "dao",
        "file_name": "Vault.sol",
        "from_function": "withdraw",
        "trace": {"node": "call"},
    }), encoding="utf-8")

    findings, _ = module._collect_findings(output, tmp_path / "Vault.sol")
    assert len(findings) == 1
    assert findings[0]["name"] == "dao"
    assert "withdraw" in findings[0]["message"]
