"""Run the production adapter and real shared compiler in a built LAKES image."""

import json
import os
from pathlib import Path
import sys

from toolrank import compilation, execution, runner
from toolrank.schemas import CompositionPlan, ExecutionSchedule


case_root = Path(sys.argv[1])
mode = sys.argv[2]
project_root = case_root / "project"
entry = project_root / "contracts/Main.sol"
target = entry if mode in {"file", "legacy"} else entry.parent
out_dir = case_root / "result"
version = "0.8.30" if mode == "multiple_entries" else "0.8.19"
gptscan_root = Path(os.environ["LAKES_GPTSCAN_ROOT"])
# GPTScan resolves its grammar and whitelist relative to src/. Replace only
# its LLM entrypoint inside this disposable container, keeping the real tasks
# module and compiler. Adapter subprocesses then use the same probe too.
probe = gptscan_root / "src/main.py"
probe.write_text(Path(__file__).with_name("compile_probe.py").read_text())
runner.GPTSCAN_MAIN = probe
runner.GPTSCAN_PY = gptscan_root / ".venv/bin/python"
# A stale parent setting must neither select the explicit inputs nor enable
# the project compiler on the legacy path.
os.environ["LAKES_GPTSCAN_ENTRYPOINTS"] = '["stale.sol"]'
if mode in {"file", "directory"}:
    plan = execution.build_execution_plan(
        target, out_dir,
        CompositionPlan(
            selected_tool_ids=["gptscan"], primary_tool_id="gptscan",
            execution_schedule=ExecutionSchedule(tool_timeout_seconds=30),
        ),
        project_root=project_root, write_lakes_output=False,
    )
    completed = (
        execution.execute_plan(plan)
        if mode == "file" else execution._native_smartbugs_execute(plan)
    )
    assert completed.status == "executed", completed.stderr_tail
    (out_dir / "execution.json").write_text(completed.model_dump_json())
else:
    rc = runner._run_gptscan(
        entry, out_dir, "", 30, "", target_root=target,
        project_root=project_root if mode != "legacy" else None,
    )
    assert rc == 0, f"GPTScan compilation adapter exited with {rc}"
if mode != "legacy":
    binary = Path.home() / f".solc-select/artifacts/solc-{version}/solc-{version}"
    bundle = compilation.build_compilation_bundle(
        target, ["smartian", "vandal"], project_root=project_root,
        installed_compilers={version: binary},
    )
    assert bundle.manifest.status == "READY", bundle.manifest.failure_reason
    assert bundle.manifest.compiler_version == version
    for name in bundle.manifest.entrypoints:
        for tool in ("smartian", "vandal"):
            assert bundle.route_for(tool, name) is not None
    compilation.write_compilation_manifest(bundle, out_dir)
print(json.dumps({"mode": mode, "result": str(out_dir / "result.json")}))
