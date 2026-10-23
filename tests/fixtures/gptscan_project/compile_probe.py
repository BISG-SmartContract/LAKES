"""Exercise vendored GPTScan's compiler without calling its LLM pipeline."""

import argparse
import json
from pathlib import Path
import os

import tasks


parser = argparse.ArgumentParser()
parser.add_argument("-s", required=True)
parser.add_argument("-o", required=True)
parser.add_argument("-k", required=True)
args = parser.parse_args()
source_root = Path(args.s).resolve()
falcon = tasks.compile_project(str(source_root))
assert falcon is not None
units = falcon.crytic_compile.compilation_units.values()
source_names = sorted(
    Path(name).resolve().relative_to(source_root).as_posix()
    for name in falcon.source_code
)
main = next(contract for contract in falcon.contracts if contract.name == "Main")
operations = sum(len(node.irs) for function in main.functions for node in function.nodes)
assert operations > 0, "Falcon must parse and analyze the real solc AST"
payload = {
    "success": True,
    "results": [{
        "code": "compile_probe",
        "affectedFiles": [{"filePath": str(source_root / name)} for name in source_names],
    }],
    "probe": {
        "sources": source_names,
        "contracts": sorted(contract.name for contract in falcon.contracts),
        "compilers": sorted({unit.compiler_version.version for unit in units}),
        "entrypoints": json.loads(os.environ["LAKES_GPTSCAN_ENTRYPOINTS"])
        if "LAKES_GPTSCAN_ENTRYPOINTS" in os.environ else None,
        "main_ir_operations": operations,
    },
}
Path(args.o).write_text(json.dumps(payload), encoding="utf-8")
