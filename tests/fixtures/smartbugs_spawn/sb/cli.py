import argparse
from pathlib import Path
import re
from types import SimpleNamespace

import sb.analysis
import sb.semantic_version


class Tool:
    bin = False

    def __init__(self, mode):
        self.mode = mode

    def command(self, filename, timeout, bindir, main):
        return ["analyze", filename, str(timeout), bindir, main]

    def entrypoint(self, filename, timeout, bindir, main):
        return ["entrypoint", filename]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t")
    parser.add_argument("-f", type=Path)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--runtime", action="store_true")
    for flag in ("--continue-on-errors", "--sarif", "--json"):
        parser.add_argument(flag, action="store_true")
    args = parser.parse_args()
    mode = "runtime" if args.runtime else "solidity" if args.f.suffix == ".sol" else "bytecode"
    versions = re.findall(r"pragma\s+solidity\s+([^;]+);", args.f.read_text())
    compiler = (
        sb.semantic_version.match(versions, {"0.8.19", "0.8.24", "0.8.30"})
        if mode == "solidity"
        else None
    )
    task = SimpleNamespace(
        absfn=str(args.f.resolve()),
        tool=Tool(mode),
        settings=SimpleNamespace(timeout=args.timeout, main=False),
        solc_path=None,
        solc_version=compiler,
    )
    args.results.mkdir(parents=True, exist_ok=True)
    sb.analysis.run(task, args.results / "result.json")
