"""Pinned SmartBugs parser with JSON-safe Solidity snippets.

Based on smartbugs/smartbugs@89c16bb tools/manticore-0.3.7/parser.py.
The upstream parser stores snippet bytes in findings, which breaks result.json.
"""

import io
import tarfile
from typing import Optional

import yaml

import sb.parse_utils


VERSION = "2026/10/23"
FINDINGS: set[str] = set()


def parse_file(lines: list[bytes]) -> list[dict]:
    findings: list[dict] = []
    snippet = False
    finding: dict = {}
    for line in lines:
        if snippet:
            snippet = False
            parts = line.split()
            if finding and parts:
                finding["line"] = int(parts[0])
                finding["code"] = line.decode("utf-8", errors="replace")
        elif line.startswith(b"  Solidity snippet:"):
            snippet = True
        elif line[0:1] == b"-":
            finding = {"name": line[1:-2].strip().decode("utf-8", errors="ignore")}
            findings.append(finding)
    return findings


def parse(
    exit_code: Optional[int], log: list[str], output: Optional[bytes]
) -> tuple[list[dict], set[str], set[str], set[str]]:
    findings: list[dict] = []
    infos: set[str] = set()
    errors, fails = sb.parse_utils.errors_fails(exit_code, log)
    if any("Invalid solc compilation" in line for line in log):
        errors.add("solc error")
    try:
        with io.BytesIO(output) as buffer, tarfile.open(fileobj=buffer) as archive:
            for filename in archive.getnames():
                if not filename.endswith("/global.findings"):
                    continue
                try:
                    contents = archive.extractfile(filename).read()
                    parsed = parse_file(contents.splitlines())
                except Exception as exc:
                    fails.add(f"problem extracting {filename} from output archive: {exc}")
                    continue
                metadata = None
                try:
                    metadata_path = filename.replace("/global.findings", "/manticore.yml")
                    metadata = yaml.safe_load(archive.extractfile(metadata_path).read())
                except Exception:
                    infos.add("manticore.yml not found")
                source, contract = None, None
                if isinstance(metadata, dict):
                    cli = metadata.get("cli")
                    if isinstance(cli, dict):
                        contract = cli.get("contract")
                        argv = cli.get("argv")
                        if isinstance(argv, list) and argv:
                            source = argv[0]
                for finding in parsed:
                    if source:
                        finding["filename"] = source
                    if contract:
                        finding["contract"] = contract
                    findings.append(finding)
    except Exception as exc:
        fails.add(f"error parsing results: {exc}")
    return findings, infos, errors, fails
