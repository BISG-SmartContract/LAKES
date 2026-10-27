#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from toolrank import docker_runtime

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def strip_ansi(s: str) -> str:
    return ANSI_ESCAPE_RE.sub("", s)


def norm_sev(s: Optional[str]) -> str:
    s = (s or "").strip().upper()
    mapping = {
        "INFO": "Info",
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
    }
    return mapping.get(s, s.capitalize() if s else "Info")


def parse_securify_output(text: str, filename: str) -> Dict[str, Any]:
    # Normalize line endings and remove any ANSI/TTY control codes.
    text = strip_ansi(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Split blocks by 2+ newlines
    blocks = [b.strip("\n") for b in re.split(r"\n{2,}", text) if b.strip()]
    findings: List[Dict[str, Any]] = []

    for b in blocks:
        if not re.search(r"^Severity:\s*", b, flags=re.M):
            continue

        sev = pat = typ = contract = None
        line: Optional[int] = None
        desc_lines: List[str] = []
        source_lines: List[str] = []

        in_desc = False
        in_source = False

        for ln in b.splitlines():
            m = re.match(r"^Severity:\s*(.+?)\s*$", ln)
            if m:
                sev = m.group(1).strip()
                in_desc = in_source = False
                continue

            m = re.match(r"^Pattern:\s*(.+?)\s*$", ln)
            if m:
                pat = m.group(1).strip()
                in_desc = in_source = False
                continue

            m = re.match(r"^Description:\s*(.*)\s*$", ln)
            if m:
                in_desc = True
                in_source = False
                desc_lines.append(m.group(1).rstrip())
                continue

            # Description continuation lines are indented
            if in_desc and re.match(r"^\s{2,}\S", ln):
                desc_lines.append(ln.strip())
                continue

            m = re.match(r"^Type:\s*(.+?)\s*$", ln)
            if m:
                typ = m.group(1).strip()
                in_desc = in_source = False
                continue

            m = re.match(r"^Contract:\s*(.+?)\s*$", ln)
            if m:
                contract = m.group(1).strip()
                in_desc = in_source = False
                continue

            m = re.match(r"^Line:\s*(\d+)\s*$", ln)
            if m:
                line = int(m.group(1))
                in_desc = in_source = False
                continue

            if re.match(r"^Source:\s*$", ln):
                in_source = True
                in_desc = False
                continue

            if in_source and ln.startswith(">"):
                # keep caret-lines etc
                source_lines.append(ln[1:].lstrip())

        description = "\n".join([x for x in desc_lines if x is not None]).strip()

        findings.append(
            {
                "address": None,
                "contract": contract,
                "filename": filename,
                "function": None,
                "line": line,
                "name": pat,
                "severity": norm_sev(sev),
                "type": typ,
                "description": description,
                "message": description or (pat or ""),
                "source": source_lines,
                "raw": b,  # keep original block for debugging
            }
        )

    return {
        "errors": [],
        "fails": [],
        "findings": findings,
        "infos": [],
        "parser": {
            "id": "securify",
            "mode": "solidity",
            "version": datetime.date.today().isoformat(),
        },
    }


def run_securify_docker(
    contract_path: str,
    project_root: Optional[str],
    image: str,
    platform: Optional[str],
    docker_bin: str,
    use_sudo: bool,
    tty: bool,
) -> Tuple[int, str, str, str]:
    """Run securify via docker.

    This builds and runs the exact command form:
      sudo docker run --rm -it -v <contract_dir>:/share <image> /share/<contract>.sol

    Note:
    - If `tty=True` (i.e. `-t`), we intentionally do NOT capture stdout/stderr because pseudo-TTY output
      is not reliably capturable across platforms. In that mode, output will stream to the terminal.
    - For JSON conversion, prefer `tty=False` so we can capture output.
    """

    contract_path = os.path.abspath(contract_path)
    contract_dir = os.path.abspath(project_root) if project_root else os.path.dirname(contract_path)
    docker_runtime.configure(contract_path, contract_dir)
    try:
        contract_file = os.path.relpath(contract_path, contract_dir)
    except ValueError:
        contract_file = os.path.basename(contract_path)
    if contract_file == ".." or contract_file.startswith(f"..{os.sep}"):
        raise ValueError("contract must be inside project root")

    cmd: List[str] = []
    if use_sudo:
        cmd.append("sudo")

    # Build the exact docker command
    cmd += [docker_bin, "run", "--rm", "-i", *docker_runtime.cli_args("securify2")]
    if tty:
        cmd.append("-t")
    if platform:
        cmd += ["--platform", platform]
    cmd += ["-v", f"{docker_runtime.shared_path(contract_dir)}:/share", image, "--interpreter", f"/share/{contract_file}"]
    cmd_str = " ".join(cmd)

    if tty:
        # Stream output to terminal (best for sudo prompts / interactive runs)
        p = subprocess.run(cmd)
        return p.returncode, "", "", cmd_str

    # Capture output (best for parsing to JSON)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr, cmd_str


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run securify in docker and convert its text output to JSON."
    )
    ap.add_argument("contract", help="Full path to the .sol contract file")
    ap.add_argument(
        "-o",
        "--out",
        default="result.json",
        help="Output JSON path (default: result.json)",
    )
    ap.add_argument(
        "--project-root",
        default=None,
        help="Project root mounted at /share so Solidity imports remain available",
    )
    ap.add_argument(
        "--image",
        default="securify",
        help="Docker image name (default: securify)",
    )
    ap.add_argument(
        "--docker",
        default="docker",
        help="Docker executable to use (default: docker)",
    )
    ap.add_argument(
        "--sudo",
        action="store_true",
        help="Use sudo when invoking docker (useful if your docker requires sudo)",
    )
    ap.add_argument(
        "--tty",
        action="store_true",
        help="Allocate a TTY for docker run (equivalent to `-t`, i.e. `-it`)",
    )
    ap.add_argument(
        "--platform",
        default=None,
        help='Docker platform, e.g. "linux/amd64" (optional)',
    )
    ap.add_argument(
        "--debug-cmd",
        action="store_true",
        help="Print the exact docker command that will be executed",
    )
    args = ap.parse_args()

    rc, out, err, cmd_str = run_securify_docker(
        args.contract,
        args.project_root,
        args.image,
        args.platform,
        args.docker,
        args.sudo,
        args.tty,
    )

    if args.debug_cmd:
        sys.stderr.write(f"Executing: {cmd_str}\n")
        sys.stderr.write(f"Captured stdout bytes: {len(out.encode('utf-8', errors='ignore'))}\n")
        sys.stderr.write(f"Captured stderr bytes: {len(err.encode('utf-8', errors='ignore'))}\n")

    if rc != 0:
        sys.stderr.write("securify docker run failed.\n")
        sys.stderr.write(err + "\n")
        sys.stderr.write(out + "\n")
        return rc

    # Securify output may be written to stderr (and some docker/sudo combos split output).
    combined = "\n".join([out or "", err or ""]).strip()
    result = parse_securify_output(combined, os.path.abspath(args.contract))

    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Wrote {len(result['findings'])} findings to {out_path}")

    if len(result["findings"]) == 0 and combined:
        raw_path = out_path + ".raw.txt"
        try:
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(combined)
            sys.stderr.write(f"Note: 0 findings parsed; wrote captured output to {raw_path}\n")
        except Exception as e:
            sys.stderr.write(f"Note: 0 findings parsed; failed to write raw output: {e}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
