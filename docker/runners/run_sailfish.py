#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IMAGE = "holmessherlock/sailfish"
PLATFORM = "linux/amd64"


def _build_report(
    sol_filename: str,
    solc_ver: str,
    rules: str,
    source_dir: Path,
    artifacts_dir: Path,
    log_file: Optional[Path] = None,
) -> Dict[str, Any]:
    return {
        "errors": [],
        "fails": [],
        "findings": [],
        "infos": [],
        "parser": {
            "tool": "sailfish",
            "image": IMAGE,
            "platform": PLATFORM,
            "solc_version": solc_ver,
            "rules": rules,
            "workspace_dir": str(source_dir),
            "artifacts_dir": str(artifacts_dir),
            "contract": sol_filename,
            "log_file": str(log_file) if log_file else "",
        },
    }


def _write_report(out_dir: Path, report: Dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return result_path


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return None


def _extract_error_summary_from_log(log_file: Path) -> str:
    try:
        lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    # Prefer Python exception line
    for line in reversed(lines):
        s = line.strip()
        if not s:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*Error:", s) or re.match(r"^[A-Za-z_][A-Za-z0-9_]*Exception:", s):
            return s
    # Fallback to last non-empty line
    for line in reversed(lines):
        s = line.strip()
        if s:
            return s
    return ""


def _strip_comments(text: str) -> str:
    out: List[str] = []
    i = 0
    n = len(text)
    in_block = False
    while i < n:
        if in_block:
            if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue
        if i + 1 < n and text[i] == "/" and text[i + 1] == "*":
            in_block = True
            i += 2
            continue
        if i + 1 < n and text[i] == "/" and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _extract_solc_version(sol_path: Path, default_solc_ver: str = "0.4.25") -> str:
    try:
        text = sol_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return default_solc_ver
    text = _strip_comments(text)
    specs = [m.group(1).strip() for m in re.finditer(r"pragma\s+solidity\s+([^;]+);", text, re.IGNORECASE)]
    if not specs:
        return default_solc_ver
    candidates: List[Tuple[int, int, int, str]] = []
    for spec in specs:
        m = re.search(r"(?:\^|~|>=|>|=)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", spec)
        if not m:
            continue
        raw = m.group(1)
        if raw.count(".") == 1:
            raw = f"{raw}.0"
        try:
            a, b, c = [int(x) for x in raw.split(".")[:3]]
        except ValueError:
            continue
        candidates.append((a, b, c, raw))
    if not candidates:
        return default_solc_ver
    candidates.sort(reverse=True)
    return candidates[0][3]


def _iter_contracts(path: Path) -> List[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() == ".sol" else []
    if path.is_dir():
        return sorted([p for p in path.rglob("*.sol") if p.is_file()])
    return []


def _parse_ver_tuple(ver: str) -> Optional[Tuple[int, int, int]]:
    s = str(ver).strip().lstrip("v")
    parts = s.split(".")
    if len(parts) < 2:
        return None
    nums: List[int] = []
    for p in parts[:3]:
        if not p.isdigit():
            return None
        nums.append(int(p))
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _discover_local_solc_bins() -> Dict[str, Path]:
    bins: Dict[str, Path] = {}
    candidates: List[Path] = []
    repo_root = Path(__file__).resolve().parent
    candidates.append(repo_root / "venv" / ".solc-select" / "artifacts")
    try:
        venv_root = Path(sys.executable).resolve().parent.parent
        candidates.append(venv_root / ".solc-select" / "artifacts")
    except Exception:
        pass
    candidates.append(Path.home() / ".solc-select" / "artifacts")

    for base in candidates:
        if not base.exists():
            continue
        for p in base.glob("solc-*"):
            if not p.is_dir():
                continue
            ver = p.name.replace("solc-", "", 1).lstrip("v")
            bin_path = p / f"solc-{ver}"
            if bin_path.exists() and bin_path.is_file():
                bins.setdefault(ver, bin_path.resolve())

    solcx_dir = Path.home() / ".solcx"
    if solcx_dir.exists():
        for p in solcx_dir.glob("solc-v*"):
            if not p.is_file():
                continue
            m = re.fullmatch(r"solc-v([0-9]+\.[0-9]+\.[0-9]+)", p.name)
            if not m:
                continue
            bins.setdefault(m.group(1), p.resolve())
    return bins


def _is_linux_elf(path: Path) -> bool:
    try:
        proc = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    desc = (proc.stdout or "").strip().lower()
    return ("elf" in desc) and ("linux" in desc or "gnu/linux" in desc or "sysv" in desc)


def _select_local_solc_bin(version: str, bins: Dict[str, Path]) -> Tuple[Optional[Path], Optional[str], str]:
    target = str(version).strip().lstrip("v")
    exact = bins.get(target)
    if exact:
        if _is_linux_elf(exact):
            return exact, target, f"local_exact:{target}"
        return None, None, f"local_exact_not_linux:{target}"

    t = _parse_ver_tuple(target)
    if not t:
        return None, None, f"local_invalid_target:{target}"
    return None, None, f"local_exact_not_found:{target}"


def _iter_path_entries(data: Any) -> List[Tuple[str, Dict[str, Any]]]:
    entries: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(data, dict):
        # A single record may also contain nested trace or analysis metadata.
        if any(k in data for k in ("bug_type", "from_function", "to_function", "state_variable", "file_name")):
            return [("", data)]
        # Case A: {"tod_symex_path_1.json": {...}, ...}
        nested = [(k, v) for k, v in data.items() if isinstance(v, dict)]
        if nested:
            for k, v in nested:
                entries.append((str(k), v))
            return entries
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            if isinstance(item, dict):
                entries.append((str(idx), item))
    return entries


def _symex_results(contract_out_dir: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for p in sorted(contract_out_dir.glob("*_symex_path_*.json")):
        data = _load_json(p)
        if isinstance(data, dict):
            out[p.name] = data
    return out


def _make_finding(
    record: Dict[str, Any],
    default_name: str,
    fallback_filename: str,
    source_path: Path,
    path_file: Path,
    symex: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    name = str(record.get("bug_type") or default_name)
    filename = str(record.get("file_name") or fallback_filename or source_path.name)

    parts: List[str] = []
    from_fn = record.get("from_function")
    to_fn = record.get("to_function")
    state_var = record.get("state_variable")
    if from_fn or to_fn:
        parts.append(f"path: {from_fn or '?'} -> {to_fn or '?'}")
    if state_var:
        parts.append(f"state_variable: {state_var}")
    if symex is not None:
        result = str(symex.get("result") or "")
        if result:
            parts.append(f"symex_result: {result}")
    parts.append(f"source: {path_file.name}")

    finding: Dict[str, Any] = {
        "name": name,
        "filename": filename,
        "message": " | ".join(parts),
    }
    return finding


def _collect_findings(sailfish_out: Path, source_path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    findings: List[Dict[str, Any]] = []
    infos: List[str] = []

    if not sailfish_out.exists():
        infos.append("sailfish_out directory not found")
        return findings, infos

    candidate_dirs: List[Path] = [p for p in sorted(sailfish_out.iterdir()) if p.is_dir()]
    if not candidate_dirs:
        candidate_dirs = [sailfish_out]

    for contract_dir in candidate_dirs:
        symex_by_name = _symex_results(contract_dir)
        path_info_files = sorted(contract_dir.glob("*_path_info.json"))
        if not path_info_files:
            continue
        for p in path_info_files:
            data = _load_json(p)
            if data is None:
                infos.append(f"invalid_json: {p}")
                continue
            entries = _iter_path_entries(data)
            if not entries:
                continue
            default_name = p.name.replace("_path_info.json", "")
            for entry_key, rec in entries:
                # If symex exists and is explicitly UNSAT, skip this static path
                symex = symex_by_name.get(entry_key) if entry_key else None
                if symex is not None:
                    symex_result = str(symex.get("result") or "").strip().upper()
                    if symex_result and symex_result == "UNSAT":
                        continue
                findings.append(
                    _make_finding(
                        record=rec,
                        default_name=default_name,
                        fallback_filename=source_path.name,
                        source_path=source_path,
                        path_file=p,
                        symex=symex,
                    )
                )

    # stable dedupe
    dedup: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        key = json.dumps(
            {
                "name": f.get("name", ""),
                "filename": f.get("filename", ""),
                "message": f.get("message", ""),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        dedup.setdefault(key, f)

    return list(dedup.values()), infos


def run_sailfish(
    workspace_dir: str | Path,
    sol_filename: str,
    solc_ver: str,
    rules: str = "DAO,TOD",
    proxy: Optional[str] = None,
    timeout: Optional[int] = 1000,
    raise_on_error: bool = False,
    artifacts_root: Optional[str | Path] = None,
) -> str:
    """
    Run Sailfish and always write a unified result json to:
      <artifacts_root>/sailfish_out/result.json

    Returns:
      str path of <artifacts_root>/sailfish_out
    """
    source_dir = Path(workspace_dir).expanduser().resolve()
    artifacts_dir = (
        Path(artifacts_root).expanduser().resolve()
        if artifacts_root is not None
        else source_dir
    )
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    source_path = source_dir / sol_filename
    sailfish_out = artifacts_dir / "sailfish_out"
    run_infos: List[str] = []

    if not source_path.exists():
        report = _build_report(sol_filename, solc_ver, rules, source_dir, artifacts_dir)
        report["errors"].append("INPUT_NOT_FOUND")
        report["fails"].append(f"source file not found: {source_path}")
        _write_report(sailfish_out, report)
        if raise_on_error:
            raise RuntimeError(f"Sailfish input missing: {source_path}")
        return str(sailfish_out)

    inner_src = "/src"
    inner_out = "/work"
    local_bins = _discover_local_solc_bins()
    local_solc_bin, selected_local_ver, local_note = _select_local_solc_bin(solc_ver, local_bins)
    run_infos.append(local_note)
    if selected_local_ver:
        run_infos.append(f"solc_selected:{selected_local_ver}")

    if local_solc_bin:
        inner_cmd = textwrap.dedent(
            f"""
        set -e
        cp /tmp/host_solc /tmp/solc
        chmod +x /tmp/solc
        python3 -c 'p=\"/root/sailfish/code/static_analysis/analysis/icfg.py\"; s=open(p,\"r\",encoding=\"utf-8\",errors=\"ignore\").read(); old=\"for key in from_to.keys():\\n                from_node = from_to[key][0]\\n                to_node = from_to[key][1]\"; new=\"for key in from_to.keys():\\n                if len(from_to.get(key, [])) < 2:\\n                    continue\\n                from_node = from_to[key][0]\\n                to_node = from_to[key][1]\\n                if not from_node._instructions:\\n                    continue\"; s = s.replace(old,new) if old in s else s; open(p,\"w\",encoding=\"utf-8\").write(s); print(\"[patch] icfg recursive guard applied\")'
        ln -sf /tmp/solc /usr/local/bin/solc
        mkdir -p {inner_out}/sailfish_out
        cd /root/sailfish/code/static_analysis/analysis
        python contractlint.py \
          -c {inner_src}/{sol_filename} \
          -o {inner_out}/sailfish_out \
          -r range \
          -p {rules} \
          -sv cvc4 \
          -oo \
          -sc /usr/local/bin/solc
        """
        ).strip()
    else:
        inner_cmd = textwrap.dedent(
            f"""
        set -e
        export SAILFISH_SOLC_VER="{solc_ver}"
        python3 - <<'PY'
import json
import os
import urllib.request

ver = os.environ.get("SAILFISH_SOLC_VER", "").strip().lstrip("v")
if not ver:
    raise SystemExit("empty SAILFISH_SOLC_VER")

base = "https://binaries.soliditylang.org/linux-amd64"
req = urllib.request.Request(base + "/list.json", headers={{"User-Agent": "Mozilla/5.0"}})
data = json.loads(urllib.request.urlopen(req, timeout=30).read().decode("utf-8", errors="ignore"))
releases = data.get("releases") or {{}}

fname = releases.get(ver) or releases.get("v" + ver)
if not fname:
    parts = ver.split(".")
    if len(parts) >= 2:
        prefix = "{{}}.{{}}.".format(parts[0], parts[1])
        cands = []
        for k, v in releases.items():
            kk = str(k).lstrip("v")
            if not kk.startswith(prefix):
                continue
            try:
                sem = tuple(int(x) for x in kk.split(".")[:3])
            except Exception:
                continue
            cands.append((sem, v, kk))
        if cands:
            cands.sort()
            _, fname, chosen = cands[-1]
            print("[solc] fallback {{}} -> {{}}".format(ver, chosen))

if not fname:
    raise AssertionError("solc version not found: " + ver)

bin_url = base + "/" + fname
req2 = urllib.request.Request(bin_url, headers={{"User-Agent": "Mozilla/5.0"}})
blob = urllib.request.urlopen(req2, timeout=60).read()
with open("/tmp/solc", "wb") as f:
    f.write(blob)
os.chmod("/tmp/solc", 0o755)
print("[solc] downloaded {{}} -> /tmp/solc".format(bin_url))
PY
        python3 -c 'p=\"/root/sailfish/code/static_analysis/analysis/icfg.py\"; s=open(p,\"r\",encoding=\"utf-8\",errors=\"ignore\").read(); old=\"for key in from_to.keys():\\n                from_node = from_to[key][0]\\n                to_node = from_to[key][1]\"; new=\"for key in from_to.keys():\\n                if len(from_to.get(key, [])) < 2:\\n                    continue\\n                from_node = from_to[key][0]\\n                to_node = from_to[key][1]\\n                if not from_node._instructions:\\n                    continue\"; s = s.replace(old,new) if old in s else s; open(p,\"w\",encoding=\"utf-8\").write(s); print(\"[patch] icfg recursive guard applied\")'
        ln -sf /tmp/solc /usr/local/bin/solc
        mkdir -p {inner_out}/sailfish_out
        cd /root/sailfish/code/static_analysis/analysis
        python contractlint.py \
          -c {inner_src}/{sol_filename} \
          -o {inner_out}/sailfish_out \
          -r range \
          -p {rules} \
          -sv cvc4 \
          -oo \
          -sc /usr/local/bin/solc
        """
        ).strip()

    extra_env: List[str] = []
    if proxy:
        extra_env.extend(["-e", f"HTTP_PROXY={proxy}", "-e", f"HTTPS_PROXY={proxy}"])

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--platform",
        PLATFORM,
        *extra_env,
    ]
    if local_solc_bin:
        docker_cmd += ["-v", f"{str(local_solc_bin)}:/tmp/host_solc:ro"]
    docker_cmd += [
        "-v",
        f"{str(source_dir)}:{inner_src}:ro",
        "-v",
        f"{str(artifacts_dir)}:{inner_out}",
        "-w",
        inner_out,
        IMAGE,
        "bash",
        "-lc",
        inner_cmd,
    ]

    start = datetime.datetime.now()
    log_file = artifacts_dir / f"sailfish_{start:%Y%m%d_%H%M%S}.log"

    try:
        res = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        timed_out = artifacts_dir / f"sailfish_timeout_{start:%Y%m%d_%H%M%S}.log"
        timed_out.write_text(
            f"Timed out after {timeout}s\n\nSTDOUT:\n{e.stdout or ''}\n\nSTDERR:\n{e.stderr or ''}",
            encoding="utf-8",
        )
        report = _build_report(sol_filename, solc_ver, rules, source_dir, artifacts_dir, timed_out)
        report["errors"].append("TIMEOUT")
        report["fails"].append(f"Sailfish timed out after {timeout}s")
        report["infos"].extend(run_infos)
        report["infos"].append(f"timeout_log: {timed_out}")
        _write_report(sailfish_out, report)
        if raise_on_error:
            raise RuntimeError(f"Sailfish timed out after {timeout}s, see {timed_out}") from e
        return str(sailfish_out)

    log_file.write_text((res.stdout or "") + (res.stderr or ""), encoding="utf-8")
    report = _build_report(sol_filename, solc_ver, rules, source_dir, artifacts_dir, log_file)

    if res.returncode != 0:
        report["errors"].append(f"EXIT_CODE_{res.returncode}")
        report["fails"].append("Sailfish process failed")
        detail = _extract_error_summary_from_log(log_file)
        if detail:
            report["fails"].append(detail)
        report["infos"].extend(run_infos)
        report["infos"].append(f"log_file: {log_file}")
        _write_report(sailfish_out, report)
        if raise_on_error:
            raise RuntimeError(f"Sailfish failed, see {log_file}")
        return str(sailfish_out)

    findings, infos = _collect_findings(sailfish_out, source_path)
    report["findings"] = findings
    report["infos"].extend(run_infos)
    report["infos"].extend(infos)
    report["infos"].append(f"log_file: {log_file}")
    _write_report(sailfish_out, report)
    return str(sailfish_out)


def run_sailfish_batch(
    contracts_root: str | Path,
    out_root: str | Path,
    rules: str = "DAO,TOD",
    proxy: Optional[str] = None,
    timeout: Optional[int] = 1000,
    default_solc_ver: str = "0.4.25",
) -> int:
    contracts_root = Path(contracts_root).expanduser().resolve()
    out_root = Path(out_root).expanduser().resolve()
    contracts = _iter_contracts(contracts_root)
    if not contracts:
        print(f"[batch] no .sol found: {contracts_root}")
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    total = len(contracts)
    failed = 0
    for idx, contract in enumerate(contracts, start=1):
        print(f"\n[batch] {idx}/{total} {contract}")
        solc_ver = _extract_solc_version(contract, default_solc_ver=default_solc_ver)
        print(f"[batch] solc={solc_ver}")
        workspace_dir = contract.parent
        try:
            rel = contract.relative_to(contracts_root)
        except ValueError:
            rel = Path(contract.name)
        raw_artifacts_dir = out_root / "_raw" / "sailfish" / rel
        output_path = run_sailfish(
            workspace_dir=workspace_dir,
            sol_filename=contract.name,
            solc_ver=solc_ver,
            rules=rules,
            proxy=proxy,
            timeout=timeout,
            raise_on_error=False,
            artifacts_root=raw_artifacts_dir,
        )
        src_result = Path(output_path) / "result.json"
        if not src_result.exists():
            failed += 1
            print(f"[batch] missing result.json: {src_result}")
            continue
        dst_dir = out_root / "sailfish" / rel
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_result, dst_dir / "result.json")
        try:
            result_obj = json.loads(src_result.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            result_obj = {}
        if (result_obj.get("errors") or []):
            failed += 1

    print(f"\n[batch_total] contracts={total} failed={failed} succeeded={total - failed}")
    return 0 if failed == 0 else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Sailfish and output unified result.json")
    parser.add_argument("workspace_dir", nargs="?", help="Directory containing source file")
    parser.add_argument("sol_filename", nargs="?", help="Solidity filename under workspace_dir")
    parser.add_argument("solc_ver", nargs="?", help="solc version for Sailfish")
    parser.add_argument(
        "--artifacts_root",
        default="",
        help="Single mode: directory for logs/sailfish_out/result.json (default: workspace_dir)",
    )
    parser.add_argument("--batch_dir", default="", help="Batch mode: root directory that contains .sol files")
    parser.add_argument("--batch_out_root", default="", help="Batch mode: output root for copied result.json")
    parser.add_argument("--default_solc_ver", default="0.4.25", help="Fallback solc version when pragma missing")
    parser.add_argument("--rules", default="DAO,TOD", help="Sailfish patterns, default DAO,TOD")
    parser.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy")
    parser.add_argument("--timeout", type=int, default=1000, help="Timeout seconds")
    parser.add_argument("--raise_on_error", action="store_true", help="Raise exception on tool failure")
    args = parser.parse_args()

    if args.batch_dir:
        if not args.batch_out_root:
            print("--batch_out_root is required when using --batch_dir", file=sys.stderr)
            return 2
        return run_sailfish_batch(
            contracts_root=args.batch_dir,
            out_root=args.batch_out_root,
            rules=args.rules,
            proxy=args.proxy,
            timeout=args.timeout,
            default_solc_ver=args.default_solc_ver,
        )

    if not args.workspace_dir or not args.sol_filename or not args.solc_ver:
        print("single mode needs: workspace_dir sol_filename solc_ver", file=sys.stderr)
        return 2

    out = run_sailfish(
        workspace_dir=args.workspace_dir,
        sol_filename=args.sol_filename,
        solc_ver=args.solc_ver,
        rules=args.rules,
        proxy=args.proxy,
        timeout=args.timeout,
        raise_on_error=args.raise_on_error,
        artifacts_root=args.artifacts_root if args.artifacts_root else None,
    )
    print(out)
    result = _load_json(Path(out) / "result.json")
    if not isinstance(result, dict):
        return 2
    errors = [str(value).upper() for value in (result.get("errors") or [])]
    if any("TIMEOUT" in value for value in errors):
        return 124
    if errors or (result.get("fails") or []):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
