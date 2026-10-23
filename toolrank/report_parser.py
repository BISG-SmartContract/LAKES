"""Report parser: extract normalized findings from tool execution output.

Supports:
- SARIF v2.1.0 (standard for static analysis tools)
- SmartBugs JSON wrapper format
- Generic JSON findings arrays
- Plain JSON with tool-specific key mapping

The parser scans a results directory for recognized file formats,
extracts findings, and returns them as raw dicts suitable for
``_normalize_raw_findings()`` in ``engine.py``.
"""
from __future__ import annotations

from copy import deepcopy
import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Set

from toolrank.categories import normalize_category

logger = logging.getLogger(__name__)


# Explicitly distinguishes parser-owned normalized projections from arbitrary
# analyzer JSON.  Structural guessing is unsafe because a legitimate finding
# may itself contain keys such as ``raw``, ``category``, and ``location``.
PARSER_PROJECTION_MARKER = "__lakes_parser_finding_projection_v1__"
REPORT_INPUT_FILENAME_KEY = "__lakes_original_input_filename__"


def normalize_finding_severity(item: Dict[str, Any]) -> Any:
    """Keep a tool's severity label or code, including zero-valued codes."""
    for key in ("severity", "impact", "level"):
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def normalize_finding_confidence(value: Any) -> float | None:
    """Accept finite probabilities or percentages without repeated rescaling."""
    try:
        confidence = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 100.0:
        return None
    return confidence / 100.0 if confidence > 1.0 else confidence


def _position_integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            return None
    return value if isinstance(value, int) and value >= 0 else None


def normalize_finding_location(item: Dict[str, Any]) -> str:
    """Prefer source lines, then contract-qualified bytecode instruction PCs."""
    location = str(item.get("location") or "").strip()
    if location:
        return location
    filename = next(
        (str(item[key]).strip() for key in ("file", "filename", "sourceFile") if item.get(key)),
        "",
    )
    if not filename:
        return ""
    for key in ("line", "lineno", "startLine"):
        line = _position_integer(item.get(key))
        if line is not None and line > 0:
            return f"{filename}:{line}"
    address = _position_integer(item.get("address"))
    if address is not None:
        contract = item.get("contract")
        if isinstance(contract, str) and contract.strip():
            return f"{filename}:contract:{contract.strip()}:pc:{address}"
        return f"{filename}:pc:{address}"
    return filename


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_per_tool_findings_from_run_dir(
    run_dir: str | Path,
    selected_tool_ids: Set[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Read findings from a run-scoped temp directory.

    **Primary path** — used when the execution pipeline creates a per-run
    temp dir containing only this run's selected tools' reports.

    Expected layout (runner convention)::

        run_dir/{tool_id}/{contract_stem}.json   → unified JSON with ``findings``
        run_dir/{tool_id}/.../result.json        → SmartBugs raw result

    No recursive scanning, no SARIF guessing, no multi-contract mixing.
    Only *selected_tool_ids* are read.
    """
    root = Path(run_dir)
    if not root.exists():
        return {}

    per_tool: Dict[str, List[Dict[str, Any]]] = {}
    for tool_id in selected_tool_ids:
        tool_dir = root / tool_id
        if not tool_dir.is_dir():
            continue

        findings: List[Dict[str, Any]] = []

        # Primary: flat {stem}.json files written by runner
        for jf in sorted(tool_dir.glob("*.json")):
            if jf.name in ("fusion_plan.json", "config.json", "metadata.json",
                           "gptscan_output.json"):
                continue
            parsed = _parse_json_file(jf, tool_id)
            if parsed:
                findings.extend(parsed)

        # Fallback: result.json inside a subdirectory (SmartBugs raw)
        if not findings:
            for rj in sorted(tool_dir.rglob("result.json")):
                if rj.parent == tool_dir:
                    continue  # already checked above
                parsed = _parse_json_file(rj, tool_id)
                if parsed:
                    findings.extend(parsed)

        if findings:
            per_tool[tool_id] = findings

    return per_tool


def load_per_tool_findings(
    results_root: str | Path,
    selected_tool_ids: Set[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Scan *results_root* and parse findings for each selected tool.

    **Generic fallback** — supports multiple conventions including SARIF.
    Prefer ``load_per_tool_findings_from_run_dir`` for run-scoped temp dirs.
    """
    root = Path(results_root)
    if not root.exists():
        return {}

    per_tool: Dict[str, List[Dict[str, Any]]] = {}
    for tool_id in selected_tool_ids:
        findings = _scan_tool_results(root, tool_id)
        if findings:
            per_tool[tool_id] = findings

    return per_tool


# ---------------------------------------------------------------------------
# Internal: per-tool scanning
# ---------------------------------------------------------------------------


def _scan_tool_results(
    root: Path, tool_id: str
) -> List[Dict[str, Any]]:
    """Try multiple directory/file conventions for a single tool.

    Primary path (runner convention):
      ``results_root/{tool_id}/{contract_stem}.json``  — unified JSON with ``findings``
      ``results_root/{tool_id}/**/result.json``  — SmartBugs raw result

    Fallback paths:
      ``results_root/{tool_id}.sarif``  — single SARIF file
      ``results_root/{tool_id}.json``  — single JSON file
      Recursive SARIF/JSON scan in tool subdirectory
    """
    findings: List[Dict[str, Any]] = []

    # --- Primary: tool subdirectory with unified JSON reports ---
    tool_dir = root / tool_id
    if tool_dir.is_dir():
        # First: flat {stem}.json files (runner convention: _run_one copies here)
        for jf in sorted(tool_dir.glob("*.json")):
            if jf.name in ("fusion_plan.json", "config.json", "metadata.json",
                           "gptscan_output.json"):
                continue
            parsed = _parse_json_file(jf, tool_id)
            if parsed:
                findings.extend(parsed)

        # Second: result.json inside subdirectories (SmartBugs raw convention)
        if not findings:
            for rj in sorted(tool_dir.rglob("result.json")):
                if rj.parent == tool_dir:
                    continue  # already handled above
                parsed = _parse_json_file(rj, tool_id)
                if parsed:
                    findings.extend(parsed)

        # Third (fallback): SARIF files in tool subdirectory
        if not findings:
            for sarif in sorted(tool_dir.rglob("*.sarif")):
                findings.extend(_parse_sarif_file(sarif, tool_id))

    if findings:
        return findings

    # --- Fallback: single file at root level ---
    sarif_file = root / f"{tool_id}.sarif"
    if sarif_file.is_file():
        findings.extend(_parse_sarif_file(sarif_file, tool_id))

    json_file = root / f"{tool_id}.json"
    if json_file.is_file() and not findings:
        findings.extend(_parse_json_file(json_file, tool_id))

    return findings


# ---------------------------------------------------------------------------
# SARIF parser
# ---------------------------------------------------------------------------


def _parse_sarif_file(
    path: Path, tool_id: str
) -> List[Dict[str, Any]]:
    """Parse a SARIF v2.1.0 file into normalized finding dicts."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse SARIF %s: %s", path, exc)
        return []

    findings: List[Dict[str, Any]] = []
    runs = data.get("runs", [])
    for run in runs:
        # Build rule map for category/description lookup
        rules = {}
        tool_component = run.get("tool", {}).get("driver", {})
        for rule in tool_component.get("rules", []):
            rules[rule.get("id", "")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # Category: prefer rule shortDescription, tags, or ruleId
            tags = rule.get("properties", {}).get("tags", [])
            category = normalize_category(
                _first_tag_as_category(tags)
                or rule.get("shortDescription", {}).get("text", "")
                or rule_id
                or "unknown"
            )

            # Location
            location = _sarif_location(result)

            # Severity / confidence
            level = result.get("level", "warning")
            severity_map = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
            severity = severity_map.get(level, "medium")

            rank = result.get("rank", result.get("properties", {}).get("confidence"))
            confidence = normalize_finding_confidence(rank)

            # Explanation
            message = result.get("message", {}).get("text", "")
            explanation = message or rule.get("fullDescription", {}).get("text", "")

            findings.append({
                PARSER_PROJECTION_MARKER: True,
                "source_tool": tool_id,
                "category": category,
                "location": location,
                "severity": severity,
                "confidence": confidence,
                "explanation": explanation,
                "raw": deepcopy(result),
            })

    return findings


def _sarif_location(result: Dict[str, Any]) -> str:
    """Extract a human-readable location string from a SARIF result."""
    locations = result.get("locations", [])
    if not locations:
        return ""
    loc = locations[0]
    phys = loc.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    uri = artifact.get("uri", "")
    region = phys.get("region", {})
    start_line = region.get("startLine")
    if uri and start_line:
        return f"{uri}:{start_line}"
    return uri or ""


def _first_tag_as_category(tags: List[str]) -> str:
    """Use the first SARIF tag as a finding category if it looks like a vuln type."""
    vuln_tags = {
        "reentrancy", "access_control", "arithmetic", "unchecked_low_level_calls",
        "denial_of_service", "bad_randomness", "front_running", "time_manipulation",
        "short_addresses", "unknown_unknowns", "overflow", "underflow",
        "integer_overflow", "integer_underflow", "tx_origin", "delegatecall",
        "selfdestruct", "uninitialized_storage",
    }
    for tag in tags:
        normalized = tag.lower().replace("-", "_").replace(" ", "_")
        if normalized in vuln_tags:
            return normalized
    return tags[0] if tags else ""


# ---------------------------------------------------------------------------
# JSON parser (SmartBugs wrapper + generic)
# ---------------------------------------------------------------------------


def _parse_json_file(
    path: Path, tool_id: str
) -> List[Dict[str, Any]]:
    """Parse a JSON file into normalized finding dicts.

    Handles multiple formats:
    1. SmartBugs wrapper: ``{"findings": [...]}`` or ``{"results": [...]}``
    2. Direct findings array: ``[{...}, ...]``
    3. Tool-specific nested: ``{"analysis": {"findings": [...]}}``

    Findings marked as ``ignored: true`` (from runner's canonical category
    mapping) are filtered out.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse JSON %s: %s", path, exc)
        return []

    raw_list = _extract_findings_array(data)
    if not raw_list:
        return []

    findings: List[Dict[str, Any]] = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        # Filter out IGNORE findings from runner canonical mapping
        if item.get("ignored") is True:
            continue
        if item.get("category") == "IGNORE":
            continue
        finding = _normalize_json_finding(item, tool_id)
        input_filename = data.get(REPORT_INPUT_FILENAME_KEY) if isinstance(data, dict) else None
        if isinstance(input_filename, str) and input_filename:
            # Bytecode adapters run private temporary inputs. Use their logical
            # input for fusion while retaining the analyzer's original filename.
            finding["location"] = normalize_finding_location({
                **item,
                "location": "",
                "file": input_filename,
            })
        findings.append(finding)

    return findings


def _extract_findings_array(data: Any) -> List[Any]:
    """Extract the findings array from various JSON wrapper formats."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Try common wrapper keys
        for key in ("findings", "results", "vulnerabilities", "issues", "detectors"):
            if key in data and isinstance(data[key], list):
                return data[key]

        # SmartBugs nested: {"analysis": {"findings": [...]}}
        analysis = data.get("analysis")
        if isinstance(analysis, dict):
            for key in ("findings", "results"):
                if key in analysis and isinstance(analysis[key], list):
                    return analysis[key]

    return []


def _normalize_json_finding(
    item: Dict[str, Any], tool_id: str
) -> Dict[str, Any]:
    """Normalize a single JSON finding dict to canonical keys."""
    # Category
    category = (
        item.get("category")
        or item.get("vulnerability_type")
        or item.get("type")
        or item.get("check")
        or item.get("name")
        or item.get("title")
        or "unknown"
    )

    # Location
    location = normalize_finding_location(item)

    # Severity
    severity = normalize_finding_severity(item)

    # Confidence
    confidence = normalize_finding_confidence(item.get("confidence"))

    # Explanation
    explanation = (
        item.get("explanation")
        or item.get("description")
        or item.get("message")
        or item.get("info")
        or ""
    )

    return {
        PARSER_PROJECTION_MARKER: True,
        "source_tool": item.get("source_tool", tool_id),
        "category": normalize_category(category),
        "location": location,
        "severity": severity,
        "confidence": confidence,
        "explanation": explanation,
        "raw": deepcopy(item),
    }
