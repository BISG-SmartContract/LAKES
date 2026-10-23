from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

from toolrank.categories import DASP10_CATEGORIES, normalize_category


# Paper tool universe (20 tools: 18 paper + sailfish/smartian) used by the external SmartBugs runner.
TOOL_NAME_MAP: Dict[str, str] = {
    "slither": "slither",
    "gptscan": "gptscan",
    "vulhunter": "vulhunter",
    "mandohgt": "mando-hgt",
    "mythril": "mythril",
    "oyente": "oyente",
    "osiris": "osiris",
    "securify": "securify",
    "securify2": "securify2",
    "smartcheck": "smartcheck",
    "solhint": "solhint",
    "maian": "maian",
    "vandal": "vandal",
    "manticore": "manticore",
    "sfuzz": "sfuzz",
    "confuzzius": "confuzzius",
    "conkas": "conkas",
    "honeybadger": "honeybadger",
    "sailfish": "sailfish",
    "smartian": "smartian",
}

PAPER_TOOL_IDS: Set[str] = set(TOOL_NAME_MAP.values())

_LEGACY_TOOL_ALIASES: Dict[str, str] = {
    "semgrep": "semgrep",
    "madmax": "madmax",
    "pakala": "pakala",
    "teether": "teether",
}

CANONICAL_CATEGORIES = {category.upper() for category in DASP10_CATEGORIES}

DEFAULT_VULNERABILITY_MAPPING_CSV = Path(__file__).resolve().parent / "config" / "vulnerabilities_mapping.csv"

def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _normalize_tool_name(name: str) -> str:
    normalized = name.strip().lower()
    for char in [" ", "-", "_"]:
        normalized = normalized.replace(char, "")
    return normalized


def _map_tool_name(tool_name: str) -> str:
    normalized = _normalize_tool_name(tool_name)
    mapped = TOOL_NAME_MAP.get(normalized)
    if mapped:
        return mapped
    mapped = _LEGACY_TOOL_ALIASES.get(normalized)
    if mapped:
        print(f"[warn] '{tool_name}' is a legacy tool not in current paper universe", file=sys.stderr)
        return mapped
    fallback = tool_name.strip().lower()
    print(f"[warn] unknown tool '{tool_name}', fallback to '{fallback}'", file=sys.stderr)
    return fallback


def _parse_tools(raw: str) -> List[str]:
    if not raw:
        return []
    out: List[str] = []
    seen = set()
    cleaned = raw.replace(chr(0xFF0C), ",")
    for part in cleaned.split(","):
        name = part.strip()
        if not name:
            continue
        key = _normalize_tool_name(name)
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def _norm_label(label: str) -> str:
    return normalize_category(label).upper()


def _normalize_vuln_name(name: str) -> str:
    normalized = name.strip().lower()
    normalized = re.sub(r"\bswc[-\s]*\d+\b", "", normalized)
    normalized = re.sub(r"\bmwe[-\s]*\d+\b\s*:?\s*", "", normalized)
    normalized = normalized.replace("-", " ").replace("_", " ")
    normalized = re.sub(r"\bto a\b", "to", normalized)
    normalized = re.sub(r"[^a-z0-9\s]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _is_truthy(value: object) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _map_finding_to_canonical_category(
    tool: str, finding_name: str, mapping: Dict[Tuple[str, str], str]
) -> tuple[str, bool]:
    tool_norm = _normalize_tool_name(tool)
    vuln_norm = _normalize_vuln_name(finding_name)
    category = mapping.get((tool_norm, vuln_norm))
    if category is None:
        return ("", False)
    if category == "IGNORE":
        return ("IGNORE", True)
    return (normalize_category(category), False)


def _enrich_report_with_categories(
    report: dict, tool: str, mapping: Dict[Tuple[str, str], str]
) -> dict:
    findings = report.get("findings")
    if not isinstance(findings, list):
        return report
    enriched = []
    for finding in findings:
        if not isinstance(finding, dict):
            enriched.append(finding)
            continue
        raw_name = finding.get("name") or finding.get("title") or finding.get("check") or ""
        canonical, is_ignored = _map_finding_to_canonical_category(tool, raw_name, mapping)
        enriched_finding = dict(finding)
        enriched_finding["raw_name"] = raw_name
        if is_ignored:
            enriched_finding["category"] = "IGNORE"
            enriched_finding["ignored"] = True
        elif canonical:
            enriched_finding["category"] = canonical
        elif enriched_finding.get("category"):
            enriched_finding["category"] = normalize_category(
                enriched_finding["category"]
            )
        enriched.append(enriched_finding)
    enriched_report = dict(report)
    enriched_report["findings"] = enriched
    return enriched_report


def _load_mapping(mapping_path: Path = DEFAULT_VULNERABILITY_MAPPING_CSV) -> Dict[Tuple[str, str], str]:
    if not mapping_path.exists():
        _die(f"Mapping CSV not found: {mapping_path}", 1)
    mapping: Dict[Tuple[str, str], str] = {}
    with mapping_path.open("r", encoding="utf-8", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            tool_raw = row.get("Tool") or row.get("Tools") or ""
            tool = _normalize_tool_name(str(tool_raw))
            vulnerability = (row.get("Vulnerability name") or "").strip()
            if not tool or not vulnerability:
                continue
            vuln_norm = _normalize_vuln_name(vulnerability)
            if "Category" in row:
                category = (row.get("Category") or "").strip()
                if category:
                    mapping[(tool, vuln_norm)] = _norm_label(category)
                continue
            if _is_truthy(row.get("Ignore")):
                mapping[(tool, vuln_norm)] = "IGNORE"
                continue
            category_cols = [
                key for key in row.keys() if key not in {"Tools", "Tool", "Vulnerability name", "Ignore"}
            ]
            chosen = None
            for key in sorted(category_cols):
                if _is_truthy(row.get(key)):
                    chosen = key
                    break
            if chosen:
                mapping[(tool, vuln_norm)] = _norm_label(chosen)
    return mapping
