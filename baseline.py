"""Baseline support for incremental security scanning.

A baseline suppresses findings that already exist in a known-good scan, while
keeping newly introduced findings visible. Matching is deliberately based on
stable semantic fields; for reproducibility, generate and apply the baseline
against the same project-relative path layout.
"""

import hashlib
import json
import os
from typing import Dict, Iterable, List, Set


def finding_key(finding, root=None):
    """Return a stable identity for a finding, excluding volatile scan metadata."""
    path = os.path.abspath(finding.file)
    if root:
        try:
            path = os.path.relpath(path, os.path.abspath(root))
        except ValueError:
            pass
    path = path.replace(os.sep, "/")
    payload = "|".join(
        str(v) for v in (
            finding.rule_id,
            finding.language,
            finding.category,
            path,
            finding.message,
            finding.snippet,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_baseline(findings: Iterable, root=None) -> Dict:
    findings = list(findings)
    entries = sorted({finding_key(f, root=root) for f in findings})
    return {
        "tool": "SentinelLint",
        "formatVersion": 1,
        "findingCount": len(entries),
        "findings": entries,
    }


def save_baseline(path: str, findings: Iterable, root=None) -> None:
    data = build_baseline(findings, root=root)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def load_baseline(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("tool") != "SentinelLint":
        raise ValueError("baseline was not produced by SentinelLint")
    if data.get("formatVersion") != 1:
        raise ValueError("unsupported SentinelLint baseline format")
    findings = data.get("findings")
    if not isinstance(findings, list) or not all(isinstance(v, str) for v in findings):
        raise ValueError("baseline findings must be a list of strings")
    return set(findings)


def filter_baseline(findings: Iterable, baseline_keys: Set[str], root=None):
    """Return (new_findings, suppressed_count)."""
    new = []
    suppressed = 0
    for finding in findings:
        if finding_key(finding, root=root) in baseline_keys:
            suppressed += 1
        else:
            new.append(finding)
    return new, suppressed
