"""Tool JSON -> Finding building blocks shared by every collector: the
fingerprint recipe and the severity mapping table (docs/spec.md).
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_WHITESPACE = re.compile(r"\s+")
_DIGIT = re.compile(r"\d")


def _location_key(location: dict) -> str:
    if "file" in location:
        return str(location["file"])
    if "url" in location:
        method = location.get("method") or ""
        path = urlsplit(str(location["url"])).path
        return f"{method} {path}"
    if "package" in location:
        return f"{location.get('ecosystem', '')} {location['package']}"
    raise ValueError(f"unrecognized location shape: {location!r}")


def _evidence_norm(evidence: str | None) -> str:
    if not evidence:
        return ""
    collapsed = _WHITESPACE.sub(" ", evidence.strip())
    return _DIGIT.sub("0", collapsed)


def fingerprint(source: str, rule: str, location: dict, evidence: str | None) -> str:
    """`fp-` + first 16 hex chars of sha256(source | rule | location_key |
    evidence_norm). Line numbers and digits in evidence never change it; the
    file/path/package and the rule do.
    """
    key = "|".join([source, rule, _location_key(location), _evidence_norm(evidence)])
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"fp-{digest[:16]}"


def severity(source: str, raw: dict) -> str:
    """Dispatch on `source`; see tests/README.md for the expected `raw` shape
    per source and docs/spec.md for the table.
    """
    if source == "bandit":
        return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}[raw["issue_severity"]]
    if source == "semgrep":
        if raw.get("metadata_severity") == "CRITICAL":
            return "critical"
        return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}[raw["severity"]]
    if source in ("pip-audit", "osv"):
        cvss = raw.get("cvss")
        if cvss is None:
            return "medium"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    if source == "gitleaks":
        return "critical" if raw.get("in_tree") else "high"
    if source == "zap":
        return {3: "high", 2: "medium", 1: "low", 0: "info"}[int(raw["riskcode"])]
    if source == "ratelimit":
        return "medium"
    raise ValueError(f"unknown source: {source!r}")
