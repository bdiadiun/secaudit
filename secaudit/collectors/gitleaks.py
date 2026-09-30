"""gitleaks detect -s <repo> -f json -r <tmp>

A finding whose File exists in the current worktree is "working tree"
(critical), else it only lives in history (high). The secret is redacted
in-collector so the raw value never reaches Finding.evidence.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool

SOURCE = "gitleaks"


def tool_version() -> str | None:
    exe = find_tool("gitleaks")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> list[dict]:
    exe = find_tool("gitleaks")
    if exe is None:
        raise ToolMissing("gitleaks not installed")
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "gitleaks.json"
        subprocess.run(
            [exe, "detect", "-s", str(ctx.repo), "-f", "json", "-r", str(out_path)],
            capture_output=True, text=True, check=False,
        )
        if not out_path.exists():
            return []
        return json.loads(out_path.read_text() or "[]")


def _redact(match: str, secret: str) -> str:
    if not secret:
        return match
    return match.replace(secret, f"<REDACTED:{len(secret)}>")


def parse(raw: list[dict], ctx: Context) -> list[Finding]:
    findings = []
    for item in raw:
        secret = item.get("Secret") or ""
        evidence = _redact(item.get("Match", ""), secret)
        location = {"file": item["File"], "line": item.get("StartLine")}
        in_tree = bool(ctx.repo) and (Path(ctx.repo) / item["File"]).exists()
        findings.append(Finding(
            id=fingerprint(SOURCE, item["RuleID"], location, evidence),
            source=SOURCE,
            rule=item["RuleID"],
            severity=severity(SOURCE, {"in_tree": in_tree}),
            confidence="high",
            cwe=None,
            title=item.get("Description", item["RuleID"]),
            location=location,
            evidence=evidence,
            remediation="rotate the secret, then purge it from history",
            references=[],
            status="new",
            accepted=None,
        ))
    return findings
