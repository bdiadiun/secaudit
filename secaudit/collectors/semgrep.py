"""semgrep --config auto --json --quiet <repo>

--config auto needs network; SECAUDIT_OFFLINE=1 makes this collector report
itself missing instead of hanging on a DNS lookup, same as an absent binary.
"""
from __future__ import annotations

import json
import os
import subprocess

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool, relpath

SOURCE = "semgrep"


def tool_version() -> str | None:
    exe = find_tool("semgrep")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> dict:
    if os.environ.get("SECAUDIT_OFFLINE") == "1":
        raise ToolMissing("semgrep rules need network")
    exe = find_tool("semgrep")
    if exe is None:
        raise ToolMissing("semgrep not installed")
    result = subprocess.run(
        [exe, "--config", "auto", "--json", "--quiet", str(ctx.repo)],
        capture_output=True, text=True, check=False,
    )
    return json.loads(result.stdout or "{}")


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for item in raw.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        location = {
            "file": relpath(item["path"], ctx.repo),
            "line": item.get("start", {}).get("line"),
        }
        evidence = extra.get("lines")
        cwe_list = metadata.get("cwe") or []
        findings.append(Finding(
            id=fingerprint(SOURCE, item["check_id"], location, evidence),
            source=SOURCE,
            rule=item["check_id"],
            severity=severity(SOURCE, {
                "severity": extra.get("severity"),
                "metadata_severity": metadata.get("severity"),
            }),
            confidence="medium",
            cwe=cwe_list[0] if cwe_list else None,
            title=extra.get("message", item["check_id"]),
            location=location,
            evidence=evidence,
            remediation=extra.get("fix") or extra.get("fix_regex"),
            references=metadata.get("references", []),
            status="new",
            accepted=None,
        ))
    return findings
