"""bandit -r <repo> -f json -x <repo>/.venv,<repo>/node_modules"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, relpath

SOURCE = "bandit"


def tool_version() -> str | None:
    exe = shutil.which("bandit")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    first_line = out.stdout.strip().splitlines()[0] if out.stdout.strip() else None
    return first_line


def run(ctx: Context) -> dict:
    exe = shutil.which("bandit")
    if exe is None:
        raise ToolMissing("bandit not installed")
    exclude = f"{ctx.repo}/.venv,{ctx.repo}/node_modules"
    result = subprocess.run(
        [exe, "-r", str(ctx.repo), "-f", "json", "-x", exclude],
        capture_output=True, text=True, check=False,
    )
    return json.loads(result.stdout or "{}")


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for item in raw.get("results", []):
        location = {"file": relpath(item["filename"], ctx.repo), "line": item.get("line_number")}
        evidence = item.get("issue_text")
        cwe = f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else None
        more_info = item.get("more_info")
        findings.append(Finding(
            id=fingerprint(SOURCE, item["test_id"], location, evidence),
            source=SOURCE,
            rule=item["test_id"],
            severity=severity(SOURCE, {"issue_severity": item["issue_severity"]}),
            confidence=item.get("issue_confidence", "medium").lower(),
            cwe=cwe,
            title=evidence or item["test_id"],
            location=location,
            evidence=evidence,
            remediation=more_info,
            references=[more_info] if more_info else [],
            status="new",
            accepted=None,
        ))
    return findings
