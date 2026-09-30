"""pip-audit -r <requirements> when present, else pip-audit --local inside
the repo's .venv if it exists, else skipped. Output -f json.

Module is named pip_audit (valid identifier); the finding source string is
still "pip-audit" per docs/spec.md.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing

SOURCE = "pip-audit"


def tool_version() -> str | None:
    exe = shutil.which("pip-audit")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> dict:
    exe = shutil.which("pip-audit")
    if exe is None:
        raise ToolMissing("pip-audit not installed")
    requirements = ctx.repo / "requirements.txt" if ctx.repo else None
    if requirements is not None and requirements.exists():
        cmd = [exe, "-r", str(requirements), "-f", "json"]
    elif ctx.repo is not None and (ctx.repo / ".venv").exists():
        cmd = [exe, "--local", "-f", "json"]
    else:
        raise ToolMissing("no requirements file or virtualenv found")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=ctx.repo)
    return json.loads(result.stdout or "{}")


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for dependency in raw.get("dependencies", []):
        for vuln in dependency.get("vulns", []):
            location = {
                "package": dependency["name"],
                "version": dependency["version"],
                "ecosystem": "PyPI",
            }
            evidence = vuln.get("description")
            fix_versions = vuln.get("fix_versions") or []
            findings.append(Finding(
                id=fingerprint(SOURCE, vuln["id"], location, evidence),
                source=SOURCE,
                rule=vuln["id"],
                severity=severity(SOURCE, {"cvss": vuln.get("cvss")}),
                confidence="medium",
                cwe=None,
                title=f"{dependency['name']} {vuln['id']}",
                location=location,
                evidence=evidence,
                remediation=f"upgrade to {', '.join(fix_versions)}" if fix_versions else None,
                references=vuln.get("aliases", []),
                status="new",
                accepted=None,
            ))
    return findings
