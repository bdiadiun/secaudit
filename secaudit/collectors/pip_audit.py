"""pip-audit against the **target** repo's own environment, never secaudit's:
when `<repo>/.venv/bin/python` exists, freeze it with that interpreter (not
sys.executable) and audit the frozen list with `-r ... --disable-pip` so
pip-audit resolves nothing and installs nothing. Else fall back to
`<repo>/requirements.txt`. Else skipped. `--local` is never used: it would
audit the venv secaudit itself runs from.

Module is named pip_audit (valid identifier); the finding source string is
still "pip-audit" per docs/spec.md.
"""
from __future__ import annotations

import json
import os
import shutil  # noqa: F401 - re-exported so tests can monkeypatch pip_audit.shutil.which
import subprocess
import sys
import tempfile
from pathlib import Path

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool, load_json

SOURCE = "pip-audit"


def tool_version() -> str | None:
    exe = find_tool("pip-audit")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def _candidate_pythons(repo: Path | None) -> list[Path]:
    """Where the TARGET's interpreter may live, most specific first.

    `<repo>/.venv` is the plain case. An orchestrator keeps a task's venv next
    to the worktree (`<worktree>.venv`, `<worktree>.venv-linux` in a Linux
    container) so git never sees it — a live run skipped pip-audit on seven
    reports in a row before this list existed. `VIRTUAL_ENV` is last and only
    when it is not the environment secaudit itself runs in.
    """
    out: list[Path] = []
    if repo is not None:
        repo = Path(repo)
        out.append(repo / ".venv" / "bin" / "python")
        out.append(repo.parent / f"{repo.name}.venv" / "bin" / "python")
        out.append(repo.parent / f"{repo.name}.venv-linux" / "bin" / "python")
    venv = os.environ.get("VIRTUAL_ENV")
    if venv and Path(venv).resolve() != Path(sys.prefix).resolve():
        out.append(Path(venv) / "bin" / "python")
    return out


def _freeze(python: Path, cwd: Path | None) -> str:
    result = subprocess.run(
        [str(python), "-m", "pip", "freeze"],
        capture_output=True, text=True, check=False, cwd=cwd,
    )
    return result.stdout or ""


def run(ctx: Context) -> dict:
    exe = find_tool("pip-audit")
    if exe is None:
        raise ToolMissing("pip-audit not installed")

    candidates = _candidate_pythons(ctx.repo)
    target_python = next((c for c in candidates if c.exists()), None)
    if target_python is not None:
        frozen = _freeze(target_python, ctx.repo)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tmp:
            tmp.write(frozen)
            tmp_path = tmp.name
        try:
            cmd = [exe, "-r", tmp_path, "--disable-pip", "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=ctx.repo)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return load_json(result, "pip-audit", ok_codes=(0, 1))

    requirements = ctx.repo / "requirements.txt" if ctx.repo else None
    if requirements is not None and requirements.exists():
        cmd = [exe, "-r", str(requirements), "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=ctx.repo)
        return load_json(result, "pip-audit", ok_codes=(0, 1))

    raise ToolMissing(
            "no virtualenv or requirements file; looked for "
            + ", ".join(str(c) for c in candidates)
        )


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
