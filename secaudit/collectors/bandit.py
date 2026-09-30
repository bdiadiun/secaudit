"""bandit -r <repo> -f json -q -x <excludes> — test paths excluded (spec inv. 19)."""
from __future__ import annotations

import json
import shutil  # noqa: F401 - re-exported so tests can monkeypatch bandit.shutil.which
import subprocess
from fnmatch import fnmatch
from pathlib import PurePosixPath

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool, relpath

SOURCE = "bandit"

# `assert` and `/tmp` in tests are not security findings: 4036 of 4328 on the
# first live run. Secrets in tests are gitleaks' job. bandit's -x takes globs.
EXCLUDE_DIRS = (".venv", "node_modules", ".git", "tests", "test", "e2e")
EXCLUDE_GLOBS = ("**/test_*.py", "**/*_test.py", "**/conftest.py")


def is_test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in {"tests", "test", "e2e"} for part in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    return name == "conftest.py" or fnmatch(name, "test_*.py") or fnmatch(name, "*_test.py")


def tool_version() -> str | None:
    exe = find_tool("bandit")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    first_line = out.stdout.strip().splitlines()[0] if out.stdout.strip() else None
    return first_line


def run(ctx: Context) -> dict:
    exe = find_tool("bandit")
    if exe is None:
        raise ToolMissing("bandit not installed")
    exclude = ",".join([*(f"{ctx.repo}/{d}" for d in EXCLUDE_DIRS), *(f"{ctx.repo}/{g}" for g in EXCLUDE_GLOBS)])
    result = subprocess.run(
        [exe, "-r", str(ctx.repo), "-f", "json", "-q", "-x", exclude],
        capture_output=True, text=True, check=False,
    )
    # bandit exits 1 when it *has* findings, not when it fails, and prints a
    # "Working... 100%" progress line to stdout ahead of the JSON when stdout
    # isn't a TTY (observed live against the orchestrator repo) even with
    # -q. Parse from the first '{' instead of trusting the whole stdout to
    # be JSON; only raise when there's no JSON object at all.
    stdout = result.stdout or ""
    start = stdout.find("{")
    if start == -1:
        raise ValueError(f"bandit produced no JSON output (exit {result.returncode})")
    return json.loads(stdout[start:])


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for item in raw.get("results", []):
        file = relpath(item["filename"], ctx.repo)
        if is_test_path(file):
            continue
        location = {"file": file, "line": item.get("line_number")}
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
