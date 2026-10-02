"""semgrep <--config packs from ctx.stack> --json --quiet <repo>

Operator decision: `--config auto` is rejected — it calls home to the
semgrep registry to guess a ruleset, silently, on every run. The stack is
instead passed explicitly (`scan --stack`) and mapped to a fixed set of
registry packs (still network-fetched, hence SECAUDIT_OFFLINE below, but
never guessed).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool, relpath

SOURCE = "semgrep"

# lang -> registry packs; node/javascript/typescript share one pack set
# because a stack like "node:react" doesn't commit to a specific dialect.
_LANG_PACKS: dict[str, list[str]] = {
    "python": ["p/python"],
    "node": ["p/javascript", "p/typescript", "p/nodejs"],
    "javascript": ["p/javascript", "p/typescript", "p/nodejs"],
    "typescript": ["p/javascript", "p/typescript", "p/nodejs"],
    "ruby": ["p/ruby"],
    "go": ["p/golang"],
    "rust": ["p/rust"],
    "php": ["p/php"],
    "jvm": ["p/java"],
    "java": ["p/java"],
}

_FRAMEWORK_PACKS: dict[str, str] = {
    "fastapi": "p/fastapi",
    "flask": "p/flask",
    "django": "p/django",
    "jinja2": "p/jinja2",
    "react": "p/react",
    "express": "p/express",
    "next": "p/nextjs",
    "rails": "p/rails",
}


def _config_packs(stack: dict[str, list[str]], repo: Path | None) -> list[str]:
    """Registry packs for `--config`, in a stable order, deduplicated.
    Unknown langs/frameworks contribute nothing — they are not an error by
    themselves, only an empty overall result is (see `run`).
    """
    packs: list[str] = []
    for lang, frameworks in stack.items():
        for pack in _LANG_PACKS.get(lang.lower(), []):
            if pack not in packs:
                packs.append(pack)
        for fw in frameworks:
            pack = _FRAMEWORK_PACKS.get(fw.lower())
            if pack and pack not in packs:
                packs.append(pack)
    if packs and repo is not None and (repo / "Dockerfile").is_file():
        packs.append("p/dockerfile")
    return packs


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
    packs = _config_packs(ctx.stack, ctx.repo)
    if not packs:
        raise ToolMissing(f"no semgrep ruleset for stack {ctx.stack!r}")
    exe = find_tool("semgrep")
    if exe is None:
        raise ToolMissing("semgrep not installed")
    config_args = [arg for pack in packs for arg in ("--config", pack)]
    result = subprocess.run(
        [exe, *config_args, "--json", "--quiet", str(ctx.repo)],
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
