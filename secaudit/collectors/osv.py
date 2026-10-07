"""osv-scanner --format json -r <repo>; scans every lockfile it finds."""
from __future__ import annotations

import json
import subprocess

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool, load_json

SOURCE = "osv"


def tool_version() -> str | None:
    exe = find_tool("osv-scanner")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> dict:
    exe = find_tool("osv-scanner")
    if exe is None:
        raise ToolMissing("osv-scanner not installed")
    result = subprocess.run(
        [exe, "--format", "json", "-r", str(ctx.repo)],
        capture_output=True, text=True, check=False,
    )
    # 128 = "no lockfiles found": a clean scan, with nothing on stdout.
    if result.returncode == 128:
        return {}
    return load_json(result, "osv-scanner", ok_codes=(0, 1))


def _cvss(vuln: dict) -> float | None:
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        if score is None:
            continue
        try:
            return float(score)
        except (TypeError, ValueError):
            continue
    db_score = (vuln.get("database_specific") or {}).get("cvss", {}).get("score")
    if db_score is not None:
        return float(db_score)
    return None


def _fix_versions(vuln: dict) -> list[str]:
    versions = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    versions.append(event["fixed"])
    return versions


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for result in raw.get("results", []):
        for package_entry in result.get("packages", []):
            package = package_entry["package"]
            for vuln in package_entry.get("vulnerabilities", []):
                location = {
                    "package": package["name"],
                    "version": package.get("version", ""),
                    "ecosystem": package.get("ecosystem", "PyPI"),
                }
                evidence = vuln.get("summary")
                fix_versions = _fix_versions(vuln)
                findings.append(Finding(
                    id=fingerprint(SOURCE, vuln["id"], location, evidence),
                    source=SOURCE,
                    rule=vuln["id"],
                    severity=severity(SOURCE, {"cvss": _cvss(vuln)}),
                    confidence="medium",
                    cwe=None,
                    title=vuln.get("summary", vuln["id"]),
                    location=location,
                    evidence=evidence,
                    remediation=f"upgrade to {', '.join(fix_versions)}" if fix_versions else None,
                    references=[],
                    status="new",
                    accepted=None,
                ))
    return findings
