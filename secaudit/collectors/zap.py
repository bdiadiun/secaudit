"""Only runs with --url: docker run --rm --network host
ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <url> -J <out>. Baseline
mode only — passive, nothing fuzzes or brute-forces.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing

SOURCE = "zap"


def tool_version() -> str | None:
    exe = shutil.which("docker")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> dict:
    if ctx.url is None:
        raise ToolMissing("zap requires --url")
    exe = shutil.which("docker")
    if exe is None:
        raise ToolMissing("docker not installed")
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "zap.json"
        subprocess.run(
            [
                exe, "run", "--rm", "--network", "host",
                "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py",
                "-t", ctx.url, "-J", str(out_path),
            ],
            capture_output=True, text=True, check=False,
        )
        if not out_path.exists():
            return {"site": []}
        return json.loads(out_path.read_text() or "{}")


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            riskcode = int(alert.get("riskcode", 0))
            cwe = f"CWE-{alert['cweid']}" if alert.get("cweid") else None
            references = [r for r in (alert.get("reference") or "").split("\n") if r]
            instances = alert.get("instances") or [{}]
            for instance in instances:
                location = {
                    "url": instance.get("uri", site.get("@name", "")),
                    "method": instance.get("method"),
                }
                evidence = instance.get("evidence") or None
                findings.append(Finding(
                    id=fingerprint(SOURCE, alert["pluginid"], location, evidence),
                    source=SOURCE,
                    rule=alert["pluginid"],
                    severity=severity(SOURCE, {"riskcode": riskcode}),
                    confidence="medium",
                    cwe=cwe,
                    title=alert.get("name", alert["pluginid"]),
                    location=location,
                    evidence=evidence,
                    remediation=alert.get("solution"),
                    references=references,
                    status="new",
                    accepted=None,
                ))
    return findings
