"""Only runs with --url: docker run --rm --network host -v <tmp>:/zap/wrk:rw
ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <url> -J zap.json. Baseline
mode only — passive, nothing fuzzes or brute-forces.

The bind-mount's host side must live under `ctx.out` (the scan's `--out`,
inside the repo tree), not system temp: on colima/Docker Desktop only paths
under the host's shared prefix are visible inside the container, so a
`tempfile.mkdtemp()` in `/tmp` or `/var/folders` mounts empty and zap can
never write `-J`'s report (finding 69).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing, find_tool

SOURCE = "zap"

# zap-baseline.py's own wait budget (minutes) and the hard ceiling on the
# docker call (seconds), with a little slack over the former so zap gets to
# report its own timeout instead of being killed mid-write.
_WAIT_MINUTES = "5"
_SUBPROCESS_TIMEOUT = 330


def tool_version() -> str | None:
    exe = find_tool("docker")
    if exe is None:
        return None
    try:
        out = subprocess.run(
            [exe, "run", "--rm", "ghcr.io/zaproxy/zaproxy:stable", "zap.sh", "-version"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    version = out.stdout.strip()
    return version or None


def run(ctx: Context) -> dict:
    if ctx.url is None:
        raise ToolMissing("zap requires --url")
    exe = find_tool("docker")
    if exe is None:
        raise ToolMissing("docker not installed")
    if ctx.out is None:
        raise ToolMissing("zap requires --out (bind-mount target for the report)")
    # dir=ctx.out, not the default system temp root: see module docstring.
    with tempfile.TemporaryDirectory(prefix="zap-", dir=ctx.out) as tmp:
        # zap-baseline.py writes -J's report as the container's `zap` user;
        # without world-writable perms on the mount it can't create the file.
        os.chmod(tmp, 0o777)
        try:
            result = subprocess.run(
                [
                    exe, "run", "--rm", "--network", "host",
                    "-v", f"{tmp}:/zap/wrk:rw",
                    "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py",
                    "-t", ctx.url, "-J", "zap.json",
                    "-I",  # exit 0 on WARN too; secaudit reads the report, not the exit code
                    "-T", _WAIT_MINUTES,
                ],
                capture_output=True, text=True, check=False, timeout=_SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolMissing(f"zap timed out after {_SUBPROCESS_TIMEOUT}s") from exc
        out_path = Path(tmp) / "zap.json"
        if not out_path.exists():
            tail = ((result.stderr or "") + (result.stdout or ""))[-200:]
            raise ToolMissing(f"zap produced no report: {tail}")
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
