"""The only collector that talks to the target itself. Discovers
/openapi.json, picks POST paths matching the auth pattern, sends up to 30
requests with an invalid body, stops at the first 429. Never sends valid
credentials, never exceeds 30 requests per path.
"""
from __future__ import annotations

import re
import time

import httpx

from ..normalize import fingerprint, severity
from ..schema import Finding
from .base import Context, ToolMissing

SOURCE = "ratelimit"

AUTH_PATTERN = re.compile(r"login|token|auth|session|password", re.IGNORECASE)
MAX_REQUESTS_PER_PATH = 30
PACE_SECONDS = 5 / MAX_REQUESTS_PER_PATH


def tool_version() -> str | None:
    # A benign probe against the target, not an external binary.
    return None


def run(ctx: Context) -> dict:
    if ctx.url is None:
        raise ToolMissing("ratelimit requires --url")
    with httpx.Client(base_url=ctx.url, timeout=5.0) as client:
        try:
            response = client.get("/openapi.json")
            response.raise_for_status()
            spec = response.json()
        except httpx.HTTPError as exc:
            raise ToolMissing(f"no openapi.json at {ctx.url}: {exc}") from exc

        paths = [
            path
            for path, methods in (spec.get("paths") or {}).items()
            if "post" in methods and AUTH_PATTERN.search(path)
        ]

        results = []
        for path in paths:
            saw_429 = False
            for _ in range(MAX_REQUESTS_PER_PATH):
                probe = client.post(path, json={"secaudit": "probe"})
                if probe.status_code == 429:
                    saw_429 = True
                    break
                time.sleep(PACE_SECONDS)
            results.append({"path": path, "saw_429": saw_429})

    return {"url": ctx.url, "results": results}


def parse(raw: dict, ctx: Context) -> list[Finding]:
    findings = []
    url = raw.get("url") or ctx.url or ""
    for entry in raw.get("results", []):
        if entry["saw_429"]:
            continue
        location = {"url": f"{url}{entry['path']}", "method": "POST"}
        findings.append(Finding(
            id=fingerprint(SOURCE, "no-429-after-burst", location, None),
            source=SOURCE,
            rule="no-429-after-burst",
            severity=severity(SOURCE, {}),
            confidence="medium",
            cwe=None,
            title=f"No 429 after a burst of POST requests to {entry['path']}",
            location=location,
            evidence=None,
            remediation="add rate limiting to this endpoint, per identity and per IP",
            references=[],
            status="new",
            accepted=None,
        ))
    return findings
