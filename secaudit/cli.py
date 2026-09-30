"""typer entrypoint: scan, report, baseline, checklist.

Collectors are looked up as module attributes at call time
(`module.run(ctx)`, not a name bound at import time) so tests can monkeypatch
`secaudit.collectors.<name>.run` / `.parse` directly and have the CLI observe
the replacement.
"""
from __future__ import annotations

import importlib.resources
import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import typer
import yaml

from . import baseline as baseline_module
from .collectors import bandit, gitleaks, osv, pip_audit, ratelimit, semgrep, zap
from .collectors.base import Context, ToolMissing
from .report import render
from .schema import Finding, Report

app = typer.Typer(add_completion=False)

_COLLECTORS = [bandit, semgrep, pip_audit, osv, gitleaks, zap, ratelimit]
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _git_commit(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    commit = result.stdout.strip()
    return commit or None


def _load_baseline_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text())
    return [Finding.model_validate(f) for f in data.get("findings", [])]


@app.command()
def scan(
    repo: Path = typer.Option(..., exists=True, file_okay=False),
    out: Path = typer.Option(...),
    url: str | None = typer.Option(
        None, help="Loopback target for zap/ratelimit; refused if not 127.0.0.0/8, ::1 or localhost."
    ),
    baseline: Path | None = typer.Option(None, help="Previous findings.json to diff against."),
    accepted: Path | None = typer.Option(None, help="accepted.yml of accepted-risk fingerprints."),
    fail_on: str = typer.Option(
        "high", "--fail-on",
        help="Minimum severity of a new/known finding that fails the scan.",
    ),
) -> None:
    if fail_on not in _SEVERITY_RANK:
        typer.echo(f"unknown --fail-on severity: {fail_on!r}", err=True)
        raise typer.Exit(code=2)

    if url is not None:
        host = urlsplit(url).hostname or ""
        if not _is_loopback_host(host):
            typer.echo(f"--url host {host!r} is not loopback; refusing", err=True)
            raise typer.Exit(code=2)

    started_at = datetime.now(timezone.utc).isoformat()
    ctx = Context(repo=repo, url=url)

    findings: list[Finding] = []
    tools: dict[str, str | None] = {}
    skipped: list[dict] = []

    for module in _COLLECTORS:
        source = module.SOURCE
        try:
            tools[source] = module.tool_version()
        except Exception:  # noqa: BLE001 - a version probe must not abort the scan
            tools[source] = None
        try:
            raw = module.run(ctx)
        except ToolMissing as exc:
            skipped.append({"source": source, "reason": str(exc)})
            continue
        except Exception as exc:  # noqa: BLE001 - a broken collector must not hide the rest
            skipped.append({"source": source, "reason": f"error: {exc}"})
            continue
        findings.extend(module.parse(raw, ctx))

    baseline_findings = _load_baseline_findings(baseline) if baseline else None

    accepted_entries: list[dict] | None = None
    if accepted is not None:
        raw_accepted = yaml.safe_load(accepted.read_text()) or []
        try:
            accepted_entries, warnings = baseline_module.load_accepted(raw_accepted)
        except baseline_module.InvalidAccepted as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
        for warning in warnings:
            typer.echo(f"warning: {warning}", err=True)

    applied = baseline_module.apply(findings, baseline_findings, accepted_entries)
    summary = baseline_module.summarize(applied)
    finished_at = datetime.now(timezone.utc).isoformat()

    report = Report.model_validate({
        "schema_version": "1.0",
        "target": {"repo": str(repo), "commit": _git_commit(repo), "url": url},
        "run": {
            "started_at": started_at,
            "finished_at": finished_at,
            "tools": tools,
            "skipped": skipped,
        },
        "findings": [f.model_dump(mode="json") for f in applied],
        "summary": summary,
        "baseline": {"path": str(baseline) if baseline else None, "commit": None},
    })

    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(report.model_dump_json(indent=2))

    threshold = _SEVERITY_RANK[fail_on]
    trips = any(
        getattr(report.summary, sev) > 0
        for sev, rank in _SEVERITY_RANK.items()
        if rank >= threshold
    )
    raise typer.Exit(code=1 if trips else 0)


@app.command(name="report")
def report_command(findings_path: Path = typer.Argument(..., exists=True)) -> None:
    data = json.loads(findings_path.read_text())
    report = Report.model_validate(data)
    typer.echo(render(report), nl=False)


@app.command(name="baseline")
def baseline_command(
    findings_path: Path = typer.Argument(..., exists=True),
    out: Path = typer.Option(...),
) -> None:
    out.write_text(findings_path.read_text())


@app.command()
def checklist() -> None:
    text = importlib.resources.files("secaudit").joinpath("checklist/generic.md").read_text()
    typer.echo(text, nl=False)


if __name__ == "__main__":
    app()
