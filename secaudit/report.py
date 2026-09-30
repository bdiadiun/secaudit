"""Markdown from a Report: deterministic ordering so the same findings.json
always renders byte-identical output.
"""
from __future__ import annotations

from .schema import Finding, Report

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_STATUS_RANK = {"new": 0, "known": 1}


def _location_str(location: dict) -> str:
    if "file" in location:
        line = location.get("line")
        return f"{location['file']}:{line}" if line is not None else str(location["file"])
    if "url" in location:
        method = location.get("method") or ""
        return f"{method} {location['url']}".strip()
    if "package" in location:
        parts = [str(location.get("ecosystem", "")), str(location["package"]), str(location.get("version", ""))]
        return " ".join(p for p in parts if p)
    return str(location)


def _render_finding(finding: Finding) -> list[str]:
    lines = [
        f"### {finding.id} — {finding.source}/{finding.rule}",
        "",
        f"- location: {_location_str(finding.location)}",
        f"- {finding.title}",
    ]
    if finding.evidence:
        lines += ["", "```", finding.evidence, "```"]
    if finding.remediation:
        lines.append(f"- remediation: {finding.remediation}")
    if finding.references:
        lines.append(f"- references: {', '.join(finding.references)}")
    if finding.accepted is not None:
        lines.append(
            f"- accepted by {finding.accepted.by} on {finding.accepted.date}: "
            f"{finding.accepted.reason}"
        )
    lines.append("")
    return lines


def render(report: Report) -> str:
    lines = [
        "# Security audit report",
        "",
        f"- repo: {report.target.repo}",
        f"- commit: {report.target.commit or 'unknown'}",
        f"- url: {report.target.url or 'n/a'}",
        f"- started: {report.run.started_at}",
        f"- finished: {report.run.finished_at}",
        "",
        "## Summary",
        "",
        "| severity | count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev} | {getattr(report.summary, sev)} |")
    lines += [
        "",
        f"new: {report.summary.new}, known: {report.summary.known}, "
        f"resolved: {report.summary.resolved}, accepted: {report.summary.accepted}",
        "",
    ]

    if report.run.skipped:
        lines.append("## Skipped tools")
        lines.append("")
        for skip in report.run.skipped:
            lines.append(f"- {skip.source}: {skip.reason}")
        lines.append("")

    active = [f for f in report.findings if f.status in ("new", "known")]
    for sev in _SEVERITY_ORDER:
        group = sorted(
            (f for f in active if f.severity == sev),
            key=lambda f: (_STATUS_RANK[f.status], f.id),
        )
        if not group:
            continue
        lines.append(f"## {sev.capitalize()}")
        lines.append("")
        for finding in group:
            lines.extend(_render_finding(finding))

    accepted = sorted((f for f in report.findings if f.status == "accepted"), key=lambda f: f.id)
    if accepted:
        lines.append("## Accepted")
        lines.append("")
        for finding in accepted:
            lines.extend(_render_finding(finding))

    resolved = sorted((f for f in report.findings if f.status == "resolved"), key=lambda f: f.id)
    if resolved:
        lines.append("## Resolved")
        lines.append("")
        for finding in resolved:
            lines.extend(_render_finding(finding))

    return "\n".join(lines) + "\n"
