"""Invariant 10: report output is byte-identical across two invocations on
the same input; groups ordered critical -> info; within a group `new`
before `known`; `Skipped tools` section present only when `run.skipped` is
non-empty.

Interface: secaudit.report.render(report: schema.Report) -> str.
"""
from secaudit.report import render
from secaudit.schema import Report


def _finding(id_, severity, status, rule="B602", file="app/utils.py"):
    return {
        "id": id_,
        "source": "bandit",
        "rule": rule,
        "severity": severity,
        "confidence": "high",
        "cwe": None,
        "title": f"finding {id_}",
        "location": {"file": file, "line": 1},
        "evidence": None,
        "remediation": None,
        "references": [],
        "status": status,
        "accepted": None,
    }


def _report(findings, skipped=None):
    return Report.model_validate({
        "schema_version": "1.0",
        "target": {"repo": "/repo", "commit": "abc123", "url": None},
        "run": {
            "started_at": "2024-06-01T12:00:00Z",
            "finished_at": "2024-06-01T12:05:00Z",
            "tools": {"bandit": "1.7.9"},
            "skipped": skipped or [],
        },
        "findings": findings,
        "summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "new": 0, "known": 0, "resolved": 0, "accepted": 0,
        },
        "baseline": {"path": None, "commit": None},
    })


def test_render_is_byte_identical_across_two_invocations():
    report = _report([
        _finding("fp-1111111111111111", "high", "new"),
        _finding("fp-2222222222222222", "low", "known"),
    ])
    assert render(report) == render(report)


def test_render_groups_ordered_critical_to_info():
    report = _report([
        _finding("fp-1111111111111111", "low", "new", file="a.py"),
        _finding("fp-2222222222222222", "critical", "new", file="b.py"),
        _finding("fp-3333333333333333", "medium", "new", file="c.py"),
    ])
    text = render(report)
    assert text.index("fp-2222222222222222") < text.index("fp-3333333333333333")
    assert text.index("fp-3333333333333333") < text.index("fp-1111111111111111")


def test_render_orders_new_before_known_within_same_severity_group():
    report = _report([
        _finding("fp-1111111111111111", "high", "known", file="a.py"),
        _finding("fp-2222222222222222", "high", "new", file="b.py"),
    ])
    text = render(report)
    assert text.index("fp-2222222222222222") < text.index("fp-1111111111111111")


def test_render_omits_skipped_tools_section_when_no_skips():
    report = _report([], skipped=[])
    assert "Skipped tools" not in render(report)


def test_render_includes_skipped_tools_section_when_skips_present():
    report = _report([], skipped=[{"source": "semgrep", "reason": "semgrep not installed"}])
    text = render(report)
    assert "Skipped tools" in text
    assert "semgrep" in text
    assert "semgrep not installed" in text
