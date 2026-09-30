"""Invariant 13: Report JSON round-trips through schema.py without loss;
schema_version is "1.0".
"""
import pytest
from pydantic import ValidationError

from secaudit.schema import Finding, Report

FINDING = {
    "id": "fp-0123456789abcdef",
    "source": "bandit",
    "rule": "B602",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-78",
    "title": "subprocess call with shell=True",
    "location": {"file": "app/utils.py", "line": 11},
    "evidence": "subprocess.call(cmd, shell=True)",
    "remediation": None,
    "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    "status": "new",
    "accepted": None,
}

REPORT = {
    "schema_version": "1.0",
    "target": {"repo": "/repo", "commit": "abc123", "url": None},
    "run": {
        "started_at": "2024-06-01T12:00:00Z",
        "finished_at": "2024-06-01T12:05:00Z",
        "tools": {"bandit": "1.7.9", "semgrep": None},
        "skipped": [{"source": "semgrep", "reason": "semgrep not installed"}],
    },
    "findings": [FINDING],
    "summary": {
        "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0,
        "new": 1, "known": 0, "resolved": 0, "accepted": 0,
    },
    "baseline": {"path": None, "commit": None},
}


def test_report_json_round_trip_is_lossless():
    report = Report.model_validate(REPORT)
    restored = Report.model_validate_json(report.model_dump_json())
    assert restored == report
    assert restored.model_dump(mode="json") == report.model_dump(mode="json")


def test_report_schema_version_is_pinned_to_1_0():
    report = Report.model_validate(REPORT)
    assert report.schema_version == "1.0"


def test_report_rejects_wrong_schema_version():
    bad = dict(REPORT, schema_version="2.0")
    with pytest.raises(ValidationError):
        Report.model_validate(bad)


def test_finding_round_trip_preserves_all_fields():
    finding = Finding.model_validate(FINDING)
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding
    assert restored.location == {"file": "app/utils.py", "line": 11}
