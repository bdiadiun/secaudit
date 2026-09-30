"""Invariant 2: the severity table in docs/spec.md holds for every row;
CVSS boundaries are inclusive at 9.0 / 7.0 / 4.0; missing CVSS -> medium.

Interface: secaudit.normalize.severity(source, raw) -> str. See
tests/README.md for the expected `raw` shape per source.
"""
import pytest

from secaudit.normalize import severity


@pytest.mark.parametrize(
    "source, raw, expected",
    [
        # bandit: HIGH/MEDIUM/LOW -> high/medium/low
        ("bandit", {"issue_severity": "HIGH"}, "high"),
        ("bandit", {"issue_severity": "MEDIUM"}, "medium"),
        ("bandit", {"issue_severity": "LOW"}, "low"),
        # semgrep: ERROR/WARNING/INFO -> high/medium/low
        ("semgrep", {"severity": "ERROR", "metadata_severity": None}, "high"),
        ("semgrep", {"severity": "WARNING", "metadata_severity": None}, "medium"),
        ("semgrep", {"severity": "INFO", "metadata_severity": None}, "low"),
        # semgrep: metadata.severity CRITICAL overrides to critical
        ("semgrep", {"severity": "WARNING", "metadata_severity": "CRITICAL"}, "critical"),
        ("semgrep", {"severity": "ERROR", "metadata_severity": "CRITICAL"}, "critical"),
        # pip-audit / osv: CVSS thresholds, inclusive boundaries
        ("pip-audit", {"cvss": 9.0}, "critical"),
        ("pip-audit", {"cvss": 9.5}, "critical"),
        ("pip-audit", {"cvss": 8.9}, "high"),
        ("pip-audit", {"cvss": 7.0}, "high"),
        ("pip-audit", {"cvss": 6.9}, "medium"),
        ("pip-audit", {"cvss": 4.0}, "medium"),
        ("pip-audit", {"cvss": 3.9}, "low"),
        ("pip-audit", {"cvss": 0.0}, "low"),
        ("pip-audit", {"cvss": None}, "medium"),  # no score -> medium
        ("osv", {"cvss": 9.0}, "critical"),
        ("osv", {"cvss": 7.0}, "high"),
        ("osv", {"cvss": 4.0}, "medium"),
        ("osv", {"cvss": 3.9}, "low"),
        ("osv", {"cvss": None}, "medium"),
        # gitleaks: working tree / only in history -> critical / high
        ("gitleaks", {"in_tree": True}, "critical"),
        ("gitleaks", {"in_tree": False}, "high"),
        # zap: riskcode 3/2/1/0 -> high/medium/low/info
        ("zap", {"riskcode": 3}, "high"),
        ("zap", {"riskcode": 2}, "medium"),
        ("zap", {"riskcode": 1}, "low"),
        ("zap", {"riskcode": 0}, "info"),
        # ratelimit: constant medium
        ("ratelimit", {}, "medium"),
    ],
)
def test_severity_matches_spec_table(source, raw, expected):
    assert severity(source, raw) == expected
