"""Invariant 12: every collector's parse() on its fixture yields >= 1 finding
with all required fields and a location of the shape the table prescribes.

Invariant 3: gitleaks evidence never contains the raw secret from the
fixture (neither in `evidence` nor in the finding's serialized form).
"""
from pathlib import Path

import pytest

from secaudit.collectors import bandit, gitleaks, osv, pip_audit, semgrep, zap
from secaudit.collectors.base import Context
from secaudit.schema import Finding

from conftest import load_fixture

REPO = Path("/repo")
RAW_SECRET = "sk-test-FAKE0000000000000000"


def _ctx(**kw):
    return Context(repo=REPO, url=kw.get("url"))


def test_bandit_parse_yields_findings_with_file_location():
    raw = load_fixture("bandit.json")
    findings = bandit.parse(raw, _ctx())
    assert len(findings) >= 1
    for f in findings:
        assert isinstance(f, Finding)
        assert f.source == "bandit"
        assert f.rule
        assert f.severity in {"critical", "high", "medium", "low", "info"}
        assert set(f.location.keys()) == {"file", "line"}
        assert f.location["file"] == "app/utils.py" or f.location["file"] == "app/crypto.py"


def test_semgrep_parse_yields_findings_with_file_location():
    raw = load_fixture("semgrep.json")
    findings = semgrep.parse(raw, _ctx())
    assert len(findings) >= 1
    for f in findings:
        assert f.source == "semgrep"
        assert set(f.location.keys()) == {"file", "line"}
    critical = [f for f in findings if f.location["file"] == "app/views.py"]
    assert critical and critical[0].severity == "critical"


def test_pip_audit_parse_yields_findings_with_package_location():
    raw = load_fixture("pip_audit.json")
    findings = pip_audit.parse(raw, _ctx())
    assert len(findings) >= 1
    for f in findings:
        assert f.source == "pip-audit"
        assert set(f.location.keys()) == {"package", "version", "ecosystem"}
        assert f.location["ecosystem"] == "PyPI"


def test_osv_parse_yields_findings_with_package_location():
    raw = load_fixture("osv.json")
    findings = osv.parse(raw, _ctx())
    assert len(findings) >= 1
    for f in findings:
        assert f.source == "osv"
        assert set(f.location.keys()) == {"package", "version", "ecosystem"}


def test_zap_parse_yields_findings_with_url_location():
    raw = load_fixture("zap.json")
    findings = zap.parse(raw, _ctx(url="http://127.0.0.1:8000"))
    assert len(findings) >= 1
    for f in findings:
        assert f.source == "zap"
        assert set(f.location.keys()) == {"url", "method"}
    high = [f for f in findings if f.location["method"] == "POST"]
    assert high and high[0].severity == "high"


def test_gitleaks_parse_yields_findings_with_file_location():
    raw = load_fixture("gitleaks.json")
    findings = gitleaks.parse(raw, _ctx())
    assert len(findings) >= 1
    for f in findings:
        assert f.source == "gitleaks"
        assert set(f.location.keys()) == {"file", "line"}


def test_gitleaks_evidence_redacts_raw_secret():
    raw = load_fixture("gitleaks.json")
    findings = gitleaks.parse(raw, _ctx())
    assert findings[0].evidence is not None
    assert RAW_SECRET not in findings[0].evidence
    assert "<REDACTED:" in findings[0].evidence


def test_gitleaks_serialized_finding_never_contains_raw_secret():
    raw = load_fixture("gitleaks.json")
    findings = gitleaks.parse(raw, _ctx())
    serialized = findings[0].model_dump_json()
    assert RAW_SECRET not in serialized
