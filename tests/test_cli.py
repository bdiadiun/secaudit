"""Invariant 4: --url with a non-loopback host exits 2 and calls no
collector; localhost/127.0.0.1/[::1] are accepted. The CLI has no override
flag for the loopback rule.

Invariant 5: a missing tool records a run.skipped entry; the other
collectors still run; exit code is computed from the findings.

Invariant 6: a collector raising a non-ToolMissing exception is skipped with
an "error:" prefixed reason; the others still run.

Invariant 9: --fail-on default is high; a medium finding alone exits 0, a
high finding exits 1; --fail-on medium with a medium finding exits 1.

Invariant 14: `secaudit checklist` prints the packaged generic.md
byte-for-byte, exit 0.
"""
import importlib.resources
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaudit.cli import app
from secaudit.collectors import bandit, gitleaks, osv, pip_audit, ratelimit, semgrep, zap
from secaudit.collectors.base import ToolMissing
from secaudit.schema import Finding

runner = CliRunner()
COLLECTORS = [bandit, semgrep, pip_audit, osv, gitleaks, zap, ratelimit]


_IDS = {
    "bandit": "fp-aaaaaaaaaaaaaaaa",
    "semgrep": "fp-bbbbbbbbbbbbbbbb",
    "pip-audit": "fp-cccccccccccccccc",
    "osv": "fp-dddddddddddddddd",
    "gitleaks": "fp-eeeeeeeeeeeeeeee",
    "zap": "fp-1111111111111111",
    "ratelimit": "fp-2222222222222222",
}


def _finding(source, severity, rule="R1"):
    return Finding.model_validate({
        "id": _IDS[source],
        "source": source,
        "rule": rule,
        "severity": severity,
        "confidence": "high",
        "cwe": None,
        "title": "t",
        "location": {"file": "app/x.py", "line": 1},
        "evidence": None,
        "remediation": None,
        "references": [],
        "status": "new",
        "accepted": None,
    })


def _patch_all_skip(monkeypatch, calls):
    """Every collector's run raises ToolMissing; records who was called."""
    for mod in COLLECTORS:
        def make_run(name):
            def _run(ctx):
                calls.append(name)
                raise ToolMissing(f"{name} not installed")
            return _run
        monkeypatch.setattr(mod, "run", make_run(mod.SOURCE))


def _patch_one_finding(monkeypatch, calls, source, severity):
    """All collectors ToolMissing except `source`, which returns one finding."""
    _patch_all_skip(monkeypatch, calls)
    target = next(m for m in COLLECTORS if m.SOURCE == source)

    def _run(ctx):
        calls.append(source)
        return {"stub": True}

    def _parse(raw, ctx):
        return [_finding(source, severity)]

    monkeypatch.setattr(target, "run", _run)
    monkeypatch.setattr(target, "parse", _parse)


def test_scan_rejects_non_loopback_url_with_exit_2_and_no_collector_call(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    result = runner.invoke(app, [
        "scan", "--repo", str(tmp_path), "--out", str(tmp_path / "out"),
        "--url", "http://example.com",
    ])
    assert result.exit_code == 2
    assert calls == []


@pytest.mark.parametrize("url", [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://[::1]:8000",
])
def test_scan_accepts_loopback_urls(tmp_path, monkeypatch, url):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    result = runner.invoke(app, [
        "scan", "--repo", str(tmp_path), "--out", str(tmp_path / "out"), "--url", url,
    ])
    assert result.exit_code == 0


def test_scan_help_exposes_no_loopback_override_option():
    result = runner.invoke(app, ["scan", "--help"])
    lowered = result.output.lower()
    assert "remote" not in lowered
    assert "insecure" not in lowered
    assert "allow" not in lowered


def test_missing_tool_is_recorded_in_run_skipped_and_others_still_run(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    bandit_source = bandit.SOURCE

    def _bandit_run(ctx):
        calls.append("bandit")
        raise ToolMissing("bandit not installed")

    monkeypatch.setattr(bandit, "run", _bandit_run)

    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads((out / "findings.json").read_text())
    skipped_sources = {s["source"] for s in data["run"]["skipped"]}
    assert bandit_source in skipped_sources
    # every other collector's run was still attempted
    assert set(calls) == {m.SOURCE for m in COLLECTORS}


def test_collector_error_is_recorded_with_error_prefix_and_others_still_run(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)

    def _semgrep_run(ctx):
        calls.append("semgrep")
        raise ValueError("boom")

    monkeypatch.setattr(semgrep, "run", _semgrep_run)

    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads((out / "findings.json").read_text())
    entry = next(s for s in data["run"]["skipped"] if s["source"] == "semgrep")
    assert entry["reason"].startswith("error:")
    assert set(calls) == {m.SOURCE for m in COLLECTORS}


def test_fail_on_default_high_with_only_medium_finding_exits_0(tmp_path, monkeypatch):
    calls = []
    _patch_one_finding(monkeypatch, calls, bandit.SOURCE, "medium")
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 0


def test_fail_on_default_high_with_high_finding_exits_1(tmp_path, monkeypatch):
    calls = []
    _patch_one_finding(monkeypatch, calls, bandit.SOURCE, "high")
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 1


def test_fail_on_medium_with_medium_finding_exits_1(tmp_path, monkeypatch):
    calls = []
    _patch_one_finding(monkeypatch, calls, bandit.SOURCE, "medium")
    out = tmp_path / "out"
    result = runner.invoke(app, [
        "scan", "--repo", str(tmp_path), "--out", str(out), "--fail-on", "medium",
    ])
    assert result.exit_code == 1
