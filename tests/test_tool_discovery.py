"""Invariant 15: all five repository collectors skipped -> exit 2 and
findings.json still written; one of them ran -> exit computed from
findings as usual.

Invariant 16: a collector finds its binary on PATH **and** next to
sys.executable (the venv secaudit runs from), so `pip install secaudit
bandit` into one venv works without activating it.

Invariant 17: bandit's run() tolerates a nonzero exit code from the bandit
binary as long as stdout is JSON (bandit exits 1 when it has findings, not
when it fails) and does not raise ToolMissing / a bare exception for it.

Invariant 18: pip-audit's run(), when the target repo has a `.venv`, freezes
that venv's own interpreter (not `sys.executable`, which is secaudit's own
venv) and audits the frozen list with `-r ... --disable-pip`, never
`--local` (which would audit secaudit's own venv instead of the target's).
"""
from __future__ import annotations

import json
import subprocess

from typer.testing import CliRunner

from secaudit.cli import app
from secaudit.collectors import bandit, pip_audit
from secaudit.collectors.base import Context

from test_cli import COLLECTORS, _patch_all_skip, _patch_one_finding

runner = CliRunner()


def test_all_repo_collectors_skipped_exits_2_and_writes_findings_json(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 2
    assert (out / "findings.json").exists()


def test_one_repo_collector_running_exits_by_findings_not_by_skip_count(tmp_path, monkeypatch):
    calls = []
    _patch_one_finding(monkeypatch, calls, bandit.SOURCE, "low")
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(out)])
    assert result.exit_code == 0


def test_bandit_tool_version_found_next_to_sys_executable_when_absent_from_path(monkeypatch):
    # The dev venv already has bandit installed next to sys.executable
    # (.venv/bin/bandit); strip PATH so a plain shutil.which("bandit") lookup
    # fails and only the sys.executable-adjacent lookup can succeed.
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert bandit.tool_version() is not None


def test_bandit_run_parses_findings_when_binary_exits_nonzero_with_json_stdout(tmp_path, monkeypatch):
    monkeypatch.setattr(bandit.shutil, "which", lambda name: "/usr/bin/bandit")

    bandit_json = json.dumps({
        "results": [
            {
                "test_id": "B602",
                "filename": str(tmp_path / "app" / "x.py"),
                "line_number": 3,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "shell=True",
                "issue_cwe": {"id": 78},
                "more_info": "https://example.com/b602",
            }
        ]
    })

    def fake_run(cmd, capture_output=True, text=True, check=False):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout=bandit_json, stderr="noisy warning\n")

    monkeypatch.setattr(bandit.subprocess, "run", fake_run)

    raw = bandit.run(Context(repo=tmp_path))
    findings = bandit.parse(raw, Context(repo=tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "B602"


def test_pip_audit_run_freezes_target_venv_python_and_disables_pip(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    venv_bin = repo / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    target_python = venv_bin / "python"
    target_python.write_text("#!/bin/sh\n")
    target_python.chmod(0o755)

    monkeypatch.setattr(pip_audit.shutil, "which", lambda name: "/usr/bin/pip-audit")

    calls = []

    def fake_run(cmd, capture_output=True, text=True, check=False, cwd=None):
        calls.append(list(cmd))
        if str(target_python) in cmd:
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="requests==1.0.0\n", stderr="")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=json.dumps({"dependencies": []}), stderr="")

    monkeypatch.setattr(pip_audit.subprocess, "run", fake_run)

    pip_audit.run(Context(repo=repo))

    freeze_calls = [c for c in calls if str(target_python) in c]
    assert freeze_calls, f"expected a freeze call using {target_python}, got {calls}"

    audit_calls = [c for c in calls if c and c[0] == "/usr/bin/pip-audit"]
    assert audit_calls, f"expected a pip-audit invocation, got {calls}"
    audit_cmd = audit_calls[0]
    assert "-r" in audit_cmd
    assert "--disable-pip" in audit_cmd
    assert "--local" not in audit_cmd
