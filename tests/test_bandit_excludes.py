"""Invariant 19: bandit's run() passes the test-path excludes to -x
(.venv, node_modules, .git, tests, test, e2e, **/test_*.py, **/*_test.py,
**/conftest.py); parse() drops any finding under those paths too, in case
the installed bandit ignores a glob.
"""
from __future__ import annotations

import copy
import subprocess
from pathlib import Path

from secaudit.collectors import bandit
from secaudit.collectors.base import Context

from conftest import load_fixture

REPO = Path("/repo")

REQUIRED_EXCLUDES = {
    ".venv", "node_modules", ".git",
    "tests", "test", "e2e",
    "**/test_*.py", "**/*_test.py", "**/conftest.py",
}


def _ctx():
    return Context(repo=REPO, url=None)


def _strip_repo_prefix(part: str) -> str:
    prefix = str(REPO) + "/"
    return part[len(prefix):] if part.startswith(prefix) else part


def test_bandit_run_passes_test_path_excludes_to_dash_x(monkeypatch):
    monkeypatch.setattr(bandit, "find_tool", lambda name: "/usr/bin/bandit")

    captured = {}

    def fake_run(cmd, capture_output=True, text=True, check=False):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr(bandit.subprocess, "run", fake_run)

    bandit.run(_ctx())

    cmd = captured["cmd"]
    exclude_value = cmd[cmd.index("-x") + 1]
    tails = {_strip_repo_prefix(part) for part in exclude_value.split(",")}
    missing = REQUIRED_EXCLUDES - tails
    assert not missing, f"missing -x excludes: {missing} (got {exclude_value!r})"


def test_bandit_parse_drops_findings_under_test_paths():
    raw = load_fixture("bandit.json")
    raw = copy.deepcopy(raw)
    test_dir_item = copy.deepcopy(raw["results"][0])
    test_dir_item["filename"] = "tests/test_x.py"
    test_dir_item["test_id"] = "B999-TESTDIR"
    conftest_item = copy.deepcopy(raw["results"][0])
    conftest_item["filename"] = "conftest.py"
    conftest_item["test_id"] = "B999-CONFTEST"
    raw["results"].extend([test_dir_item, conftest_item])

    findings = bandit.parse(raw, _ctx())

    rules = {f.rule for f in findings}
    assert "B999-TESTDIR" not in rules
    assert "B999-CONFTEST" not in rules
    files = {f.location["file"] for f in findings}
    assert "tests/test_x.py" not in files
    assert "conftest.py" not in files
