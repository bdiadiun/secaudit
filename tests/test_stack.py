"""Invariant 20: `scan` requires an explicit `--stack` instead of semgrep's
network-guessing `--config auto`. No stack (or a syntactically empty one)
refuses to scan before any collector runs; a known stack maps to a fixed set
of semgrep registry packs; a stack none of whose languages map to a pack is
a skip (`ToolMissing`), not a crash or a silent `auto` fallback.
"""
from __future__ import annotations

import json
import subprocess

from typer.testing import CliRunner

from secaudit.cli import app
from secaudit.collectors import semgrep
from secaudit.collectors.base import Context, ToolMissing

from test_cli import _patch_all_skip, _patch_one_survivor

runner = CliRunner()


def _fake_semgrep_run(calls):
    def fake_run(cmd, capture_output=True, text=True, check=False):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="{}", stderr="")
    return fake_run


def test_scan_without_stack_exits_2_and_calls_no_collector(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    result = runner.invoke(app, ["scan", "--repo", str(tmp_path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "stack unknown" in result.output
    assert calls == []


def test_scan_with_empty_stack_exits_2_and_calls_no_collector(tmp_path, monkeypatch):
    calls = []
    _patch_all_skip(monkeypatch, calls)
    result = runner.invoke(app, [
        "scan", "--repo", str(tmp_path), "--out", str(tmp_path / "out"), "--stack", "",
    ])
    assert result.exit_code == 2
    assert calls == []


def test_scan_stack_is_parsed_into_lang_framework_dict_and_recorded_on_target(tmp_path, monkeypatch):
    calls = []
    _patch_one_survivor(monkeypatch, calls, semgrep.SOURCE)
    out = tmp_path / "out"
    result = runner.invoke(app, [
        "scan", "--repo", str(tmp_path), "--out", str(out),
        "--stack", "python:fastapi,jinja2;node:react",
    ])
    assert result.exit_code == 0
    data = json.loads((out / "findings.json").read_text())
    assert data["target"]["stack"] == {"python": ["fastapi", "jinja2"], "node": ["react"]}


def test_semgrep_run_builds_config_from_python_fastapi_jinja2(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep, "find_tool", lambda name: "/usr/bin/semgrep")
    calls = []
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_semgrep_run(calls))

    semgrep.run(Context(repo=tmp_path, stack={"python": ["fastapi", "jinja2"]}))

    assert len(calls) == 1
    cmd = calls[0]
    assert cmd[0] == "/usr/bin/semgrep"
    config_args = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert config_args == ["p/python", "p/fastapi", "p/jinja2"]
    assert "auto" not in cmd
    assert "--json" in cmd and "--quiet" in cmd
    assert cmd[-1] == str(tmp_path)


def test_semgrep_run_builds_config_from_node_react(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep, "find_tool", lambda name: "/usr/bin/semgrep")
    calls = []
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_semgrep_run(calls))

    semgrep.run(Context(repo=tmp_path, stack={"node": ["react"]}))

    cmd = calls[0]
    config_args = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert config_args == ["p/javascript", "p/typescript", "p/nodejs", "p/react"]


def test_semgrep_run_adds_dockerfile_pack_when_repo_has_a_dockerfile(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr(semgrep, "find_tool", lambda name: "/usr/bin/semgrep")
    calls = []
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_semgrep_run(calls))

    semgrep.run(Context(repo=tmp_path, stack={"python": []}))

    cmd = calls[0]
    config_args = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert config_args == ["p/python", "p/dockerfile"]


def test_semgrep_run_raises_tool_missing_for_a_stack_with_no_known_pack(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep, "find_tool", lambda name: "/usr/bin/semgrep")

    def fake_run(cmd, capture_output=True, text=True, check=False):
        raise AssertionError("semgrep must not be invoked for an unresolved stack")

    monkeypatch.setattr(semgrep.subprocess, "run", fake_run)

    ctx = Context(repo=tmp_path, stack={"cobol": ["whatever"]})
    try:
        semgrep.run(ctx)
        raise AssertionError("expected ToolMissing")
    except ToolMissing as exc:
        assert "no semgrep ruleset" in str(exc)


def test_semgrep_run_ignores_unknown_framework_but_keeps_known_lang_pack(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep, "find_tool", lambda name: "/usr/bin/semgrep")
    calls = []
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_semgrep_run(calls))

    semgrep.run(Context(repo=tmp_path, stack={"python": ["notaframework"]}))

    cmd = calls[0]
    config_args = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert config_args == ["p/python"]
