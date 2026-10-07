"""A collector whose tool crashes or prints nothing must be skipped, never
reported as a clean "0 findings" (osv-scanner SIGSEGV, 08.10)."""
import subprocess
from pathlib import Path

import pytest

from secaudit.collectors import bandit, gitleaks, osv, pip_audit, semgrep
from secaudit.collectors.base import Context, ToolCrashed


def _fake(monkeypatch, mod, code, stdout=""):
    monkeypatch.setattr(mod, "find_tool", lambda name: "/bin/" + name)
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, code, stdout, ""),
    )


def _ctx(tmp_path):
    (tmp_path / "requirements.txt").write_text("x\n")
    return Context(repo=tmp_path, stack={"python": []})


CASES = [
    (osv, "{}"), (semgrep, "{}"), (pip_audit, "{}"), (bandit, '{"results": []}'),
]


@pytest.mark.parametrize("mod,ok", CASES)
@pytest.mark.parametrize("code", [2, -11])
def test_crash_exit_is_skipped(monkeypatch, tmp_path, mod, ok, code):
    _fake(monkeypatch, mod, code)
    monkeypatch.setattr(semgrep, "_config_packs", lambda *a: ["p/python"])
    with pytest.raises(ToolCrashed, match=rf"crashed: exit {code}"):
        mod.run(_ctx(tmp_path))


@pytest.mark.parametrize("mod,ok", CASES)
def test_empty_or_garbled_stdout_is_invalid_output(monkeypatch, tmp_path, mod, ok):
    monkeypatch.setattr(semgrep, "_config_packs", lambda *a: ["p/python"])
    for out in ("", "not json"):
        _fake(monkeypatch, mod, 0, out)
        with pytest.raises(ToolCrashed, match="invalid output"):
            mod.run(_ctx(tmp_path))


@pytest.mark.parametrize("mod,ok", CASES)
@pytest.mark.parametrize("code", [0, 1])
def test_normal_exit_with_json_passes(monkeypatch, tmp_path, mod, ok, code):
    monkeypatch.setattr(semgrep, "_config_packs", lambda *a: ["p/python"])
    _fake(monkeypatch, mod, code, ok)
    assert mod.run(_ctx(tmp_path)) is not None


def test_osv_no_lockfiles_is_clean(monkeypatch, tmp_path):
    _fake(monkeypatch, osv, 128)
    assert osv.run(_ctx(tmp_path)) == {}


def test_gitleaks_crash_and_missing_report(monkeypatch, tmp_path):
    _fake(monkeypatch, gitleaks, 2)
    with pytest.raises(ToolCrashed, match="crashed: exit 2"):
        gitleaks.run(_ctx(tmp_path))
    _fake(monkeypatch, gitleaks, 1)  # leaks claimed, no report written
    with pytest.raises(ToolCrashed, match="invalid output"):
        gitleaks.run(_ctx(tmp_path))
    _fake(monkeypatch, gitleaks, 0)  # clean run, no report: fine
    assert gitleaks.run(_ctx(tmp_path)) == []


def test_cli_files_crash_under_skipped(monkeypatch, tmp_path):
    from secaudit import cli

    def boom(ctx):
        raise ToolCrashed("crashed: exit 2")

    monkeypatch.setattr(osv, "run", boom)
    monkeypatch.setattr(osv, "tool_version", lambda: "1")
    from secaudit.collectors.base import ToolMissing
    for m in (bandit, gitleaks, pip_audit, semgrep):
        monkeypatch.setattr(m, "run", lambda ctx: (_ for _ in ()).throw(ToolMissing("x")))
    from typer.testing import CliRunner
    import json
    out = tmp_path / "out"
    CliRunner().invoke(cli.app, ["scan", "--repo", str(tmp_path), "--out", str(out), "--stack", "python"])
    data = json.loads((out / "findings.json").read_text())
    assert {"source": "osv", "reason": "crashed: exit 2"} in data["run"]["skipped"]
