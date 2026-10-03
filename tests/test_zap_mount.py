"""Finding 69: zap's run() didn't mount its temp dir into the container, so
`-J <out>` could never be written — docker silently returned {"site": []}
on every scan (0 alerts, false-negative; live on certreg2: WARN-NEW: 9 once
the mount and perms were in place). The mount's host side must also live
under `ctx.out`, not system temp: on colima only paths under the host's
shared prefix are visible inside the container (live: a `/tmp`/`/var/folders`
mount came back empty even with `-v`; moving it under `--out` produced a
39 KB zap.json with 12 alerts).

Covers: argv carries the bind mount (rooted under ctx.out) and a report path
relative to it; report missing after the docker call -> `ToolMissing`, not a
silent empty result; `ctx.out` unset -> `ToolMissing` before docker even
runs; report present -> parsed exactly as before.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from secaudit.collectors import zap
from secaudit.collectors.base import Context, ToolMissing

from conftest import load_fixture


def _ctx(out: Path) -> Context:
    return Context(repo=Path("/repo"), url="http://127.0.0.1:8000", out=out)


def _mount_target(cmd: list[str]) -> str:
    return cmd[cmd.index("-v") + 1]


def test_zap_run_mounts_tmp_dir_under_out_and_requests_zap_json_report(monkeypatch, tmp_path):
    monkeypatch.setattr(zap, "find_tool", lambda name: "/usr/bin/docker")
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, check=False, timeout=None):
        captured["cmd"] = cmd
        mount = _mount_target(cmd)
        host_dir, _, container_dir = mount.partition(":")
        assert container_dir == "/zap/wrk:rw"
        assert Path(host_dir).parent == tmp_path  # mount rooted under ctx.out, not system temp
        (Path(host_dir) / "zap.json").write_text(json.dumps(load_fixture("zap.json")))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(zap.subprocess, "run", fake_run)

    raw = zap.run(_ctx(tmp_path))

    cmd = captured["cmd"]
    assert cmd[cmd.index("-J") + 1] == "zap.json"
    assert raw == load_fixture("zap.json")


def test_zap_run_raises_tool_missing_when_report_file_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(zap, "find_tool", lambda name: "/usr/bin/docker")

    def fake_run(cmd, capture_output=True, text=True, check=False, timeout=None):
        # docker ran but never produced /zap/wrk/zap.json (permissions,
        # crash, or a mount outside the host's shared prefix).
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(zap.subprocess, "run", fake_run)

    with pytest.raises(ToolMissing, match="zap produced no report"):
        zap.run(_ctx(tmp_path))


def test_zap_run_raises_tool_missing_when_out_not_set(monkeypatch):
    monkeypatch.setattr(zap, "find_tool", lambda name: "/usr/bin/docker")

    with pytest.raises(ToolMissing, match="--out"):
        zap.run(Context(repo=Path("/repo"), url="http://127.0.0.1:8000", out=None))


def test_zap_run_parses_report_identically_to_before_the_mount_fix(monkeypatch, tmp_path):
    monkeypatch.setattr(zap, "find_tool", lambda name: "/usr/bin/docker")

    def fake_run(cmd, capture_output=True, text=True, check=False, timeout=None):
        host_dir, _, _ = _mount_target(cmd).partition(":")
        (Path(host_dir) / "zap.json").write_text(json.dumps(load_fixture("zap.json")))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(zap.subprocess, "run", fake_run)

    raw = zap.run(_ctx(tmp_path))
    findings = zap.parse(raw, _ctx(tmp_path))

    assert len(findings) >= 1
    for f in findings:
        assert f.source == "zap"
