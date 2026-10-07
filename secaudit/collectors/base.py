"""Shared collector contract: the run context and the "tool not installed"
signal every collector's `run` raises instead of crashing the scan.
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


def find_tool(name: str) -> str | None:
    """Look up a collector's binary on `PATH`, falling back to the
    directory `sys.executable` lives in: `pip install secaudit bandit`
    into one venv must work without activating that venv first, so the
    binary can sit next to secaudit's own interpreter without being on
    `PATH`.
    """
    exe = shutil.which(name)
    if exe is not None:
        return exe
    candidate = Path(sys.executable).parent / name
    if candidate.is_file():
        return str(candidate)
    return None


@dataclass
class Context:
    repo: Path | None
    url: str | None = None
    # Where `scan --out` writes findings.json. zap's run() also stages its
    # bind-mounted report dir under here: on colima/Docker Desktop only
    # paths under the host's shared prefix (repo tree, not system /tmp or
    # /var/folders) are visible inside the container, so a tempfile.mkdtemp
    # outside this tree mounts empty and zap can never write its report.
    out: Path | None = None
    only: set[str] | None = None
    skip: set[str] | None = None
    # lang -> frameworks, from `scan --stack`; semgrep builds its --config
    # packs from this instead of the network-dependent `--config auto`.
    stack: dict[str, list[str]] = field(default_factory=dict)


class ToolMissing(Exception):
    """Raised by a collector's run() when its underlying tool (binary,
    reachable URL, ...) is not available. The CLI records it in
    run.skipped and moves on to the next collector.
    """


class ToolCrashed(ToolMissing):
    """The tool ran but died or printed nothing parseable. Subclasses
    ToolMissing so the CLI files it under run.skipped instead of treating
    an empty result as "0 findings" (osv-scanner SIGSEGV, 08.10).
    """


def load_json(result, tool: str, ok_codes: tuple[int, ...] = (0, 1), empty=None):
    """Parse a finished subprocess's stdout, or raise ToolCrashed.

    `ok_codes` is the tool's normal exit set (e.g. 1 = "findings present").
    Anything else -- including negative signal codes -- is a crash, and an
    empty/garbled stdout under a normal code is `invalid output`: neither may
    degrade to an empty "clean" result.
    """
    import json

    if result.returncode not in ok_codes:
        raise ToolCrashed(f"crashed: exit {result.returncode}")
    text = (result.stdout or "").strip()
    if not text:
        raise ToolCrashed("invalid output")
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ToolCrashed("invalid output") from exc


def relpath(path_str: str, repo: Path | None) -> str:
    """Best-effort repo-relative, posix path: scanners run with `-r <repo>`
    sometimes echo back an absolute path. Fixtures already use repo-relative
    paths, so this is a no-op on them (relative_to raises -> fall through).
    """
    path = Path(path_str)
    if repo is not None:
        try:
            path = path.relative_to(repo)
        except ValueError:
            pass
    return path.as_posix()
