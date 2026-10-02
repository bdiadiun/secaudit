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
