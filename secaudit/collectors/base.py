"""Shared collector contract: the run context and the "tool not installed"
signal every collector's `run` raises instead of crashing the scan.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Context:
    repo: Path | None
    url: str | None = None
    only: set[str] | None = None
    skip: set[str] | None = None


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
