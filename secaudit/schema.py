"""Pydantic v2 models for the findings/report contract — the JSON shapes in
docs/spec.md, verbatim. Consumers (the report renderer, the CLI, an agent
reading findings.json) depend on this module only, never on collector
internals.
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
Status = Literal["new", "known", "resolved", "accepted"]


class Accepted(BaseModel):
    """An entry from accepted.yml, copied onto a matched finding."""

    model_config = ConfigDict(extra="forbid")

    reason: str
    by: str
    date: date
    expires: date | None = None


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    commit: str | None = None
    url: str | None = None
    # As passed to `scan --stack` (lang -> frameworks) — the report must show
    # which stack the semgrep config pack selection was derived from.
    stack: dict[str, list[str]] = Field(default_factory=dict)


class SkippedTool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    reason: str


class RunInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    started_at: str
    finished_at: str
    tools: dict[str, str | None] = {}
    skipped: list[SkippedTool] = []


class BaselineInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str | None = None
    commit: str | None = None


class Summary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    new: int = 0
    known: int = 0
    resolved: int = 0
    accepted: int = 0


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    rule: str
    severity: Severity
    confidence: Confidence
    cwe: str | None = None
    title: str
    # One of {file, line} / {url, method} / {package, version, ecosystem} —
    # no discriminated submodel per tests/README.md, callers know the shape
    # from `source`.
    location: dict[str, object]
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = []
    status: Status
    accepted: Accepted | None = None


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    target: Target
    run: RunInfo
    findings: list[Finding] = []
    summary: Summary
    baseline: BaselineInfo
