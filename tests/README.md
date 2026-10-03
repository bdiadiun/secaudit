# Interfaces assumed by the tests

`docs/spec.md` fixes the JSON schema and the collector contract
(`SOURCE`, `tool_version()`, `run(ctx)`, `parse(raw, ctx)`) but leaves a few
Python-level signatures open. The tests were written against the following
choices; implement exactly these so the suite goes green without renegotiating
the contract:

- `secaudit.normalize.fingerprint(source: str, rule: str, location: dict, evidence: str | None) -> str`
  — pure function, returns `"fp-" + sha256(...)[:16]` per the spec's
  fingerprint recipe. `location` is a plain dict with one of the three
  shapes (`file`/`line`, `url`/`method`, `package`/`version`/`ecosystem`).
- `secaudit.normalize.severity(source: str, raw: dict) -> str` — dispatches
  on `source`. Expected `raw` keys per source (see `tests/test_severity.py`
  for the exact parametrization):
  - `bandit`: `{"issue_severity": "HIGH"|"MEDIUM"|"LOW"}`
  - `semgrep`: `{"severity": "ERROR"|"WARNING"|"INFO", "metadata_severity": str|None}`
    (`metadata_severity == "CRITICAL"` overrides to `critical`)
  - `pip-audit` / `osv`: `{"cvss": float|None}`
  - `gitleaks`: `{"in_tree": bool}`
  - `zap`: `{"riskcode": int}`
  - `ratelimit`: `{}` (always `medium`)
- `secaudit.schema.Finding` / `secaudit.schema.Report` — pydantic v2 models
  matching the JSON shapes in `docs/spec.md` verbatim; `location` is typed as
  `dict[str, object]` (no discriminated submodel required);
  `schema_version` is the literal `"1.0"`. `Finding.accepted` is a nested
  pydantic model (`reason: str`, `by: str`, `date: date`,
  `expires: date | None`), not a plain dict, so callers use attribute access
  (`finding.accepted.reason`).
- `secaudit.collectors.base.Context(repo: Path, url: str | None = None, out: Path | None = None, only: set[str] | None = None, skip: set[str] | None = None, stack: dict[str, list[str]] = {})`
  — `stack` is `scan --stack`'s parsed `{lang: [framework, ...]}`; only
  `semgrep.run()` reads it (building `--config` packs instead of `auto`).
  `out` is `scan --out`; zap.run() stages its bind-mounted report dir under
  it (colima/Docker Desktop only share paths under the host's own tree).
- `secaudit.collectors.base.ToolMissing(Exception)`
- One module per source: `secaudit.collectors.bandit`, `.semgrep`,
  `.pip_audit` (source string is still `"pip-audit"`), `.osv`, `.gitleaks`,
  `.zap`, `.ratelimit`. Each exposes module-level `SOURCE`, `tool_version()`,
  `run(ctx) -> raw`, `parse(raw, ctx) -> list[Finding]`. `zap` and
  `ratelimit`'s `run` must raise `ToolMissing` themselves when `ctx.url` is
  `None` (the CLI always calls every collector; per-collector `run` decides
  whether it is applicable).
- `secaudit.collectors.ratelimit.run` is synchronous and uses `httpx` (a
  plain `httpx.Client`, not `AsyncClient`) so it can be intercepted with
  `pytest-httpx`'s `httpx_mock`. Any pacing between requests must go through
  `time.sleep` (module-level `import time`) so tests can monkeypatch
  `time.sleep` to keep the burst instantaneous.
- `secaudit.collectors.ratelimit.run(ctx)` fetches `GET {ctx.url}/openapi.json`,
  selects `POST` paths whose path matches `login|token|auth|session|password`,
  and for each sends up to 30 `POST` requests with an invalid JSON body,
  stopping as soon as one answers `429`. It returns a raw structure that
  `parse(raw, ctx)` turns into zero-or-one `Finding` per selected path: no
  finding when a `429` was seen, one `medium`-severity finding
  (`location={"url": ctx.url + path, "method": "POST"}`) when it never was.
- The CLI (`secaudit.cli.app`, typer) must look up `run`/`parse` as
  attributes on the imported collector submodules at call time (e.g.
  `from secaudit.collectors import bandit; bandit.run(ctx)`), not bind local
  references at import time — tests monkeypatch
  `secaudit.collectors.<name>.run` / `.parse` directly and expect the CLI to
  see the replacement.
- Skip-reason strings: a `ToolMissing` skip records `reason=str(exc)`; any
  other exception from `run` records `reason=f"error: {exc}"`.
- `secaudit.baseline.load_accepted(raw: list[dict]) -> tuple[list[dict], list[str]]`
  — validates each entry has `id`, `reason`, `by`, `date`; raises
  `secaudit.baseline.InvalidAccepted` (a `ValueError` subclass whose message
  names the offending entry's `id` and the missing field) when one is
  absent. Filters out entries whose `expires` is in the past, returning them
  as human-readable warning strings in the second tuple element instead.
- `secaudit.baseline.apply(findings: list[Finding], baseline: list[Finding] | None, accepted: list[dict] | None) -> list[Finding]`
  — sets `status` to `new`/`known` by matching `id` against `baseline`,
  appends `resolved` findings copied from `baseline`, then applies `accepted`
  entries (already validated by `load_accepted`) by `id` regardless of
  new/known, setting `status="accepted"` and populating `finding.accepted`.
- `secaudit.baseline.summarize(findings: list[Finding]) -> dict` — returns
  `{"critical": int, "high": int, "medium": int, "low": int, "info": int,
  "new": int, "known": int, "resolved": int, "accepted": int}`; severity
  counts only include findings whose `status in {"new", "known"}`.
- `secaudit.report.render(report: secaudit.schema.Report) -> str` — renders
  the markdown described in `docs/spec.md`.
- `secaudit.cli.app` exposes `scan`, `report`, `baseline` typer commands.
  `scan --url <host-not-loopback>` exits `2` before any collector's `run` is
  called. `--fail-on` accepts `critical|high|medium|low|info` (default
  `high`). `scan` without `--stack` (or an empty one) exits `2` the same way,
  message `stack unknown: pass --stack <lang[:fw,...];...>`.
